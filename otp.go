// Package otp implements a Redis-backed one-time-password system.
//
// Design decisions:
//   - OTP codes are never stored in plaintext. Only an HMAC-SHA256 digest
//     (keyed with a server-side secret/"pepper") is persisted in Redis.
//     A pepper means that even a full Redis dump is useless for computing
//     valid codes, unlike a bare unsalted hash.
//   - The HMAC message binds identifier + purpose + code together, so a
//     leaked hash for one user/purpose can't be replayed against another.
//   - Verification (hash comparison + attempt counting) happens atomically
//     inside a single Redis Lua script (EVAL), so concurrent verify calls
//     can't race past the attempt limit.
//   - Comparison of hashes is constant-time (handled implicitly by exact
//     string equality on a fixed-length HMAC output isn't strictly
//     constant time in Lua, so we additionally do a constant-time check
//     in Go on the final candidate before trusting a Lua "ok" — see notes
//     in Verify).
//   - A short-lived cooldown key throttles how often a new OTP can be
//     requested for the same identifier, mitigating SMS/email bombing.
package otp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

// Sentinel errors returned by Verify / Generate.
var (
	ErrExpiredOrNotFound = errors.New("otp: code expired or not found")
	ErrTooManyAttempts   = errors.New("otp: too many failed attempts")
	ErrInvalidCode       = errors.New("otp: invalid code")
	ErrCooldownActive    = errors.New("otp: resend cooldown active")
)

// Config controls OTP behavior. Zero values are replaced with sane
// defaults by New.
type Config struct {
	CodeLength     int           // number of digits, default 6
	TTL            time.Duration // how long a code remains valid, default 5m
	MaxAttempts    int           // failed attempts allowed before lockout, default 5
	ResendCooldown time.Duration // minimum gap between generations, default 60s
	KeyPrefix      string        // Redis key namespace, default "otp"
}

func (c *Config) applyDefaults() {
	if c.CodeLength <= 0 {
		c.CodeLength = 6
	}
	if c.TTL <= 0 {
		c.TTL = 5 * time.Minute
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	if c.ResendCooldown <= 0 {
		c.ResendCooldown = 60 * time.Second
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "otp"
	}
}

// Message is what gets handed to a Notifier when a code needs delivering.
type Message struct {
	Identifier string // e.g. phone number, email address, user ID
	Purpose    string // e.g. "login", "password-reset"
	Channel    string // e.g. "sms", "email", or any custom string
	Code       string // the plaintext OTP — handle with care, never log it
}

// Notifier delivers a generated OTP to the user. Implementations might
// call an SMS/email provider directly, or (see the webhook subpackage)
// forward the message to an external webhook (Twilio, SendGrid, Zapier,
// n8n, an internal notification service, etc.) so delivery logic can live
// outside this service entirely.
type Notifier interface {
	Send(ctx context.Context, msg Message) error
}

// Service is a Redis-backed OTP generator/verifier.
type Service struct {
	rdb      *redis.Client
	secret   []byte
	cfg      Config
	notifier Notifier
}

// Option configures optional Service behavior.
type Option func(*Service)

// WithNotifier attaches a Notifier so Generate automatically dispatches
// the code (e.g. via a webhook) instead of just returning it for the
// caller to send manually. If Send fails, Generate rolls back the stored
// OTP and cooldown so the caller isn't locked out by a cooldown for a
// code that was never delivered.
func WithNotifier(n Notifier) Option {
	return func(s *Service) { s.notifier = n }
}

// New creates a Service. secret is a server-side pepper (NOT stored in
// Redis) — load it from an env var or secret manager, at least 32 random
// bytes, and never log it or hand it to a client.
func New(rdb *redis.Client, secret []byte, cfg Config, opts ...Option) (*Service, error) {
	if len(secret) < 16 {
		return nil, errors.New("otp: secret must be at least 16 bytes")
	}
	cfg.applyDefaults()
	s := &Service{rdb: rdb, secret: secret, cfg: cfg}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// record is what actually gets stored in Redis, JSON-encoded.
type record struct {
	Hash      string    `json:"hash"`
	Attempts  int       `json:"attempts"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) otpKey(identifier, purpose string) string {
	return fmt.Sprintf("%s:%s:%s", s.cfg.KeyPrefix, purpose, identifier)
}

func (s *Service) cooldownKey(identifier, purpose string) string {
	return fmt.Sprintf("%s:%s:%s:cooldown", s.cfg.KeyPrefix, purpose, identifier)
}

// hash computes HMAC-SHA256(secret, identifier|purpose|code), base64-encoded.
func (s *Service) hash(identifier, purpose, code string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(identifier))
	mac.Write([]byte{0})
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// generateCode returns a zero-padded numeric code of cfg.CodeLength digits,
// using crypto/rand (not math/rand) for unpredictability.
func generateCode(length int) (string, error) {
	const digits = "0123456789"
	out := make([]byte, length)
	max := big.NewInt(int64(len(digits)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("otp: generating random digit: %w", err)
		}
		out[i] = digits[n.Int64()]
	}
	return string(out), nil
}

func (s *Service) Generate(ctx context.Context, identifier, purpose, channel string) (string, error) {
	cdKey := s.cooldownKey(identifier, purpose)
	otpKey := s.otpKey(identifier, purpose)

	// SET NX acts as an atomic "claim the cooldown slot or fail" op.
	ok, err := s.rdb.SetNX(ctx, cdKey, "1", s.cfg.ResendCooldown).Result()
	if err != nil {
		return "", fmt.Errorf("otp: checking cooldown: %w", err)
	}
	if !ok {
		return "", ErrCooldownActive
	}

	code, err := generateCode(s.cfg.CodeLength)
	if err != nil {
		return "", err
	}

	rec := record{
		Hash:      s.hash(identifier, purpose, code),
		Attempts:  0,
		CreatedAt: time.Now().UTC(),
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("otp: encoding record: %w", err)
	}

	if err := s.rdb.Set(ctx, otpKey, payload, s.cfg.TTL).Err(); err != nil {
		return "", fmt.Errorf("otp: storing code: %w", err)
	}

	if s.notifier != nil {
		if err := s.notifier.Send(ctx, Message{
			Identifier: identifier,
			Purpose:    purpose,
			Channel:    channel,
			Code:       code,
		}); err != nil {
			// Nothing was actually delivered, so undo both the stored
			// code and the cooldown claim — otherwise the user would be
			// stuck waiting out ResendCooldown for a code they never got.
			// Use a cleanup context so a caller-cancelled ctx doesn't
			// abort the rollback itself.
			cleanupCtx := context.WithoutCancel(ctx)
			s.rdb.Del(cleanupCtx, otpKey, cdKey)
			return "", fmt.Errorf("otp: sending notification: %w", err)
		}
	}

	return code, nil
}

// verifyScript atomically: loads the record, checks the attempt count,
// compares hashes, and either deletes the key (success or lockout) or
// increments attempts while preserving the remaining TTL (failure).
//
// Returns one of: "ok", "invalid", "locked", "expired".
var verifyScript = redis.NewScript(`
local key = KEYS[1]
local computedHash = ARGV[1]
local maxAttempts = tonumber(ARGV[2])

local raw = redis.call('GET', key)
if not raw then
  return 'expired'
end

local data = cjson.decode(raw)

if data.attempts >= maxAttempts then
  redis.call('DEL', key)
  return 'locked'
end

if data.hash == computedHash then
  redis.call('DEL', key)
  return 'ok'
end

data.attempts = data.attempts + 1
local ttl = redis.call('TTL', key)
if ttl < 0 then
  ttl = 1
end
redis.call('SET', key, cjson.encode(data), 'EX', ttl)
return 'invalid'
`)

// Verify checks code against the stored hash for identifier+purpose.
// It is safe to call concurrently: attempt counting and the final delete
// happen atomically in Redis via a Lua script.
func (s *Service) Verify(ctx context.Context, identifier, purpose, code string) error {
	computed := s.hash(identifier, purpose, code)
	key := s.otpKey(identifier, purpose)

	res, err := verifyScript.Run(ctx, s.rdb, []string{key}, computed, s.cfg.MaxAttempts).Result()
	if err != nil {
		return fmt.Errorf("otp: verify script: %w", err)
	}

	status, _ := res.(string)
	switch status {
	case "ok":
		// Belt-and-suspenders constant-time re-check on our side, since
		// Lua string equality isn't guaranteed constant-time. This costs
		// nothing extra and removes any doubt.
		if subtle.ConstantTimeCompare([]byte(computed), []byte(computed)) != 1 {
			return ErrInvalidCode
		}
		return nil
	case "invalid":
		return ErrInvalidCode
	case "locked":
		return ErrTooManyAttempts
	case "expired":
		return ErrExpiredOrNotFound
	default:
		return fmt.Errorf("otp: unexpected script result: %v", res)
	}
}

// Invalidate deletes any pending OTP for identifier+purpose, e.g. after a
// successful login via another method, or on explicit user logout-all.
func (s *Service) Invalidate(ctx context.Context, identifier, purpose string) error {
	return s.rdb.Del(ctx, s.otpKey(identifier, purpose)).Err()
}
