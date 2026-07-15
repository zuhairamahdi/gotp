// Package webhook implements otp.Notifier by POSTing signed delivery
// requests to external webhook endpoints — e.g. a Twilio-backed SMS
// relay, a SendGrid-backed email relay, or a Zapier/n8n/internal service
// for any other channel. This keeps the OTP service decoupled from any
// specific delivery provider: you point it at a URL, and whatever's on
// the other end is responsible for actually sending the message.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	otp "github.com/zuhairamahdi/gotp"
)

// Endpoint is a single webhook target for one delivery channel.
type Endpoint struct {
	URL    string // e.g. "https://relay.example.com/hooks/sms-otp"
	Secret []byte // per-endpoint HMAC signing key, at least 16 bytes
}

// Notifier implements otp.Notifier by dispatching to Endpoints keyed by
// channel (e.g. "sms", "email"). If a message's channel has no matching
// entry, the "default" entry (if configured) is used instead — this is
// what covers "or anything else": point "default" at a generic relay
// (Zapier, n8n, your own fan-out service) and any channel name works.
type Notifier struct {
	endpoints   map[string]Endpoint
	client      *http.Client
	maxRetries  int
	baseBackoff time.Duration
}

// Opt configures a Notifier.
type Opt func(*Notifier)

// WithHTTPClient overrides the default HTTP client (default: 10s timeout).
func WithHTTPClient(c *http.Client) Opt {
	return func(n *Notifier) { n.client = c }
}

// WithMaxRetries overrides the default retry count (default: 3).
func WithMaxRetries(max int) Opt {
	return func(n *Notifier) { n.maxRetries = max }
}

// New creates a webhook Notifier. endpoints maps channel name -> Endpoint;
// include a "default" key to catch channels without a specific entry.
func New(endpoints map[string]Endpoint, opts ...Opt) *Notifier {
	n := &Notifier{
		endpoints:   endpoints,
		client:      &http.Client{Timeout: 10 * time.Second},
		maxRetries:  3,
		baseBackoff: 200 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// payload is the JSON body sent to the webhook endpoint.
type payload struct {
	Identifier string `json:"identifier"`
	Purpose    string `json:"purpose"`
	Channel    string `json:"channel"`
	Code       string `json:"code"`
	Timestamp  string `json:"timestamp"`
}

// Send implements otp.Notifier. It resolves an endpoint for msg.Channel
// (falling back to "default"), signs the payload, and POSTs it with
// exponential-backoff retries.
func (n *Notifier) Send(ctx context.Context, msg otp.Message) error {
	ep, ok := n.endpoints[msg.Channel]
	if !ok {
		ep, ok = n.endpoints["default"]
		if !ok {
			return fmt.Errorf("webhook: no endpoint configured for channel %q and no default set", msg.Channel)
		}
	}
	if len(ep.Secret) < 16 {
		return fmt.Errorf("webhook: endpoint secret for channel %q must be at least 16 bytes", msg.Channel)
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	body, err := json.Marshal(payload{
		Identifier: msg.Identifier,
		Purpose:    msg.Purpose,
		Channel:    msg.Channel,
		Code:       msg.Code,
		Timestamp:  ts,
	})
	if err != nil {
		return fmt.Errorf("webhook: encoding payload: %w", err)
	}

	sig := Sign(ep.Secret, ts, body)

	var lastErr error
	backoff := n.baseBackoff
	for attempt := 1; attempt <= n.maxRetries; attempt++ {
		err := n.deliver(ctx, ep.URL, body, ts, sig)
		if err == nil {
			return nil
		}
		lastErr = err

		if attempt == n.maxRetries {
			break
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff *= 2
	}

	return fmt.Errorf("webhook: delivery failed after %d attempts: %w", n.maxRetries, lastErr)
}

func (n *Notifier) deliver(ctx context.Context, url string, body []byte, ts, sig string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Stripe-style signature header: timestamp + signature, so a receiver
	// can also enforce a max age to reject stale/replayed requests.
	req.Header.Set("X-Otp-Signature", fmt.Sprintf("t=%s,v1=%s", ts, sig))

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// Sign computes the hex-encoded HMAC-SHA256 signature over
// "<timestamp>.<body>", the same scheme used in the X-Otp-Signature
// header. Exposed so a receiving webhook can independently recompute it.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks an incoming X-Otp-Signature header (format
// "t=<timestamp>,v1=<hex signature>") against the request body, using a
// constant-time comparison. maxAge rejects requests whose timestamp is
// older than that duration, mitigating replay of a captured request.
// Use this in whatever service receives the webhook calls.
func VerifySignature(secret []byte, header string, body []byte, maxAge time.Duration) error {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			sig = kv[1]
		}
	}
	if ts == "" || sig == "" {
		return fmt.Errorf("webhook: malformed signature header")
	}

	parsedTs, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return fmt.Errorf("webhook: invalid timestamp: %w", err)
	}
	if maxAge > 0 && time.Since(parsedTs) > maxAge {
		return fmt.Errorf("webhook: signature timestamp too old")
	}

	expected := Sign(secret, ts, body)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
		return fmt.Errorf("webhook: signature mismatch")
	}
	return nil
}
