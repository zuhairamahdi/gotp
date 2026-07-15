# gotp — hashed OTP system with Redis + Go

## How it works

1. **Generate**: creates a random numeric code with `crypto/rand`, computes
   `HMAC-SHA256(secret, identifier | purpose | code)`, and stores only that
   hash (plus an attempt counter) as JSON in Redis with a TTL. The plaintext
   code is returned to your caller to send via SMS/email — it is never
   written to Redis, logs, or disk.
2. **Verify**: recomputes the same HMAC from the submitted code and compares
   it to the stored hash **inside a single Redis Lua script**, so the
   read-check-increment-write cycle is atomic. This closes a race condition
   that a naive `GET` → compare in Go → `INCR` in Go would have under
   concurrent requests (e.g. two rapid submit attempts bypassing the
   attempt limit).
3. **Resend cooldown**: a separate `SETNX`-based key blocks issuing a new
   code for the same identifier+purpose faster than `ResendCooldown`,
   which limits SMS/email bombing and cost abuse.

## Why HMAC instead of bcrypt/argon2

OTP codes are short (typically 6 digits = 1,000,000 possibilities) and
short-lived. A slow password-hashing function like bcrypt is meant to make
offline brute-forcing of a *stolen hash* expensive — but a 6-digit space is
brute-forceable in seconds even against bcrypt. What actually protects a
numeric OTP is:

- a **server-side secret (pepper)** that never leaves your backend, so an
  attacker with only the Redis dump can't compute or verify guesses at all
  without also compromising your secret store, and
- a **short TTL** and **attempt limit**, enforced server-side and
  atomically.

HMAC-SHA256 is fast (as it should be — you want low-latency logins) and,
combined with the pepper + TTL + attempt-lockout, gives you the real
protection: the hash is useless without the secret, and the code is useless
after a few minutes or a few wrong guesses.

## Things to configure for your environment

- `OTP_HMAC_SECRET`: generate with e.g. `openssl rand -base64 32`, store in
  your secret manager, rotate periodically (rotating invalidates
  in-flight OTPs, which is fine given the short TTL).
- `Config.MaxAttempts` / `Config.TTL` / `Config.ResendCooldown`: tune to
  your risk tolerance. Defaults are 6 digits, 5 minute TTL, 5 attempts,
  60 second resend cooldown.
- Consider also rate-limiting `Generate` per IP (not just per identifier)
  at your API gateway/middleware layer, to prevent enumeration/cost abuse
  across many different identifiers.
- Never log the plaintext code. Never return it in an API response except
  in local/dev environments.

## Delivery via webhooks (`webhook` package)

`otp.Service` takes an optional `otp.Notifier` (via `otp.WithNotifier(...)`).
When set, `Generate` automatically dispatches the code instead of leaving
delivery to the caller. `webhook.Notifier` is the built-in implementation:
it POSTs a signed JSON payload to a URL you configure per channel, so the
actual sending (Twilio, SendGrid, Zapier, n8n, an internal service —
anything that can receive an HTTP POST) lives entirely outside this
codebase.

```go
endpoints := map[string]webhook.Endpoint{
    "sms":     {URL: "https://relay.example.com/hooks/sms-otp", Secret: smsSecret},
    "email":   {URL: "https://relay.example.com/hooks/email-otp", Secret: emailSecret},
    "default": {URL: "https://relay.example.com/hooks/generic-otp", Secret: genericSecret}, // catches any other channel
}
notifier := webhook.New(endpoints) // 3 retries w/ exponential backoff, 10s timeout, by default

svc, _ := otp.New(rdb, secret, otp.Config{}, otp.WithNotifier(notifier))
svc.Generate(ctx, "+97312345678", "login", "sms") // dispatches to the "sms" endpoint
```

**Payload sent to your endpoint:**

```json
{
  "identifier": "+97312345678",
  "purpose": "login",
  "channel": "sms",
  "code": "123456",
  "timestamp": "2026-07-15T12:34:56Z"
}
```

**Signature header** (Stripe-style, so receivers can enforce a max age):

```
X-Otp-Signature: t=2026-07-15T12:34:56Z,v1=<hex hmac-sha256>
```

The signature is `HMAC-SHA256(endpointSecret, "<timestamp>.<body>")`. On
the receiving side, verify it with the exported helper before trusting the
payload:

```go
err := webhook.VerifySignature(endpointSecret, r.Header.Get("X-Otp-Signature"), body, 5*time.Minute)
if err != nil {
    // reject: bad signature or replayed/stale request
}
```

**Failure handling:** if all retries to the webhook fail, `Generate`
rolls back the stored OTP hash *and* the resend-cooldown key before
returning an error — so a delivery failure doesn't leave the user stuck
waiting out the cooldown for a code that never arrived.

**"Anything else":** any string is a valid `channel` — it's just a map
key. Point `"push"`, `"whatsapp"`, `"slack"`, etc. at their own endpoint,
or configure a `"default"` endpoint as a catch-all.

If you'd rather call a provider's SDK directly instead of going through a
webhook, just implement `otp.Notifier` yourself (one method: `Send(ctx,
otp.Message) error`) and pass it to `otp.WithNotifier`.

## HTTP API (Echo)

`httpapi/handlers.go` wraps the service in two Echo routes:

- `POST /otp/generate` — body `{"identifier": "...", "purpose": "...", "channel": "sms"}`.
  Generates a code and — if a `Notifier` is configured on the service (see
  the webhook section below) — dispatches it automatically. `channel` is
  optional if you've configured a `"default"` webhook endpoint. The
  response is always just `{"message": "code sent"}`; the plaintext code
  is never returned to the client.
- `POST /otp/verify` — body `{"identifier": "...", "purpose": "...", "code": "..."}`.
  Responds `{"verified": true}` on success, or an appropriate error status:
  - `400` wrong code / bad request
  - `429` too many attempts, or cooldown active on generate
  - `410` code expired or never issued

`example/main.go` wires this into a small Echo server on `:8080`, with
`middleware.Logger`, `middleware.Recover`, and a basic per-IP rate limiter
(on top of the service's own per-identifier cooldown — the two guard
different attack surfaces: one identifier hammered vs. many identifiers
hammered from one IP).

## Running

```bash
cd gotp
cp .env.example .env   # then edit values, especially OTP_HMAC_SECRET
export $(grep -v '^#' .env | xargs)
go mod tidy
go run ./cmd
```

A sample config is in `.env.example` — it already points the webhook
endpoints at `http://localhost:5001/...`, which matches the companion
Flask reference server (see `otp-webhook-server/README.md`) if you want
something running end-to-end locally to test against.

Requires a Redis instance reachable at `REDIS_ADDR` (default
`localhost:6379`). Then:

```bash
curl -X POST localhost:8080/otp/generate \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"+97312345678","purpose":"login","channel":"sms"}'

curl -X POST localhost:8080/otp/verify \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"+97312345678","purpose":"login","code":"123456"}'
```
