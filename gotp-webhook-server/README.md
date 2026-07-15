# gotp-webhook-server (Flask)

A small stand-in for "the other end" of the OTP webhooks. It receives the
signed POST from the Go `gotp`/`webhook` package, verifies the HMAC
signature (rejecting anything missing, tampered, or stale), and logs the
delivery — in place of actually calling Twilio, SendGrid, etc.

## Endpoints

- `POST /hooks/sms-otp` — verifies against `OTP_WEBHOOK_SMS_SECRET`
- `POST /hooks/email-otp` — verifies against `OTP_WEBHOOK_EMAIL_SECRET`
- `GET /healthz`

## Running

```bash
pip install -r requirements.txt
cp .env.example .env   # then edit if needed
export $(grep -v '^#' .env | xargs)
python app.py
```

Server listens on `PORT` (default `5001`).

## Signature verification

The Go side sends:

```
X-Otp-Signature: t=<RFC3339 timestamp>,v1=<hex hmac-sha256>
```

where `v1 = HMAC-SHA256(secret, "<timestamp>." + raw_body)`. This server
recomputes the same HMAC over the exact raw request bytes and does a
constant-time comparison (`hmac.compare_digest`). It also rejects
timestamps more than 5 minutes old, to limit replay of a captured request.

If verification fails, the endpoint returns `401` with a JSON `error`
field explaining why (missing header, malformed header, stale timestamp,
or mismatch) — useful for debugging a misconfigured secret.

## Wiring it to the Go service

Point the Go service's webhook endpoints at this server (see the `gotp`
project's `.env.example`):

```
OTP_WEBHOOK_SMS_URL=http://localhost:5001/hooks/sms-otp
OTP_WEBHOOK_SMS_SECRET=dev-only-sms-secret-32-bytes!!!
OTP_WEBHOOK_EMAIL_URL=http://localhost:5001/hooks/email-otp
OTP_WEBHOOK_EMAIL_SECRET=dev-only-email-secret-32-bytes!!
```

The `*_SECRET` values must be identical on both sides — they're the shared
key used to sign and verify.

## Note

This is a development/demo server (Flask's built-in dev server, logs the
code to stdout for visibility). For production, run it behind a real WSGI
server (gunicorn/uwsgi), replace the `logger.info(...)` call with an
actual Twilio/SendGrid/etc. call, and stop logging the code.
