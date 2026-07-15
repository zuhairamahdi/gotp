"""
Small Flask server that plays the role of the "other end" of the OTP
webhooks: it receives the signed POST from the Go service, verifies the
HMAC signature, and (as a stand-in for a real SMS/email provider) logs
the delivery.

Run:
    pip install -r requirements.txt
    export OTP_WEBHOOK_SMS_SECRET=dev-only-sms-secret-32-bytes!!!
    export OTP_WEBHOOK_EMAIL_SECRET=dev-only-email-secret-32-bytes!!
    python app.py

These secrets must exactly match the Secret configured for each channel
in the Go service's webhook.Endpoint map (see the gotp service's .env.example).
"""

import hashlib
import hmac
import logging
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("otp-webhook")

# Per-channel signing secrets — must match the Go side exactly.
CHANNEL_SECRETS = {
    "sms": os.environ.get("OTP_WEBHOOK_SMS_SECRET", "dev-only-sms-secret-32-bytes!!!"),
    "email": os.environ.get("OTP_WEBHOOK_EMAIL_SECRET", "dev-only-email-secret-32-bytes!!"),
}

MAX_AGE_SECONDS = 5 * 60  # reject signatures older than this (replay protection)
CLOCK_SKEW_SECONDS = 30   # small allowance for clocks not being perfectly in sync


class SignatureError(ValueError):
    pass


def verify_signature(secret: str, header: str, body: bytes) -> None:
    """Raises SignatureError if the header is missing/malformed/stale/invalid."""
    if not header:
        raise SignatureError("missing X-Otp-Signature header")

    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    ts = parts.get("t")
    sig = parts.get("v1")
    if not ts or not sig:
        raise SignatureError("malformed signature header")

    try:
        sent_at = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise SignatureError(f"invalid timestamp: {e}") from e

    age = (datetime.now(timezone.utc) - sent_at).total_seconds()
    if age > MAX_AGE_SECONDS or age < -CLOCK_SKEW_SECONDS:
        raise SignatureError("signature timestamp outside allowed window")

    # Must match the Go side exactly: HMAC-SHA256(secret, "<timestamp>.<body>")
    signed_payload = ts.encode() + b"." + body
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, sig):
        raise SignatureError("signature mismatch")


def handle_delivery(channel: str):
    secret = CHANNEL_SECRETS.get(channel)
    if not secret:
        logger.error("no secret configured for channel '%s'", channel)
        return jsonify(error=f"no secret configured for channel '{channel}'"), 500

    body = request.get_data()  # raw bytes — must verify against the exact bytes signed
    header = request.headers.get("X-Otp-Signature", "")

    try:
        verify_signature(secret, header, body)
    except SignatureError as e:
        logger.warning("rejected webhook for channel=%s: %s", channel, e)
        return jsonify(error=str(e)), 401

    data = request.get_json(silent=True) or {}
    identifier = data.get("identifier")
    code = data.get("code")
    purpose = data.get("purpose")

    # --- Stand-in for real delivery ---
    # A production version of this would call Twilio / SendGrid / whatever
    # here instead of logging. Never log the code in a real deployment;
    # this is only for local development/demo purposes.
    logger.info(
        "[%s] delivering OTP code=%s to identifier=%s (purpose=%s)",
        channel, code, identifier, purpose,
    )

    return jsonify(status="delivered"), 200


@app.route("/hooks/sms-otp", methods=["POST"])
def sms_otp():
    return handle_delivery("sms")


@app.route("/hooks/email-otp", methods=["POST"])
def email_otp():
    return handle_delivery("email")


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify(status="ok"), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)
