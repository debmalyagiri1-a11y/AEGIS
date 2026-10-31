"""Minimal signed AEGIS session tokens and SMTP MFA delivery.
AEGIS_AUTH_SECRET must be a unique 32+ byte random secret on Render.
"""
import base64
import hashlib
import hmac
import json
import os
import smtplib
import ssl
import time
from collections import defaultdict, deque
from email.message import EmailMessage
from fastapi import HTTPException

_ATTEMPTS = defaultdict(deque)

def _secret():
    secret = os.environ.get("AEGIS_AUTH_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("Set AEGIS_AUTH_SECRET to a random secret of at least 32 characters")
    return secret.encode()

def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def create_token(uid, purpose, seconds):
    payload = {"sub": int(uid), "purpose": purpose, "exp": int(time.time()) + seconds}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    return body + "." + signature

def read_token(token, purpose):
    try:
        body, signature = token.split(".")
        expected = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if payload["purpose"] != purpose or payload["exp"] <= time.time():
            raise ValueError()
        return int(payload["sub"])
    except (ValueError, TypeError, KeyError, UnicodeError) as e:
        raise ValueError("Invalid token") from e

def rate_limit(key, limit, window):
    now = time.monotonic()
    attempts = _ATTEMPTS[key]
    while attempts and attempts[0] < now - window:
        attempts.popleft()
    if len(attempts) >= limit:
        raise HTTPException(429, "Too many attempts. Try again later.")
    attempts.append(now)

def is_local_demo():
    return os.environ.get("AEGIS_DEV_MFA") == "1" and not os.environ.get("RENDER")

def deliver_mfa(address, code):
    if is_local_demo():
        print("LOCAL DEVELOPMENT MFA CODE:", code)
        return
    host = os.environ.get("AEGIS_SMTP_HOST")
    username = os.environ.get("AEGIS_SMTP_USER")
    password = os.environ.get("AEGIS_SMTP_PASSWORD")
    sender = os.environ.get("AEGIS_SMTP_FROM")
    if not all((host, username, password, sender)):
        raise HTTPException(503, "MFA email delivery is not configured")
    message = EmailMessage()
    message["Subject"] = "AEGIS verification code"
    message["From"] = sender
    message["To"] = address
    message.set_content(f"Your AEGIS verification code is {code}. It expires in 5 minutes. Do not share it.")
    try:
        with smtplib.SMTP(host, int(os.environ.get("AEGIS_SMTP_PORT", "587")), timeout=12) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(username, password)
            server.send_message(message)
    except Exception as e:
        raise HTTPException(503, "Unable to send MFA email. Try again later.") from e
