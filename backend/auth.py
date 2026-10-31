
"""AEGIS signed session tokens and Brevo HTTPS MFA delivery.

Required Render environment variables:
    AEGIS_AUTH_SECRET
    BREVO_API_KEY
    AEGIS_SMTP_FROM
"""

import base64
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict, deque

import requests
from fastapi import HTTPException


_ATTEMPTS = defaultdict(deque)


def _secret():
    secret = os.environ.get("AEGIS_AUTH_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError(
            "Set AEGIS_AUTH_SECRET to a random secret "
            "of at least 32 characters"
        )
    return secret.encode()


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def create_token(uid, purpose, seconds):
    payload = {
        "sub": int(uid),
        "purpose": purpose,
        "exp": int(time.time()) + seconds
    }

    body = _b64(
        json.dumps(payload, separators=(",", ":")).encode()
    )

    signature = _b64(
        hmac.new(
            _secret(),
            body.encode(),
            hashlib.sha256
        ).digest()
    )

    return body + "." + signature


def read_token(token, purpose):
    try:
        body, signature = token.split(".")

        expected = _b64(
            hmac.new(
                _secret(),
                body.encode(),
                hashlib.sha256
            ).digest()
        )

        if not hmac.compare_digest(signature, expected):
            raise ValueError()

        payload = json.loads(
            base64.urlsafe_b64decode(
                body + "=" * (-len(body) % 4)
            )
        )

        if (
            payload["purpose"] != purpose
            or payload["exp"] <= time.time()
        ):
            raise ValueError()

        return int(payload["sub"])

    except (
        ValueError,
        TypeError,
        KeyError,
        UnicodeError
    ) as e:
        raise ValueError("Invalid token") from e


def rate_limit(key, limit, window):
    now = time.monotonic()
    attempts = _ATTEMPTS[key]

    while attempts and attempts[0] < now - window:
        attempts.popleft()

    if len(attempts) >= limit:
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Try again later."
        )

    attempts.append(now)


def is_local_demo():
    return (
        os.environ.get("AEGIS_DEV_MFA") == "1"
        and not os.environ.get("RENDER")
    )


def deliver_mfa(address, code):
    if is_local_demo():
        print("LOCAL DEVELOPMENT MFA CODE:", code)
        return

    api_key = os.environ.get("BREVO_API_KEY", "").strip()
    sender = os.environ.get(
        "AEGIS_SMTP_FROM", ""
    ).strip()

    if not api_key or not sender:
        raise HTTPException(
            status_code=503,
            detail="MFA email delivery is not configured"
        )

    payload = {
        "sender": {
            "name": "AEGIS Security",
            "email": sender
        },
        "to": [
            {
                "email": address
            }
        ],
        "subject": "Your AEGIS verification code",
        "textContent": (
            f"Your AEGIS verification code is {code}. "
            "It expires in 5 minutes. "
            "Do not share this code with anyone."
        )
    }

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
                "accept": "application/json"
            },
            json=payload,
            timeout=12
        )

        response.raise_for_status()

    except requests.RequestException as error:
        # Avoid logging MFA codes or API credentials.
        status = None

        if (
            isinstance(error, requests.HTTPError)
            and error.response is not None
        ):
            status = error.response.status_code

        print(
            "AEGIS MFA email delivery failed. "
            f"Brevo HTTP status: {status or 'network error'}"
        )

        raise HTTPException(
            status_code=503,
            detail="Unable to send MFA email. Try again later."
        ) from error
