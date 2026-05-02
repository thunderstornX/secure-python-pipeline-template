"""
Minimal but real auth: HMAC-signed bearer tokens.

Why HMAC and not JWT?  The demo intentionally avoids the python-jose CVE
chain (CVE-2024-33663 algorithm-confusion, CVE-2024-33664 DoS).  An HMAC
token over a JSON body achieves the same demo goal -- prove a request came
from a logged-in user -- without the JOSE attack surface.

Token format::

    <base64url-payload>.<hex-hmac-sha256>

The payload is a JSON dict ``{"sub": <user_id>, "iat": <unix>}``.
Tokens are stateless; revocation requires rotating ``settings.secret_key``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings


_TOKEN_TTL_SECONDS = 60 * 60 * 24  # 24 hours


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_token(user_id: int) -> str:
    payload = {"sub": user_id, "iat": int(time.time())}
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(
        settings.secret_key.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str) -> int:
    try:
        body, sig = token.rsplit(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="malformed token") from exc

    expected = hmac.new(
        settings.secret_key.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="bad signature")

    try:
        payload = json.loads(_b64url_decode(body))
        user_id = int(payload["sub"])
        issued_at = int(payload["iat"])
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="malformed payload") from exc

    if time.time() - issued_at > _TOKEN_TTL_SECONDS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="token expired")

    return user_id


_bearer = HTTPBearer(auto_error=True, description="HMAC bearer token from /users/login")


def current_user_id(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
) -> int:
    """FastAPI dependency: returns authenticated user id, or 401."""
    return verify_token(creds.credentials)
