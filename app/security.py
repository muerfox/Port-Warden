from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.timeutil import utcnow

_HASHER = PasswordHasher()
_DUMMY_HASH = _HASHER.hash("port-warden-dummy-password")


def hash_password(password: str) -> str:
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def verify_dummy(password: str) -> None:
    verify_password(_DUMMY_HASH, password)


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_expiry(hours: int) -> datetime:
    return utcnow() + timedelta(hours=hours)


def issue_confirm_token(secret: str, payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    encoded = base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
    return f"{encoded}.{signature}"


def read_confirm_token(secret: str, token: str) -> dict:
    try:
        encoded, signature = token.split(".", 1)
        padded = encoded + "=" * (-len(encoded) % 4)
        body = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid confirm token") from exc
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid confirm token")
    payload = json.loads(body.decode("utf-8"))
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("confirm token expired; preview the ruleset again")
    return payload


class LoginLimiter:
    """In-memory failure window. One process only; document that for multi-worker deploys."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str) -> None:
        now = time.time()
        bucket = [stamp for stamp in self._hits.get(key, []) if now - stamp < self.window]
        self._hits[key] = bucket
        if len(bucket) >= self.limit:
            from fastapi import HTTPException

            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    def fail(self, key: str) -> None:
        now = time.time()
        bucket = [stamp for stamp in self._hits.get(key, []) if now - stamp < self.window]
        bucket.append(now)
        self._hits[key] = bucket

    def clear(self, key: str) -> None:
        self._hits.pop(key, None)
