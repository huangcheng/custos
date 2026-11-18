"""Opaque pagination cursors (design §6): HMAC(pepper)-tagged, principal- and
endpoint-bound, 15-minute TTL. Stateless — re-fetching the same page with an
unexpired cursor is legal; foreign/expired/tampered → 422 invalid.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from custos.errors import AppError

_TTL_SECONDS = 900


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


def _tag(pepper: bytes, payload: bytes) -> bytes:
    return hmac.new(pepper, payload, hashlib.sha256).digest()


def _enc_key(pepper: bytes) -> bytes:
    # domain-separated from credential digests: cursors are opaque to clients
    # (scan edges may reference out-of-scope names — never client-readable)
    return hmac.new(pepper, b"custos-cursor-enc|v1", hashlib.sha256).digest()


def mint_cursor(payload: dict[str, Any], pepper: bytes, endpoint: str, principal_id: str) -> str:
    body = {
        "p": payload,
        "endpoint": endpoint,
        "principal": principal_id,
        "exp": int(time.time()) + _TTL_SECONDS,
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    nonce = os.urandom(12)
    sealed = nonce + AESGCM(_enc_key(pepper)).encrypt(nonce, raw, b"cursor")
    return _b64url(sealed) + "." + _b64url(_tag(pepper, sealed))


_MAX_CURSOR_LEN = 1024


def read_cursor(token: str, pepper: bytes, endpoint: str, principal_id: str) -> dict[str, Any]:
    if len(token) > _MAX_CURSOR_LEN:
        raise AppError("invalid", "malformed cursor")
    try:
        sealed_b64, tag_b64 = token.split(".", 1)
        sealed = _b64url_decode(sealed_b64)
        tag = _b64url_decode(tag_b64)
    except (AttributeError, TypeError, ValueError):
        raise AppError("invalid", "malformed cursor") from None
    if not hmac.compare_digest(tag, _tag(pepper, sealed)):
        raise AppError("invalid", "invalid cursor")
    try:
        if len(sealed) < 28:
            raise ValueError
        raw = AESGCM(_enc_key(pepper)).decrypt(sealed[:12], sealed[12:], b"cursor")
        body = json.loads(raw)
        exp = int(body["exp"])
        payload = body["p"]
        if not isinstance(payload, dict):
            raise ValueError
    except (ValueError, KeyError, TypeError, InvalidTag):
        raise AppError("invalid", "malformed cursor") from None
    if body.get("endpoint") != endpoint or body.get("principal") != principal_id:
        raise AppError("invalid", "invalid cursor")
    if exp < time.time():
        raise AppError("invalid", "expired cursor")
    return payload
