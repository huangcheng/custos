"""Crypto core (design §4): versioned keyring, AES-256-GCM domains, pepper digests.

Blob layout: nonce(12) || ciphertext+tag. Nonces are fresh CSPRNG per seal.
AAD strings are frozen; ``hmac.compare_digest`` is the sole presented-vs-stored
comparison primitive. Errors never contain key or plaintext material.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_LEN = 12
KEY_LEN = 32
TAG_LEN = 16
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ENTRY_RE = re.compile(r"^k([1-9][0-9]*):(.+)$")
_OPERATOR_INFO = b"custos-operator-seal|v1"


class CryptoError(Exception):
    """Keyring/pepper parsing failure. Messages never contain key material."""


class UnreadableError(Exception):
    """Blob cannot be opened: missing key version OR decryption/AAD/tag failure.

    Unified per design §4 — callers map both to 500 key_unavailable.
    """


def _b64url_decode(text: str) -> bytes:
    if not _B64URL_RE.match(text):
        raise CryptoError("value is not unpadded base64url (RFC 4648 §5)")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CryptoError("value is not valid base64url") from exc


def parse_keyring(raw: str) -> dict[int, bytes]:
    """Parse ``k<n>:<base64url-32-bytes>`` entries; comments/whitespace tolerated."""
    cleaned = "\n".join(line for line in raw.splitlines() if not line.lstrip().startswith("#"))
    keys: dict[int, bytes] = {}
    for part in cleaned.split(","):
        entry = part.strip()
        if not entry:
            continue
        match = _ENTRY_RE.match(entry)
        if not match:
            raise CryptoError("malformed keyring entry (expected k<n>:<base64url-32-bytes>)")
        version = int(match.group(1))
        if version in keys:
            raise CryptoError(f"duplicate key version k{version}")
        key = _b64url_decode(match.group(2))
        if len(key) != KEY_LEN:
            raise CryptoError(f"key k{version} must decode to exactly {KEY_LEN} bytes")
        keys[version] = key
    if not keys:
        raise CryptoError("keyring is empty")
    return keys


def parse_pepper(raw: str) -> bytes:
    pepper = _b64url_decode(raw.strip())
    if len(pepper) < KEY_LEN:
        raise CryptoError(f"pepper must decode to at least {KEY_LEN} bytes")
    if not any(pepper):
        raise CryptoError("pepper must not be all-zero (use a CSPRNG)")
    return pepper


def field_aad(field_id: str, version: int) -> bytes:
    return f"field:{field_id}|{version}".encode()


def history_aad(history_id: str, version: int) -> bytes:
    return f"fieldh:{history_id}|{version}".encode()


def operator_aad(version: int) -> bytes:
    return f"operator:totp|{version}".encode()


def key_aad(key_id: str, version: int) -> bytes:
    """Revealable agent-key secret (§5): bound to the key_id, never to a row uuid."""
    return f"key:{key_id}|{version}".encode()


def token_aad(key_id: str, version: int) -> bytes:
    """Revealable operator-token secret (§5): separate domain from agent keys."""
    return f"token:{key_id}|{version}".encode()


def operator_seal_key(key: bytes) -> bytes:
    """HKDF-SHA256(ikm=keyring key, salt=empty, info pinned) — operator domain."""
    return HKDF(algorithm=SHA256(), length=KEY_LEN, salt=None, info=_OPERATOR_INFO).derive(key)


def credential_digest(pepper: bytes, presented_secret: str) -> bytes:
    """HMAC-SHA256 over the UTF-8 of the presented text, byte-for-byte as received."""
    return hmac.new(pepper, presented_secret.encode(), hashlib.sha256).digest()


def digests_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


class Vault:
    def __init__(self, keys: dict[int, bytes]) -> None:
        if not keys:
            raise CryptoError("keyring is empty")
        self._aeads: dict[int, AESGCM] = {}
        self._operator_aeads: dict[int, AESGCM] = {}
        for version, key in keys.items():
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise CryptoError("invalid key version")
            if len(key) != KEY_LEN:
                raise CryptoError(f"key k{version} must be {KEY_LEN} bytes")
            self._aeads[version] = AESGCM(key)
            self._operator_aeads[version] = AESGCM(operator_seal_key(key))
        self.current_version = max(self._aeads)

    def _aead(self, domain: str, version: int) -> AESGCM:
        table = self._operator_aeads if domain == "operator:totp" else self._aeads
        aead = table.get(version)
        if aead is None:
            raise UnreadableError("key version unavailable")
        return aead

    def _aad(self, domain: str, row_id: str, version: int) -> bytes:
        if domain == "field":
            return field_aad(row_id, version)
        if domain == "fieldh":
            return history_aad(row_id, version)
        if domain == "operator:totp":
            return operator_aad(version)
        if domain == "key":
            return key_aad(row_id, version)
        if domain == "token":
            return token_aad(row_id, version)
        raise CryptoError(f"unknown AAD domain {domain!r}")

    def seal(self, domain: str, row_id: str, plaintext: bytes) -> tuple[bytes, int]:
        version = self.current_version
        aad = self._aad(domain, row_id, version)
        nonce = os.urandom(NONCE_LEN)
        blob = nonce + self._aead(domain, version).encrypt(nonce, plaintext, aad)
        return blob, version

    def open(self, domain: str, row_id: str, blob: bytes, version: int) -> bytes:
        aead = self._aead(domain, version)
        aad = self._aad(domain, row_id, version)
        if len(blob) < NONCE_LEN + TAG_LEN:
            raise UnreadableError("malformed blob")
        try:
            return aead.decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
        except InvalidTag as exc:
            raise UnreadableError("blob failed authentication") from exc
