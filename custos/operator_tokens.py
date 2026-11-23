"""Operator tokens (design §5): ``co-<12 hex key_id>.<43 base64url secret>``.

Same HMAC/constant-time mechanics as agent keys but a SEPARATE table — an
agent key can never authenticate on the admin plane and vice versa
(prefix + table lookup). Expiry is mandatory: max 90 days, allow_sensitive
tokens max 30 days (§5); mint rejects absent/past/over-cap expiry. Mint ALSO
seals the full token under the keyring (AAD ``token:<key_id>|<version>``)
for session+step-up-only re-reveal; the draft never carries the secret.
"""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from custos.crypto import credential_digest, digests_equal
from custos.db.models import OperatorToken
from custos.errors import AppError

_TOKEN_RE = re.compile(r"^co-([0-9a-f]{12})\.([A-Za-z0-9_-]{43})\Z")
_DUMMY_DIGEST = bytes(32)
_FAILURE_MESSAGE = "authentication failed"

_MAX_LIFETIME = timedelta(days=90)
_MAX_SENSITIVE_LIFETIME = timedelta(days=30)


class OperatorAuthError(Exception):
    """Uniform operator-token authentication failure — one identical 401."""

    def __init__(self) -> None:
        super().__init__(_FAILURE_MESSAGE)


@dataclass(frozen=True)
class OperatorTokenDraft:
    """Persist-ready draft: the expiry cap is validated HERE, so no caller
    can store an over-cap or absent expiry by forgetting a check."""

    key_id: str
    digest: bytes
    expires_at: datetime
    allow_sensitive: bool


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint_operator_token(
    pepper: bytes,
    *,
    expires_at: datetime | None,
    allow_sensitive: bool = False,
    now: datetime | None = None,
) -> tuple[str, OperatorTokenDraft]:
    """Returns the full token exactly once; the draft never carries the secret.
    Expiry is mandatory and cap-validated before any row can be persisted."""
    moment = now if now is not None else datetime.now(UTC)
    validate_expiry(expires_at, allow_sensitive, moment)
    key_id = secrets.token_hex(6)  # 12 hex chars
    secret_text = _b64url(secrets.token_bytes(32))  # 43 base64url chars
    token = f"co-{key_id}.{secret_text}"
    return token, OperatorTokenDraft(
        key_id=key_id,
        digest=credential_digest(pepper, secret_text),
        expires_at=cast(datetime, expires_at),  # validate_expiry rejects None
        allow_sensitive=allow_sensitive,
    )


def validate_expiry(
    expires_at: datetime | None, allow_sensitive: bool, now: datetime
) -> None:
    """§5: expiry mandatory, in the future, within the lifetime cap."""
    if now.tzinfo is None:
        raise AppError("invalid", "now must carry a timezone")
    if expires_at is None:
        raise AppError("invalid", "expires_at is required")
    if expires_at.tzinfo is None:
        raise AppError("invalid", "expires_at must carry a timezone")
    if expires_at <= now:
        raise AppError("invalid", "expires_at must be in the future")
    cap = _MAX_SENSITIVE_LIFETIME if allow_sensitive else _MAX_LIFETIME
    if expires_at - now > cap:
        raise AppError("invalid", f"expires_at exceeds the {cap.days}-day cap")


async def verify_operator_token(
    session: AsyncSession, pepper: bytes, presented: str
) -> OperatorToken:
    match = _TOKEN_RE.match(presented)
    row: OperatorToken | None = None
    presented_digest = _DUMMY_DIGEST
    if match is not None:
        key_id, secret_text = match.group(1), match.group(2)
        presented_digest = credential_digest(pepper, secret_text)
        row = (
            await session.execute(
                select(OperatorToken).where(OperatorToken.key_id == key_id)
            )
        ).scalar_one_or_none()
    now = datetime.now(UTC)
    stored = row.digest if row is not None else _DUMMY_DIGEST
    ok = digests_equal(presented_digest, stored)
    if row is None or not ok or row.revoked_at is not None or row.expires_at <= now:
        raise OperatorAuthError()
    return row
