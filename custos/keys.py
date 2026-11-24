"""Agent keys (design §5, rev 38): ``cu-<12 hex key_id>.<43 base64url secret>``.

Every key carries full item-plane authority (Janus/Portunus parity): no mode,
no scopes. Authentication keeps only HMAC-SHA256(pepper, presented secret
text) as the stored digest. Verification runs exactly one constant-time
digest comparison on every path — unknown / expired compare against a fixed
dummy digest so all failures do equal digest work (DB-lookup timing residual
accepted, §5). Revocation hard-deletes the row, so a deleted key is simply
unknown. Mint ALSO seals the full token under the keyring (AAD domain
``key:<key_id>|<version>``) so the operator can re-reveal it through the
session+step-up-only admin reveal route; the draft itself never carries the secret.
"""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from custos.crypto import credential_digest, digests_equal
from custos.db.models import AgentKey

_TOKEN_RE = re.compile(r"^cu-([0-9a-f]{12})\.([A-Za-z0-9_-]{43})\Z")
_DUMMY_DIGEST = bytes(32)
_FAILURE_MESSAGE = "authentication failed"


@dataclass(frozen=True, eq=False)
class AgentPrincipal:
    """The authenticated agent principal (Principal protocol): identity only —
    never the digest or secret. Full item-plane authority by design."""

    actor_id: str
    actor_label: str
    actor_kind: str = "agent"

    @property
    def key_id(self) -> str:
        return self.actor_id


def as_principal(row: AgentKey) -> AgentPrincipal:
    return AgentPrincipal(actor_id=row.key_id, actor_label=row.label)


class AgentAuthError(Exception):
    """Uniform agent authentication failure — one identical 401 shape."""

    def __init__(self) -> None:
        super().__init__(_FAILURE_MESSAGE)


@dataclass(frozen=True)
class AgentKeyDraft:
    key_id: str
    digest: bytes


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint_agent_key(pepper: bytes) -> tuple[str, AgentKeyDraft]:
    """Returns the full token exactly once; the draft never carries the secret."""
    key_id = secrets.token_hex(6)  # 12 hex chars
    secret_text = _b64url(secrets.token_bytes(32))  # 43 base64url chars
    token = f"cu-{key_id}.{secret_text}"
    return token, AgentKeyDraft(key_id=key_id, digest=credential_digest(pepper, secret_text))


async def verify_agent_key(
    session: AsyncSession, pepper: bytes, presented: str
) -> AgentKey:
    match = _TOKEN_RE.match(presented)
    row: AgentKey | None = None
    presented_digest = _DUMMY_DIGEST
    if match is not None:
        key_id, secret_text = match.group(1), match.group(2)
        presented_digest = credential_digest(pepper, secret_text)
        row = (
            await session.execute(select(AgentKey).where(AgentKey.key_id == key_id))
        ).scalar_one_or_none()
    now = datetime.now(UTC)
    stored = row.digest if row is not None else _DUMMY_DIGEST
    ok = digests_equal(presented_digest, stored)
    if (
        row is None
        or not ok
        or (row.expires_at is not None and row.expires_at <= now)
    ):
        raise AgentAuthError()
    return row
