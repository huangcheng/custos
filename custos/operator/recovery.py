"""Recovery codes + recovery_reset promotion (design §5).

10 codes, 16 chars from the canonical Crockford alphabet (80-bit). Stored
as HMAC(pepper, normalized code). Verification scans unconsumed rows with
constant-time compare; consume is a guarded single-use UPDATE. Password
change revokes sessions/tokens/codes and promotes a recovery_reset session
to full, atomically disabling TOTP, deleting passkeys, and issuing fresh
codes.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from custos.crypto import credential_digest, digests_equal
from custos.db.models import (
    OperatorAccount,
    OperatorSession,
    OperatorToken,
    PasskeyCredential,
    RecoveryCode,
)
from custos.errors import AppError
from custos.operator.account import hash_password, validate_password, verify_password
from custos.operator.sessions import create_session, revoke_all_sessions

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # 32 symbols, I/L/O/U excluded
_CODE_LEN = 16


def normalize_code(presented: str) -> str | None:
    text = presented.upper().replace("-", "").replace(" ", "")
    text = text.replace("I", "1").replace("L", "1").replace("O", "0")
    if len(text) != _CODE_LEN or any(c not in _ALPHABET for c in text):
        return None
    return text


async def issue_codes(session: AsyncSession, pepper: bytes) -> list[str]:
    # prior unconsumed codes are consumed (soft) — never deleted
    await session.execute(
        update(RecoveryCode)
        .where(RecoveryCode.consumed_at.is_(None))
        .values(consumed_at=datetime.now(UTC))
    )
    codes: list[str] = []
    for _ in range(10):
        code = "".join(secrets.choice(_ALPHABET) for _ in range(_CODE_LEN))
        codes.append(code)
        session.add(RecoveryCode(digest=credential_digest(pepper, code)))
    await session.flush()
    return codes


async def consume_code(session: AsyncSession, pepper: bytes, presented: str) -> bool:
    normalized = normalize_code(presented)
    if normalized is None:
        return False
    target = credential_digest(pepper, normalized)
    rows = list(
        (
            await session.execute(
                select(RecoveryCode).where(RecoveryCode.consumed_at.is_(None))
            )
        ).scalars()
    )
    matched_id = None
    # constant-time compares padded to 10 with dummy digests — timing never
    # leaks the remaining-code count; max() guards the transient >10 case if
    # concurrent issuances ever break the ≤10-live invariant (no code skipped)
    dummy = bytes(32)
    for i in range(max(10, len(rows))):
        row = rows[i] if i < len(rows) else None
        if digests_equal(row.digest if row is not None else dummy, target) and row is not None:
            matched_id = row.id
    if matched_id is None:
        return False
    result = await session.execute(
        update(RecoveryCode)
        .where(RecoveryCode.id == matched_id, RecoveryCode.consumed_at.is_(None))
        .values(consumed_at=datetime.now(UTC))
    )
    return bool(result.rowcount == 1)  # type: ignore[attr-defined]


async def change_password(
    session: AsyncSession,
    sess_row: OperatorSession,
    *,
    current: str,
    new: str,
    pepper: bytes,
    semaphore: Any = None,
    executor: Any = None,
    wait_cap: float = 10.0,
) -> tuple[OperatorSession, list[str], str]:
    import asyncio

    acct = (
        await session.execute(select(OperatorAccount).where(OperatorAccount.id == 1))
    ).scalar_one()
    loop = asyncio.get_running_loop()
    if semaphore is not None:
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=wait_cap)
        except TimeoutError:
            raise AppError("rate_limited", "authentication busy",
                           headers={"Retry-After": "1"}) from None
    try:
        if executor is not None:
            ok = await loop.run_in_executor(executor, verify_password, acct.password_hash, current)
        else:
            ok = await asyncio.to_thread(verify_password, acct.password_hash, current)
    finally:
        if semaphore is not None:
            semaphore.release()
    if not ok:
        raise AppError("unauthorized", "authentication failed")
    validate_password(new)
    acct.password_hash = await asyncio.to_thread(hash_password, new)

    is_recovery = sess_row.purpose == "recovery_reset"
    # revoke all sessions + operator tokens + consume codes (compromise recovery)
    await revoke_all_sessions(session, except_id=sess_row.id if is_recovery else None)
    await session.execute(
        update(OperatorToken)
        .where(OperatorToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    # revoke bound unconsumed step-up/run tokens (token principals too)
    from custos.db.models import StepUpToken

    await session.execute(
        delete(StepUpToken).where(StepUpToken.consumed_at.is_(None))
    )
    await session.execute(
        update(RecoveryCode)
        .where(RecoveryCode.consumed_at.is_(None))
        .values(consumed_at=datetime.now(UTC))
    )

    fresh_codes: list[str] = []
    if is_recovery:
        # promote in place: full purpose, fresh TTLs, TOTP off, passkeys gone
        # (attacker-registered factors must not survive recovery — reset-mfa
        # parity), fresh codes
        sess_row.purpose = "full"
        sess_row.idle_ttl_seconds = 43200
        sess_row.absolute_expires_at = datetime.now(UTC) + timedelta(days=7)
        acct.totp_enabled = False
        acct.totp_secret = None
        acct.totp_key_version = None
        await session.execute(delete(PasskeyCredential))
        fresh_codes = await issue_codes(session, pepper)
        promoted = sess_row
        cookie = ""  # recovery_reset keeps its existing cookie (promoted in place)
    else:
        # full-session change: mint one replacement session, return its cookie
        promoted, cookie = await create_session(session, purpose="full")
    await session.flush()
    return promoted, fresh_codes, cookie
