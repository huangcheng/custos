"""CLI device hand-off (design §5): mint → approve → exchange.

The device code travels in the console URL fragment (never server logs);
the operator confirms the minting client's IP/UA, approves once (guarded),
and a ≥128-bit transfer code is shown once. Exchange increments attempts
then consumes in two guarded UPDATEs (5 tries, window = min(device expiry,
approval+2min)); the issued session has shortened TTLs (1h idle / 12h abs).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from custos.crypto import digests_equal
from custos.db.models import DeviceCode, OperatorSession
from custos.errors import AppError
from custos.operator.sessions import create_session

_DEVICE_TTL = 300
_TRANSFER_TTL = 120
_MAX_ATTEMPTS = 5
_MAX_LIVE_PER_IP = 5


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _hash(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


async def mint_device(session: AsyncSession, *, ip: str, user_agent: str) -> tuple[str, datetime]:
    # serialize per-IP mint so the live-row cap is atomic (single worker)
    from sqlalchemy import text

    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:ip))"), {"ip": f"device-mint:{ip}"}
    )
    live = (
        await session.execute(
            select(func.count()).select_from(DeviceCode).where(
                DeviceCode.client_ip == ip,
                DeviceCode.consumed_at.is_(None),
                DeviceCode.expires_at > datetime.now(UTC),
            )
        )
    ).scalar_one()
    if live >= _MAX_LIVE_PER_IP:
        raise AppError("rate_limited", "too many pending device requests")
    code = _b64url(secrets.token_bytes(16))  # 128-bit
    expires = datetime.now(UTC) + timedelta(seconds=_DEVICE_TTL)
    session.add(DeviceCode(code_hash=_hash(code), client_ip=ip,
                           user_agent=user_agent, expires_at=expires))
    await session.flush()
    return code, expires


async def lookup_device(session: AsyncSession, code: str) -> dict[str, Any]:
    row = (
        await session.execute(select(DeviceCode).where(DeviceCode.code_hash == _hash(code)))
    ).scalar_one_or_none()
    if row is None or row.consumed_at is not None or row.expires_at <= datetime.now(UTC):
        raise AppError("not_found", "not found")
    return {"client_ip": row.client_ip, "user_agent": row.user_agent,
            "expires_at": row.expires_at.isoformat()}


async def approve_device(
    session: AsyncSession, sess: OperatorSession, code: str
) -> tuple[str, datetime]:
    row = (
        await session.execute(select(DeviceCode).where(DeviceCode.code_hash == _hash(code)))
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None or row.expires_at <= now:
        raise AppError("not_found", "not found")
    if row.consumed_at is not None:
        raise AppError("conflict", "device already used")
    transfer = _b64url(secrets.token_bytes(16))
    new_expiry = max(row.expires_at, now + timedelta(seconds=_TRANSFER_TTL))
    result = await session.execute(
        update(DeviceCode)
        .where(DeviceCode.id == row.id, DeviceCode.approved_by_session.is_(None),
               DeviceCode.expires_at > now)
        .values(approved_by_session=sess.id, approved_at=now,
                transfer_hash=_hash(transfer), expires_at=new_expiry)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise AppError("conflict", "device already approved")
    deadline = now + timedelta(seconds=_TRANSFER_TTL)
    return transfer, deadline


async def exchange_device(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    code: str,
    transfer: str,
) -> tuple[OperatorSession, str]:
    row = (
        await session.execute(select(DeviceCode).where(DeviceCode.code_hash == _hash(code)))
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None or row.consumed_at is not None or row.expires_at <= now:
        raise AppError("unauthorized", "authentication failed")
    # transfer window = min(device expiry, approved_at + 2min) (§5)
    if row.approved_at is None or row.approved_at + timedelta(seconds=_TRANSFER_TTL) <= now:
        raise AppError("unauthorized", "authentication failed")
    # increment attempts in an INDEPENDENT committed transaction so a
    # mismatched attempt still burns a try even when the caller rolls back.
    async with maker() as inc_session:
        inc = await inc_session.execute(
            update(DeviceCode).where(DeviceCode.id == row.id)
            .values(exchange_attempts=DeviceCode.exchange_attempts + 1)
            .returning(DeviceCode.exchange_attempts)
        )
        attempts = inc.scalar_one()
        await inc_session.commit()
    if attempts > _MAX_ATTEMPTS:
        raise AppError("unauthorized", "authentication failed")
    if row.transfer_hash is None or not digests_equal(row.transfer_hash, _hash(transfer)):
        raise AppError("unauthorized", "authentication failed")
    result = await session.execute(
        update(DeviceCode)
        .where(
            DeviceCode.id == row.id,
            DeviceCode.consumed_at.is_(None),
            DeviceCode.exchange_attempts <= _MAX_ATTEMPTS,
            DeviceCode.expires_at > now,
        )
        .values(consumed_at=now)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise AppError("unauthorized", "authentication failed")
    sess_row, cookie = await create_session(
        session, purpose="full", idle_ttl=3600, absolute_ttl=43200
    )
    return sess_row, cookie
