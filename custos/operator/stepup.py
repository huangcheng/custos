"""Step-up tokens (design §5): single-use, presenter-bound, TTL 5 min.

Factor set equals login's (password + TOTP when enabled, or password +
recovery code). Failures feed lockout (kind step_up). Consumption requires
the presenting principal to equal the bound principal and still be live.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from custos.audit import FailureCounter, LedgerBudget, record_auth_event
from custos.db.models import OperatorAccount, OperatorSession, OperatorToken, StepUpToken
from custos.errors import AppError
from custos.operator.account import verify_password

_STEPUP_TTL = 300


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


async def mint_step_up(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    sess_row: OperatorSession,
    *,
    password: str,
    vault: Any,
    totp: str | None = None,
    recovery_code: str | None = None,
    pepper: bytes | None = None,
    ip: str = "unknown",
    peer_ip: str = "unknown",
    budget: LedgerBudget | None = None,
    counter: FailureCounter | None = None,
    kind: str = "single",
    semaphore: Any = None,
    executor: Any = None,
    wait_cap: float = 10.0,
) -> str:
    import asyncio

    from custos.audit import record_audit

    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        raise AppError("invalid", "inputs must be valid UTF-8") from None
    acct = (
        await session.execute(select(OperatorAccount).where(OperatorAccount.id == 1))
    ).scalar_one()

    async def _fail() -> None:
        await record_auth_event(
            maker, kind="step_up", ok=False, ip=ip, peer_ip=peer_ip,
            budget=budget, counter=counter,
        )
        await record_audit(
            maker, actor_kind="anonymous", actor_id=None, actor_label="anonymous",
            action="auth.failure", item_name=None, ok=False,
            detail={"ip": ip, "reason": "step_up"}, budget=budget, counter=counter,
        )

    # bounded argon2 (same global cap as login, §5)
    loop = asyncio.get_running_loop()
    if semaphore is not None:
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=wait_cap)
        except TimeoutError:
            raise AppError("rate_limited", "authentication busy",
                           headers={"Retry-After": "1"}) from None
    try:
        if executor is not None:
            ok = await loop.run_in_executor(executor, verify_password, acct.password_hash, password)
        else:
            ok = await asyncio.to_thread(verify_password, acct.password_hash, password)
    finally:
        if semaphore is not None:
            semaphore.release()
    if not ok:
        await _fail()
        raise AppError("unauthorized", "authentication failed")
    if recovery_code is not None:
        # recovery code replaces the TOTP factor, honored regardless of TOTP
        # state (parity with login's factor hook)
        from custos.operator.recovery import consume_code

        if pepper is None or not await consume_code(session, pepper, recovery_code):
            await _fail()
            raise AppError("unauthorized", "authentication failed")
    elif acct.totp_enabled:
        if totp is None:
            await _fail()
            raise AppError("unauthorized", "authentication failed")
        from custos.operator.totp import verify_totp

        if not await verify_totp(session, vault, totp, site="stepup"):
            await _fail()
            raise AppError("unauthorized", "authentication failed")

    token = _b64url(secrets.token_bytes(32))
    session.add(
        StepUpToken(
            session_id=sess_row.id,
            nonce_hash=_hash(token),
            kind=kind,
            expires_at=datetime.now(UTC) + timedelta(seconds=_STEPUP_TTL),
        )
    )
    await session.flush()
    return token


async def _load_valid_single(
    session: AsyncSession, token: str, presenter: OperatorSession | OperatorToken | None
) -> StepUpToken:
    if presenter is None:
        raise AppError("step_up_required", "step-up required")
    row = (
        await session.execute(
            select(StepUpToken).where(StepUpToken.nonce_hash == _hash(token))
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if isinstance(presenter, OperatorToken):
        bound = row is not None and row.operator_token_id == presenter.id
        live = presenter.revoked_at is None and presenter.expires_at > now
    else:
        bound = row is not None and row.session_id == presenter.id
        live = presenter.revoked_at is None
    if (
        row is None
        or row.kind != "single"
        or row.consumed_at is not None
        or row.expires_at <= now
        or not bound
        or not live
    ):
        raise AppError("step_up_required", "step-up required")
    return row


async def peek_single(
    session: AsyncSession, token: str, presenter: OperatorSession | OperatorToken | None
) -> StepUpToken:
    """Validate WITHOUT consuming — the admin write pre-gate must not burn
    a token on a request that is about to be rejected."""
    return await _load_valid_single(session, token, presenter)


async def consume_step_up(
    session: AsyncSession, token: str, presenter: OperatorSession | OperatorToken | None
) -> StepUpToken:
    row = await _load_valid_single(session, token, presenter)
    now = datetime.now(UTC)
    result = await session.execute(
        update(StepUpToken)
        .where(StepUpToken.id == row.id, StepUpToken.consumed_at.is_(None))
        .values(consumed_at=now)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise AppError("step_up_required", "step-up required")
    return row


def require_step_up(action: str) -> Any:
    """Dependency factory: consume a single-use step-up token bound to the
    presenting session. Admin-plane gates (session-or-token) live in
    custos.admin.auth; this factory stays session-only for /api/auth routes.

    Note: annotations must resolve from module globals (this module uses
    `from __future__ import annotations`), so Request is imported at top.
    """
    from custos.operator.sessions import require_session

    async def _dep(request: Request) -> OperatorSession:
        sess = await require_session(request)
        token = request.headers.get("x-step-up-token", "")
        if not token:
            raise AppError("step_up_required", "step-up required")
        async with request.app.state.session_maker() as session:
            presenter = await session.get(OperatorSession, sess.id)
            await consume_step_up(session, token, presenter)
            await session.commit()
        return sess

    return _dep
