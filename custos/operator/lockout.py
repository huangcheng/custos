"""Credential lockout (design §5).

Sliding 15-min window. Per-IP: 10 failures → 15-min block. Per-account:
30 failures → 30-min block, NON-extending (anchored at the 30th failure;
later failures during the block do not push the end). Suppressions
(`ip:<addr>`, `ip:*`, `account`) make lockout queries ignore ledger rows at
or before the marker ts. `agent_auth` never counts here (it has its own
30/min/IP request limiter). `setup` counts per-IP only (no account yet).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from custos.audit import FailureCounter
from custos.db.models import AuthEvent, LockoutSuppression
from custos.errors import AppError

_COUNTED_KINDS = (
    "login_password", "login_totp", "login_passkey", "login_recovery", "step_up", "setup"
)
_IP_THRESHOLD = 10
_IP_WINDOW = 15 * 60
_IP_BLOCK = 15 * 60
_ACCOUNT_THRESHOLD = 30
_ACCOUNT_WINDOW = 30 * 60
_ACCOUNT_BLOCK = 30 * 60


async def _suppression_ts(session: AsyncSession, scope: str) -> datetime | None:
    return (
        await session.execute(
            select(func.max(LockoutSuppression.suppressed_until_events_ts)).where(
                LockoutSuppression.scope == scope
            )
        )
    ).scalar_one_or_none()


async def check_lockout(
    session: AsyncSession,
    *,
    ip: str,
    account_exists: bool,
    counter: FailureCounter | None = None,
) -> None:
    now = datetime.now(UTC)

    # Flood fallback (§5): when the global ledger budget is exhausted,
    # failures live only in the in-process counter. Mirror the ledger's
    # non-extending anchor (Nth-most-recent failure + block). Suppressions
    # cannot clear counter-only blocks (monotonic ts vs wall-clock markers);
    # break-glass unlock clears the ledger path — documented limitation.
    if counter is not None:
        import time as _time

        mono_now = _time.monotonic()
        ip_anchor = counter.nth_most_recent_ts(_IP_THRESHOLD, ip=ip)
        if ip_anchor is not None:
            remaining = _IP_BLOCK - (mono_now - ip_anchor)
            if remaining > 0:
                raise AppError("locked_out", "too many attempts",
                               headers={"Retry-After": str(int(remaining) + 1)})
        if account_exists:
            acct_anchor = counter.nth_most_recent_ts(_ACCOUNT_THRESHOLD, account=True)
            if acct_anchor is not None:
                remaining = _ACCOUNT_BLOCK - (mono_now - acct_anchor)
                if remaining > 0:
                    raise AppError("locked_out", "too many attempts",
                                   headers={"Retry-After": str(int(remaining) + 1)})

    # per-IP window (setup counts here too)
    ip_supp = await _suppression_ts(session, f"ip:{ip}")
    wild_supp = await _suppression_ts(session, "ip:*")
    ip_floor = now - timedelta(seconds=_IP_WINDOW)
    for supp in (ip_supp, wild_supp):
        if supp is not None and supp > ip_floor:
            ip_floor = supp
    ip_failures = list(
        (
            await session.execute(
                select(AuthEvent.ts)
                .where(
                    AuthEvent.ip == ip,
                    AuthEvent.ok.is_(False),
                    AuthEvent.kind.in_(_COUNTED_KINDS),
                    AuthEvent.ts > ip_floor,
                )
                .order_by(AuthEvent.ts)
            )
        ).scalars()
    )
    if len(ip_failures) >= _IP_THRESHOLD:
        # block anchored at the 10th failure; expires 15 min after it
        anchor = ip_failures[_IP_THRESHOLD - 1]
        expires = anchor + timedelta(seconds=_IP_BLOCK)
        if expires > now:
            raise AppError(
                "locked_out", "too many attempts",
                headers={"Retry-After": str(max(1, int((expires - now).total_seconds()) + 1))},
            )

    if not account_exists:
        return  # no account → per-account window cannot apply (setup path)

    acct_supp = await _suppression_ts(session, "account")
    acct_floor = now - timedelta(seconds=_ACCOUNT_WINDOW)
    if acct_supp is not None and acct_supp > acct_floor:
        acct_floor = acct_supp
    # account counts everything except setup (setup is per-IP only)
    acct_kinds = tuple(k for k in _COUNTED_KINDS if k != "setup")
    acct_failures = list(
        (
            await session.execute(
                select(AuthEvent.ts)
                .where(
                    AuthEvent.ok.is_(False),
                    AuthEvent.kind.in_(acct_kinds),
                    AuthEvent.ts > acct_floor,
                )
                .order_by(AuthEvent.ts)
                .limit(_ACCOUNT_THRESHOLD)
            )
        ).scalars()
    )
    if len(acct_failures) >= _ACCOUNT_THRESHOLD:
        # NON-extending: anchor at the 30th failure in the window, not the last
        anchor = acct_failures[_ACCOUNT_THRESHOLD - 1]
        expires = anchor + timedelta(seconds=_ACCOUNT_BLOCK)
        if expires > now:
            raise AppError(
                "locked_out", "too many attempts",
                headers={"Retry-After": str(max(1, int((expires - now).total_seconds()) + 1))},
            )
