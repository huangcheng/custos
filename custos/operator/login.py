"""Password login (design §5). Uniform failures, one auth_event per failed
request, off-loop argon2 under a global concurrency semaphore.

The second factor (TOTP/recovery) is resolved via a pluggable hook so TOTP
(Task 5) and recovery (Task 6) can attach without editing this module's
failure-shape logic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from custos.audit import FailureCounter, LedgerBudget, record_audit, record_auth_event
from custos.clientip import resolve_client_ip
from custos.crypto import digests_equal
from custos.db.models import OperatorAccount, OperatorSession
from custos.errors import AppError
from custos.operator.account import verify_password
from custos.operator.sessions import create_session

# factor hook: (session, maker, account, ctx) -> stage name that failed, or
# None on success. ctx carries password/totp/recovery_code/ip/peer/budget/counter.
FactorHook = Callable[
    [AsyncSession, async_sessionmaker[AsyncSession], OperatorAccount, dict[str, Any]],
    Awaitable[str | None],
]


async def _fail(
    maker: async_sessionmaker[AsyncSession],
    *,
    kind: str,
    ip: str,
    peer_ip: str,
    budget: LedgerBudget | None,
    counter: FailureCounter | None,
) -> None:
    await record_auth_event(
        maker, kind=kind, ok=False, ip=ip, peer_ip=peer_ip, budget=budget, counter=counter
    )
    await record_audit(
        maker, actor_kind="anonymous", actor_id=None, actor_label="anonymous",
        action="auth.failure", item_name=None, ok=False,
        detail={"ip": ip, "reason": kind}, budget=budget, counter=counter,
    )


async def login(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    *,
    semaphore: asyncio.Semaphore,
    executor: ThreadPoolExecutor,
    wait_cap: float,
    username: str,
    password: str,
    totp: str | None,
    recovery_code: str | None,
    factor_hook: FactorHook | None,
    vault: Any,
    recovery_hook: Any,
    ip: str,
    peer_ip: str,
    budget: LedgerBudget | None,
    counter: FailureCounter | None,
) -> tuple[OperatorSession, str]:
    if not isinstance(password, str):
        raise AppError("invalid", "password must be a string")
    try:
        password.encode("utf-8")
        username.encode("utf-8")
    except UnicodeEncodeError:
        raise AppError("invalid", "inputs must be valid UTF-8") from None

    # Acquire the permit BEFORE any DB work: a queued request must not pin a
    # pooled connection. Concurrency is bounded by the 2-worker executor, so a
    # cancelled request cannot hand its slot to a new one while argon2 still
    # runs (§5 bounded memory). wait_for on the semaphore bounds the queue.
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout=wait_cap)
    except TimeoutError:
        raise AppError(
            "rate_limited", "authentication busy", headers={"Retry-After": "1"}
        ) from None
    acct = (
        await session.execute(select(OperatorAccount).where(OperatorAccount.id == 1))
    ).scalar_one_or_none()
    loop = asyncio.get_running_loop()
    try:
        password_ok = await loop.run_in_executor(
            executor, verify_password, acct.password_hash if acct else _DUMMY_HASH, password
        )
    finally:
        semaphore.release()
    # constant-shape: username mismatch and bad password fail identically;
    # argon2 ran regardless (dummy hash for absent account) so timing matches
    username_ok = acct is not None and digests_equal(
        username.encode(), acct.username.encode()
    )
    if acct is None or not username_ok or not password_ok:
        await _fail(maker, kind="login_password", ip=ip, peer_ip=peer_ip,
                    budget=budget, counter=counter)
        raise AppError("unauthorized", "authentication failed")

    ctx = {
        "totp": totp, "recovery_code": recovery_code,
        "ip": ip, "peer_ip": peer_ip, "budget": budget, "counter": counter,
        "vault": vault, "recovery_hook": recovery_hook,
    }
    if factor_hook is not None:
        failed_stage = await factor_hook(session, maker, acct, ctx)
    elif acct.totp_enabled:
        failed_stage = "login_totp"  # factor required but no verifier attached
    else:
        failed_stage = None
    if failed_stage is not None:
        await _fail(maker, kind=failed_stage, ip=ip, peer_ip=peer_ip,
                    budget=budget, counter=counter)
        raise AppError("unauthorized", "authentication failed")

    row, cookie = await create_session(session, purpose="full")
    # success audit is written by the route AFTER commit (a failed commit
    # must not leave an operator.login row for a session that never existed)
    return row, cookie


# A valid pinned-parameter PHC string (obviously fake input) so the
# unknown-user path performs the same argon2 work as a real verify.
async def default_factor_hook(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    acct: OperatorAccount,
    ctx: dict[str, Any],
) -> str | None:
    """Login second factor (§5): TOTP when enabled; recovery code alternative
    (Task 6 attaches). A code supplied while TOTP is disabled is ignored."""
    totp_code = ctx.get("totp")
    recovery_code = ctx.get("recovery_code")
    if acct.totp_enabled:
        if recovery_code is not None:
            hook = ctx.get("recovery_hook")
            if hook is not None and await hook(session, maker, recovery_code, ctx):
                return None
            return "login_recovery"
        if totp_code is None:
            return "login_totp"
        from custos.operator.totp import verify_totp

        vault = ctx["vault"]
        if await verify_totp(session, vault, totp_code, site="login"):
            return None
        return "login_totp"
    return None


_DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$"
    "Y3fAXLnSnuBcZRM9mzloVw$5SvDvzPF2uFOWH3wcZIG4+TiA+xz6jw603HhuZn7KEE"
)


def resolve_client(request: Any, settings: Any) -> tuple[str, str]:
    peer = request.client.host if request.client else "unknown"
    xff = ", ".join(request.headers.getlist("x-forwarded-for")) or None
    return resolve_client_ip(peer, xff, settings.trusted_proxies), peer
