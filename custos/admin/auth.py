"""Admin dual-auth + authority matrix (design §5/§6, plan 3).

AdminPrincipal satisfies the item-engine Principal protocol; every admin
principal has full item-plane authority (rev 38). Gates:
- require_admin: cookie XOR co- bearer (both → 401); 300/min per principal.
- require_session_only: tokens → 403 session_required BEFORE any state
  check (audited auth.failure); sessions consume a single step-up.
- require_sensitive: session step-up OR allow_sensitive token; plain
  tokens → 401 step_up_required (they may still step up interactively).
Operator-token auth failures are audit-only (no lockout kind exists for
them in the §5 closed list) and fail closed if the ledger is down.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from custos.audit import LedgerError, record_audit
from custos.db.models import OperatorSession, OperatorToken
from custos.errors import AppError
from custos.operator.sessions import COOKIE_NAME
from custos.operator_tokens import OperatorAuthError, verify_operator_token

router = APIRouter(prefix="/api/admin")


@dataclass(frozen=True)
class AdminPrincipal:
    actor_id: str
    actor_label: str
    actor_kind: str  # "operator_session" | "operator_token"
    row_id: uuid.UUID
    key_id: str | None = None
    allow_sensitive: bool = False

    @property
    def plane(self) -> str:
        """Cursor binding (§4): sessions bind to the plane, tokens to key_id."""
        return "session" if self.actor_kind == "operator_session" else str(self.key_id)


def _session_principal(sess: OperatorSession) -> AdminPrincipal:
    return AdminPrincipal(
        actor_id=str(sess.id),
        actor_label="operator",
        actor_kind="operator_session",
        row_id=sess.id,
    )


def _token_principal(row: OperatorToken) -> AdminPrincipal:
    return AdminPrincipal(
        actor_id=row.key_id,
        actor_label=row.label,
        actor_kind="operator_token",
        row_id=row.id,
        key_id=row.key_id,
        allow_sensitive=row.allow_sensitive,
    )


def _client_ip(request: Any) -> str:
    from custos.clientip import resolve_client_ip

    peer = request.client.host if request.client else "unknown"
    xff = ", ".join(request.headers.getlist("x-forwarded-for")) or None
    return resolve_client_ip(peer, xff, request.app.state.settings.trusted_proxies)


async def _audit_denial(
    request: Any, reason: str, principal: AdminPrincipal | None = None
) -> None:
    ip = _client_ip(request)
    if reason == "admin_auth":
        # unauthenticated flood path: same 30/min/IP gate + shared ledger
        # budget as the agent plane (§5) — rejected requests never ledger
        limiter = request.app.state.rate_limiter
        limiter.check_failed_auth_gate(ip)
        limiter.record_failed_auth(ip)
    # a KNOWN token probing a session-only route keeps its key_id attribution
    # (forensics); anonymous failures stay actor_id=None per the closed set
    actor_kind = "anonymous" if principal is None else principal.actor_kind
    actor_id = None if principal is None else principal.actor_id
    actor_label = "anonymous" if principal is None else principal.actor_label
    try:
        await record_audit(
            request.app.state.session_maker,
            actor_kind=actor_kind,
            actor_id=actor_id,
            actor_label=actor_label,
            action="auth.failure",
            item_name=None,
            ok=False,
            detail={"ip": ip, "reason": reason},
            budget=request.app.state.ledger_budget,
            counter=request.app.state.failure_counter,
        )
    except LedgerError:
        raise AppError("internal_error", "ledger unavailable") from None


async def require_admin(request: Request) -> AdminPrincipal:
    from custos.operator.sessions import require_session

    has_bearer = bool(request.headers.get("authorization"))
    if has_bearer:
        if request.cookies.get(COOKIE_NAME):
            raise AppError("unauthorized", "authentication failed")
        # §5: 429 gate BEFORE verification — gated probes never touch the DB
        request.app.state.rate_limiter.check_failed_auth_gate(_client_ip(request))
        header = request.headers.get("authorization", "")
        presented = header[7:] if header.lower().startswith("bearer ") else ""
        maker: async_sessionmaker[AsyncSession] = request.app.state.session_maker
        row: OperatorToken | None = None
        async with maker() as session:
            try:
                row = await verify_operator_token(
                    session, request.app.state.settings.pepper_raw, presented
                )
            except OperatorAuthError:
                row = None
        if row is None:
            await _audit_denial(request, "admin_auth")
            raise AppError("unauthorized", "authentication failed")
        principal = _token_principal(row)
    else:
        sess = await require_session(request)
        principal = _session_principal(sess)
    request.app.state.rate_limiter.check_admin_request(
        f"admin:{principal.actor_kind}:{principal.row_id}"
    )
    request.state.admin_principal = principal
    return principal


async def _header_step_up(
    request: Any, principal: AdminPrincipal, *, consume: bool
) -> None:
    from custos.operator.stepup import consume_step_up, peek_single

    token = request.headers.get("x-step-up-token", "")
    if not token:
        raise AppError("step_up_required", "step-up required")
    maker = request.app.state.session_maker
    async with maker() as session:
        presenter: OperatorSession | OperatorToken | None
        if principal.actor_kind == "operator_session":
            presenter = await session.get(OperatorSession, principal.row_id)
        else:
            presenter = await session.get(OperatorToken, principal.row_id)
        if consume:
            await consume_step_up(session, token, presenter)
            await session.commit()
        else:
            await peek_single(session, token, presenter)


async def peek_step_up(request: Any, principal: AdminPrincipal) -> None:
    """Validate the header step-up WITHOUT consuming (write pre-gate): a
    request rejected later must never burn the operator's token."""
    await _header_step_up(request, principal, consume=False)


async def require_session_only(request: Request) -> AdminPrincipal:
    principal = await require_admin(request)
    if principal.actor_kind != "operator_session":
        # §6: the gate fires BEFORE any state check — audited, uniform 403
        await _audit_denial(request, "session_required", principal)
        raise AppError("session_required", "interactive session required")
    await _header_step_up(request, principal, consume=True)
    return principal


async def require_sensitive(request: Request) -> AdminPrincipal:
    principal = await require_admin(request)
    if principal.actor_kind == "operator_token" and principal.allow_sensitive:
        request.state.allow_sensitive = True
        return principal
    # sessions AND plain tokens: a valid presenter-bound step-up header
    # (a plain token may step up interactively; §5 binds step-ups to either)
    await _header_step_up(request, principal, consume=True)
    return principal


@router.get("/ping")
async def ping(_: AdminPrincipal = Depends(require_admin)) -> dict[str, bool]:
    """Permanent auth-only smoke endpoint (never carries data)."""
    return {"ok": True}
