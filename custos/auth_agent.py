"""Agent-plane authentication dependency (design §5).

Order: failed-auth IP gate (429, no verification, no ledger row) → credential
verify (session closed before any further work) → on failure: in-process
bucket first, then one agent_auth event + one auth.failure audit row →
uniform 401. On success: per-key request bucket + concurrency slot, released
structurally when the dependency exits.

Client IP resolution follows §5 (custos.clientip): forwarded headers are
honored only from trusted peers, walked right-to-left; both the resolved
client and the direct peer are ledgered.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request

from custos.audit import LedgerError, record_audit, record_auth_event
from custos.db.models import AgentKey
from custos.errors import AppError
from custos.keys import AgentAuthError, AgentPrincipal, as_principal, verify_agent_key


def _client_ip(request: Request) -> tuple[str, str]:
    from custos.clientip import resolve_client_ip

    peer = request.client.host if request.client else "unknown"
    # join ALL field instances: proxies may append separate header lines
    xff = ", ".join(request.headers.getlist("x-forwarded-for")) or None
    resolved = resolve_client_ip(peer, xff, request.app.state.settings.trusted_proxies)
    return resolved, peer


async def agent_principal(request: Request) -> AsyncIterator[AgentPrincipal]:
    app = request.app
    limiter = app.state.rate_limiter
    ip, peer_ip = _client_ip(request)
    header = request.headers.get("authorization", "")
    presented = header[7:] if header.lower().startswith("bearer ") else ""

    # 429 gate first: rejected requests never verify and never ledger (§5).
    limiter.check_failed_auth_gate(ip)

    session_maker = app.state.session_maker
    key: AgentKey | None = None
    async with session_maker() as session:
        try:
            key = await verify_agent_key(session, app.state.settings.pepper_raw, presented)
        except AgentAuthError:
            key = None
    # verification session is closed before ledger writes need their own
    # connections — no double-checkout under an auth flood.

    if key is None:
        # in-process bucket advances even if the ledger is down
        limiter.record_failed_auth(ip)
        try:
            await record_auth_event(
                session_maker,
                kind="agent_auth",
                ok=False,
                ip=ip,
                peer_ip=peer_ip,
                budget=app.state.ledger_budget,
                counter=app.state.failure_counter,
            )
            await record_audit(
                session_maker,
                actor_kind="anonymous",
                actor_id=None,
                actor_label="anonymous",
                action="auth.failure",
                item_name=None,
                ok=False,
                detail={"ip": ip, "reason": "agent_auth"},
                budget=app.state.ledger_budget,
                counter=app.state.failure_counter,
            )
        except LedgerError:
            # ledger down: fail closed, never a success (§4)
            raise AppError("internal_error", "ledger unavailable") from None
        raise AppError("unauthorized", "authentication failed")

    principal = as_principal(key)
    from custos.telemetry import annotate_span

    annotate_span(principal.actor_id, "agent_request")
    limiter.check_agent_request(principal.key_id)
    limiter.acquire_agent_slot(principal.key_id)
    try:
        yield principal
    finally:
        limiter.release_agent_slot(principal.key_id)
