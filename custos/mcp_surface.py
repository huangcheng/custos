"""Remote MCP surface (design §7): Streamable HTTP at /mcp.

Bearer verified per request by the same agent auth path as REST (revocation
bites on the next request; a 401 terminates the transport session because
the SDK's auth middleware rejects before any session handling). Tools are
thin calls into the same engine functions as the REST routes — no duplicated
logic. Neither this server nor its transport logs tool arguments or results.
"""

from __future__ import annotations

import json
import logging
from contextvars import ContextVar
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette

from custos.audit import LedgerError, record_audit, record_auth_event
from custos.envexport import env_lines
from custos.errors import AppError
from custos.items import get_item, patch_item, put_item, soft_delete
from custos.keys import AgentAuthError, AgentPrincipal, verify_agent_key
from custos.limits import FieldView, valid_item_name

logger = logging.getLogger("custos.mcp")

_TOOL_RESULT_MAX = 1024 * 1024


_SLOT_KEY: ContextVar[str | None] = ContextVar("mcp_slot_key", default=None)
_IS_SSE_GET: ContextVar[bool] = ContextVar("mcp_is_sse_get", default=False)
_RATE_LIMITED: ContextVar[AppError | None] = ContextVar("mcp_rate_limited", default=None)


def _is_sse_get() -> bool:
    return _IS_SSE_GET.get()


class _AgentTokenVerifier(TokenVerifier):
    """Pure credential verification; gating/ledger/slots live in the
    request middleware (which knows the peer IP and the request lifecycle)."""

    def __init__(self, app: Starlette) -> None:
        self._app = app

    async def verify_token(self, token: str) -> AccessToken | None:
        state = self._app.state
        async with state.session_maker() as session:
            try:
                key = await verify_agent_key(session, state.settings.pepper_raw, token)
            except AgentAuthError:
                return None
        # buckets/slots only AFTER verification (key_ids are not secret —
        # unverified prefixes must never burn a victim's budget). The gate
        # releases the slot when the request ends; SSE GET streams are exempt.
        try:
            # request bucket applies to ALL requests incl. SSE GET (§5);
            # only the concurrency slot exempts the informational stream (§7)
            state.rate_limiter.check_agent_request(key.key_id)
            if not _is_sse_get():
                state.rate_limiter.acquire_agent_slot(key.key_id)
                _SLOT_KEY.set(key.key_id)
        except AppError as exc:
            # surface as a plain 429 from the gate, not a 401
            _RATE_LIMITED.set(exc)
            return None
        return AccessToken(
            token=token,
            client_id=key.key_id,
            scopes=list(key.scopes),
            expires_at=int(key.expires_at.timestamp()) if key.expires_at else None,
            claims={"label": key.label, "mode": key.mode},
        )


class MCPRequestGate:
    """Pure-ASGI gate around the mounted sub-app: failed-auth IP bucket
    (429 before verification, no ledger row), auth-failure ledger rows,
    per-key request bucket + concurrency slot held for the whole request,
    and denial audits for tool-level AppErrors (parity with REST)."""

    def __init__(self, sub: Any, app_state: Any) -> None:
        self.sub = sub
        self.state = app_state

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.sub(scope, receive, send)
            return
        state = self.state
        from custos.clientip import resolve_client_ip

        client = scope.get("client")
        peer_ip = client[0] if client else "unknown"
        xff = ", ".join(
            v.decode(errors="replace") for k, v in scope.get("headers", [])
            if k.lower() == b"x-forwarded-for"
        ) or None
        ip = resolve_client_ip(peer_ip, xff, state.settings.trusted_proxies)
        limiter = state.rate_limiter
        if scope.get("method") == "POST":
            declared = next(
                (v for k, v in scope.get("headers", []) if k.lower() == b"content-length"),
                b"",
            )
            try:
                if declared and int(declared) > 2 * 1024 * 1024:
                    await _plain_response(send, 413, "payload_too_large", None)
                    return
            except ValueError:
                await _plain_response(send, 422, "invalid", None)
                return
        try:
            limiter.check_failed_auth_gate(ip)
        except AppError as exc:
            await _plain_response(send, exc.status, exc.code, exc.headers)
            return
        status_holder: dict[str, int] = {}

        async def _send(message: Any) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                limited_exc = _RATE_LIMITED.get()
                if message["status"] == 401 and limited_exc is not None:
                    # verified key, exhausted bucket: rewrite to the limiter's
                    # 429 before any bytes leave (start not yet forwarded)
                    exc = limited_exc
                    message = {
                        "type": "http.response.start",
                        "status": exc.status,
                        "headers": [
                            (b"content-type", b"application/json"),
                            *[(k.lower().encode(), v.encode())
                              for k, v in (exc.headers or {}).items()],
                        ],
                    }
                    status_holder["status"] = exc.status
                    status_holder["rewrite_body"] = True
                await send(message)
                return
            if message["type"] == "http.response.body" and status_holder.get("rewrite_body"):
                import json as _json

                message = {
                    "type": "http.response.body",
                    "body": _json.dumps({"code": "rate_limited",
                                         "message": "rate limited"}).encode(),
                }
            await send(message)

        # informational SSE GET stream: exempt from the concurrency cap (§7)
        _IS_SSE_GET.set(scope.get("method") == "GET")
        _SLOT_KEY.set(None)
        _RATE_LIMITED.set(None)
        try:
            await self.sub(scope, receive, _send)
        finally:
            slot = _SLOT_KEY.get()
            if slot is not None:
                limiter.release_agent_slot(slot)
            status = status_holder.get("status", 500)
            if status == 401:
                # verified-and-failed credential (or missing): one ledger pair
                limiter.record_failed_auth(ip)
                try:
                    await record_auth_event(
                        state.session_maker, kind="agent_auth", ok=False, ip=ip,
                        peer_ip=peer_ip, budget=state.ledger_budget,
                        counter=state.failure_counter,
                    )
                    await record_audit(
                        state.session_maker, actor_kind="anonymous", actor_id=None,
                        actor_label="anonymous", action="auth.failure", item_name=None,
                        ok=False, detail={"ip": ip, "reason": "agent_auth"},
                        budget=state.ledger_budget, counter=state.failure_counter,
                    )
                except LedgerError:
                    logger.warning("MCP auth-failure ledger write failed (failing closed)")

async def _plain_response(send: Any, status: int, code: str,
                          headers: dict[str, str] | None) -> None:
    import json as _json

    extra = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"), *extra],
    })
    await send({
        "type": "http.response.body",
        "body": _json.dumps({"code": code, "message": code.replace("_", " ")}).encode(),
    })


def _principal() -> AgentPrincipal:
    access = get_access_token()
    if access is None:  # RequireAuthMiddleware guarantees this cannot happen
        raise AppError("unauthorized", "authentication failed")
    return AgentPrincipal(
        actor_id=access.client_id,
        actor_label=str(access.claims.get("label", "")) if access.claims else "",
        mode=str(access.claims.get("mode", "read")) if access.claims else "read",
        scopes=tuple(access.scopes),
    )


def _bounded(result: Any, cap: int) -> Any:
    if len(json.dumps(result, ensure_ascii=True, default=str).encode()) > cap:
        raise AppError("payload_too_large", "tool result too large")
    return result


def _tool_error(exc: AppError) -> Exception:
    """Surface the closed error code to the client without internals."""
    from mcp.shared.exceptions import MCPError
    from mcp.types import INVALID_PARAMS

    return MCPError(code=INVALID_PARAMS, message=f"{exc.code}: {exc.message}")


def build_mcp_server(app: Starlette) -> MCPServer:
    from mcp.server.auth.settings import AuthSettings
    from pydantic import AnyHttpUrl

    # Placeholder issuer/resource URLs: no OAuth provider is configured — the
    # token verifier alone gates the mount (agent keys, not OAuth). The URLs
    # only feed WWW-Authenticate metadata hints on 401s.
    auth = AuthSettings(
        issuer_url=AnyHttpUrl("http://localhost"),
        resource_server_url=AnyHttpUrl("http://localhost/mcp"),
        validate_token_resource=False,
    )
    server = MCPServer(name="custos", token_verifier=_AgentTokenVerifier(app), auth=auth)
    state = app.state

    async def _audit(key: AgentPrincipal, action: str, item_name: str | None,
                     ok: bool, detail: dict[str, Any]) -> None:
        from custos.telemetry import annotate_span

        annotate_span(key.actor_id, action, item_name)
        await record_audit(
            state.session_maker, actor_kind="agent", actor_id=key.actor_id,
            actor_label=key.actor_label, action=action, item_name=item_name,
            ok=ok, detail=detail,
        )

    import functools
    from collections.abc import Awaitable, Callable
    from typing import TypeVar

    _F = TypeVar("_F", bound=Callable[..., Awaitable[Any]])

    _DENIAL_ACTIONS = {
        "list_items": "list", "search": "search", "get": "get", "env": "env",
        "put": "put", "patch": "patch", "delete": "delete",
    }

    def _translate(fn: _F) -> _F:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await fn(*args, **kwargs)
            except AppError as exc:
                if exc.code in ("not_found", "read_only", "key_unavailable",
                                "secret_downgrade_denied"):
                    key = _principal()
                    name = kwargs.get("name") or (args[0] if args else None)
                    try:
                        await record_audit(
                            state.session_maker, actor_kind="agent",
                            actor_id=key.actor_id, actor_label=key.actor_label,
                            action=_DENIAL_ACTIONS.get(fn.__name__, "get"),
                            item_name=valid_item_name(name), ok=False,
                            detail={"reason": exc.code},
                            budget=state.ledger_budget, counter=state.failure_counter,
                        )
                    except LedgerError:
                        raise _tool_error(
                            AppError("internal_error", "ledger unavailable")
                        ) from None
                raise _tool_error(exc) from None
            except Exception:
                # never let exception text (may carry bound values) reach the
                # client or the SDK's error surface
                logger.exception("tool failed")  # sanitized by the log filter
                raise _tool_error(AppError("internal_error", "internal error")) from None

        return wrapper  # type: ignore[return-value]

    @server.tool(name="custos_list_items")
    @_translate
    async def list_items(cursor: str | None = None, limit: int = 50) -> dict[str, Any]:
        from custos.routes_agent import list_via_engine

        key = _principal()
        result = await list_via_engine(state, key, "list", cursor=cursor, limit=limit)
        await _audit(key, "list", None, True, {"count": len(result["items"])})
        return dict(_bounded(result, _TOOL_RESULT_MAX))

    @server.tool(name="custos_search")
    @_translate
    async def search(q: str, cursor: str | None = None, limit: int = 50) -> dict[str, Any]:
        from custos.routes_agent import list_via_engine

        if not q or len(q) > 256:
            raise AppError("invalid", "q required (max 256 chars)")
        key = _principal()
        result = await list_via_engine(state, key, "search", cursor=cursor, limit=limit, q=q)
        await _audit(key, "search", None, True, {"count": len(result["items"])})
        return dict(_bounded(result, _TOOL_RESULT_MAX))

    @server.tool(name="custos_get_item")
    @_translate
    async def get(name: str) -> dict[str, Any]:
        key = _principal()
        async with state.session_maker() as session:
            result = await get_item(session, state.session_maker, state.vault, key, name)
        await _audit(key, "get", name, True, {})
        return dict(_bounded(result, _TOOL_RESULT_MAX))

    @server.tool(name="custos_env")
    @_translate
    async def env(name: str) -> str:
        key = _principal()
        async with state.session_maker() as session:
            result = await get_item(session, state.session_maker, state.vault, key, name)
        views = [FieldView(f["name"], f["secret"], f["value"]) for f in result["fields"]]
        output = env_lines(views)
        await _audit(key, "env", name, True, {})
        return output  # env_lines enforces the 4 MiB bound

    @server.tool(name="custos_put_item")
    @_translate
    async def put(
        name: str, notes: str, fields: list[dict[str, Any]], if_match: str | None = None
    ) -> dict[str, Any]:
        key = _principal()
        body = {"notes": notes, "fields": fields}
        async with state.session_maker() as session:
            result = await put_item(
                session, state.session_maker, state.vault, key, name, body,
                if_match=if_match, upsert=True,
            )
            await session.commit()
        return dict(_bounded(result, _TOOL_RESULT_MAX))

    @server.tool(name="custos_patch_item")
    @_translate
    async def patch(
        name: str,
        notes: str | None = None,
        fields: list[dict[str, Any]] | None = None,
        if_match: str | None = None,
    ) -> dict[str, Any]:
        key = _principal()
        body: dict[str, Any] = {}
        if notes is not None:
            body["notes"] = notes
        if fields is not None:
            body["fields"] = fields
        async with state.session_maker() as session:
            result = await patch_item(
                session, state.session_maker, state.vault, key, name, body,
                if_match=if_match,
            )
            await session.commit()
        return dict(_bounded(result, _TOOL_RESULT_MAX))

    @server.tool(name="custos_delete_item")
    @_translate
    async def delete(name: str) -> dict[str, Any]:
        key = _principal()
        async with state.session_maker() as session:
            await soft_delete(session, state.session_maker, state.vault, key, name)
            await session.commit()
        return {"deleted": True}

    return server


def mount_mcp(app: Any) -> Any:
    """Build the Streamable HTTP sub-app; caller manages its session manager."""
    server = build_mcp_server(app)
    # DNS-rebinding protection: Host must be a loopback literal (the dev/
    # compose topology publishes on 127.0.0.1) or match the configured
    # public RP host when present. Tests use 'testserver'.
    import os

    from mcp.server.transport_security import TransportSecuritySettings

    allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*", "testserver"]
    allowed_origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*",
                       "http://testserver"]
    # proxied deployments declare their public RP host (same env as passkeys)
    rp_id = os.environ.get("CUSTOS_WEBAUTHN_RP_ID", "")
    if rp_id and rp_id not in ("localhost", "127.0.0.1"):
        allowed_hosts.append(rp_id)
        allowed_origins.append(f"https://{rp_id}")
    sub = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        max_request_body_size=2 * 1024 * 1024,
        transport_security=TransportSecuritySettings(
            allowed_hosts=allowed_hosts, allowed_origins=allowed_origins
        ),
    )
    return sub, MCPRequestGate(sub, app.state)
