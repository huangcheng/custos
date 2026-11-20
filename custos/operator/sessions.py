"""Operator sessions + CSRF (design §3/§5).

Opaque cookie (32 random bytes b64url), SHA-256 stored; idle/absolute
TTLs per purpose; invalidation sets revoked_at (rows survive for audit
attribution) and explicitly deletes bound unconsumed step-up tokens.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from custos.config import Settings
from custos.crypto import digests_equal
from custos.db.models import OperatorSession, StepUpToken
from custos.errors import AppError

COOKIE_NAME = "custos_session"
RECOVERY_RESET_TTL = 1800  # §5: 30-minute fixed window, no idle extension


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token_hash(cookie: str) -> bytes:
    return hashlib.sha256(cookie.encode()).digest()


async def create_session(
    session: AsyncSession,
    *,
    purpose: str = "full",
    idle_ttl: int = 43200,
    absolute_ttl: int = 604800,
) -> tuple[OperatorSession, str]:
    if purpose == "recovery_reset":
        # §4/§5 pinned invariants — never caller-supplied, so a forgotten
        # argument cannot mint a long-lived break-glass session
        idle_ttl, absolute_ttl = 0, RECOVERY_RESET_TTL
    cookie = _b64url(secrets.token_bytes(32))
    now = datetime.now(UTC)
    row = OperatorSession(
        token_hash=_token_hash(cookie),
        csrf_token=_b64url(secrets.token_bytes(32)),
        purpose=purpose,
        idle_ttl_seconds=idle_ttl,
        absolute_expires_at=now + timedelta(seconds=absolute_ttl),
    )
    session.add(row)
    await session.flush()
    return row, cookie


async def resolve_session(session: AsyncSession, cookie: str) -> OperatorSession:
    row = (
        await session.execute(
            select(OperatorSession).where(OperatorSession.token_hash == _token_hash(cookie))
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None or row.revoked_at is not None:
        raise AppError("unauthorized", "authentication failed")
    if row.absolute_expires_at <= now:
        raise AppError("unauthorized", "authentication failed")
    if row.idle_ttl_seconds > 0:
        if row.last_seen_at + timedelta(seconds=row.idle_ttl_seconds) <= now:
            raise AppError("unauthorized", "authentication failed")
        row.last_seen_at = now  # recovery_reset (idle 0) never refreshes
    return row


async def revoke_all_sessions(session: AsyncSession, except_id: Any = None) -> None:
    rows = (
        (await session.execute(select(OperatorSession).where(OperatorSession.revoked_at.is_(None))))
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    ids = [r.id for r in rows if r.id != except_id]
    for row in rows:
        if row.id != except_id:
            row.revoked_at = now
    if ids:
        await session.execute(
            delete(StepUpToken).where(
                StepUpToken.session_id.in_(ids), StepUpToken.consumed_at.is_(None)
            )
        )


class _HasHeaders(Protocol):
    @property
    def headers(self) -> Any: ...


def check_csrf(request: _HasHeaders, sess: OperatorSession) -> None:
    presented = request.headers.get("x-csrf-token", "")
    if not presented or not digests_equal(presented.encode(), sess.csrf_token.encode()):
        raise AppError("unauthorized", "authentication failed")


def set_session_cookie(response: Response, cookie: str, settings: Settings) -> None:
    response.set_cookie(
        COOKIE_NAME,
        cookie,
        httponly=True,
        secure=not settings.insecure_cookie,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def check_origin(request: Request, settings: Settings) -> None:
    """Cross-site cookie mutations → 403 (§3). Same-origin requests may omit
    Origin; when present it must be loopback (dev) or an allowed origin.
    Falls back to Referer's scheme://host when Origin is absent."""
    origin = request.headers.get("origin")
    if origin is None:
        referer = request.headers.get("referer")
        if referer:
            match = re.match(r"^(https?://[^/]+)", referer)
            origin = match.group(1) if match else None
    if origin is None:
        return
    allowed = set(getattr(settings, "allowed_origins", []) or [])
    if settings.insecure_dev:
        allowed.update({"http://localhost", "http://127.0.0.1"})
        # dev ports vary: accept any loopback port
        if re.match(r"^http://(localhost|127\.0\.0\.1)(:\d+)?$", origin):
            return
    if origin not in allowed:
        raise AppError("forbidden", "cross-site request refused")


async def require_session(request: Request) -> OperatorSession:
    """Cookie-only session dependency. Bearer+cookie → 401; CSRF/Origin
    guards run BEFORE the idle refresh is committed (a rejected request must
    not extend the session); recovery_reset is confined to its allowlist."""
    if request.headers.get("authorization"):
        raise AppError("unauthorized", "authentication failed")
    cookie = request.cookies.get(COOKIE_NAME, "")
    if not cookie:
        raise AppError("unauthorized", "authentication failed")
    async with request.app.state.session_maker() as session:
        sess = await resolve_session(session, cookie)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            check_origin(request, request.app.state.settings)
            check_csrf(request, sess)
        check_purpose(request, sess)
        await session.commit()  # persist last_seen refresh only if all gates passed
    return sess


async def revoke_session(session: AsyncSession, sess_id: Any) -> None:
    """Single-session invalidation: revoked_at + bound unconsumed step-ups
    deleted in the same transaction (§3)."""
    row = await session.get(OperatorSession, sess_id)
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
    await session.execute(
        delete(StepUpToken).where(
            StepUpToken.session_id == sess_id, StepUpToken.consumed_at.is_(None)
        )
    )


_RECOVERY_RESET_ALLOWED = (
    "/api/auth/password-change",
    "/api/auth/step-up",
    "/api/auth/totp/setup",
    "/api/auth/totp/confirm",
    "/api/auth/totp/disable",
    "/api/auth/recovery/regen",
    "/api/auth/passkeys",  # subtree incl. /{id}
    "/api/auth/logout",
    "/api/auth/status",
)


def check_purpose(request: Request | Any, sess: OperatorSession) -> None:
    """recovery_reset sessions may only reach credential-recovery routes.
    Prefix match so templated subpaths (/api/auth/passkeys/{id}) are covered."""
    if sess.purpose != "recovery_reset":
        return
    path = request.url.path
    if path == "/api/admin" or path.startswith("/api/admin/"):
        # §5 invariant: recovery sessions NEVER reach the admin plane — pinned
        # here explicitly so a future allowlist edit cannot open it silently
        raise AppError("purpose_denied", "session purpose does not allow this route")
    if not any(
        path == allowed or path.startswith(allowed + "/") for allowed in _RECOVERY_RESET_ALLOWED
    ):
        raise AppError("purpose_denied", "session purpose does not allow this route")
