"""Application factory. Routers and middleware are added by later tasks."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from custos.audit import FailureCounter, LedgerBudget
from custos.config import Settings
from custos.crypto import Vault, parse_keyring
from custos.db.session import get_session, make_engine, make_session_maker
from custos.errors import install_error_handlers
from custos.ratelimit import RateLimiter

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _head_revisions() -> set[str]:
    """Heads = revisions minus parents, parsed from the migration tree."""
    versions = _REPO_ROOT / "alembic" / "versions"
    if not versions.is_dir():
        raise RuntimeError("alembic versions directory missing; cannot verify schema")
    revisions: set[str] = set()
    parents: set[str] = set()
    for path in versions.glob("*.py"):
        text_ = path.read_text(encoding="utf-8")
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text_, re.M)
        if rev:
            revisions.add(rev.group(1))
        down = re.search(r"^down_revision(?::[^=]+)?\s*=\s*(.+?)(?=^\w|\Z)", text_, re.M | re.S)
        if down:
            parents.update(re.findall(r"['\"]([^'\"]+)['\"]", down.group(1)))
    return revisions - parents


async def _assert_key_versions(engine: AsyncEngine, settings: Settings) -> None:
    """§4: referenced key_version scan (metadata only, no decryption).
    Missing versions refuse startup unless the explicit degraded flag."""
    available = set(parse_keyring(settings.keyring_raw))
    referenced: set[int] = set()
    from sqlalchemy import select

    from custos.db.models import Field, FieldHistory, OperatorAccount

    async with engine.connect() as conn:
        for column in (Field.key_version, FieldHistory.key_version,
                       OperatorAccount.totp_key_version):
            rows = await conn.execute(
                select(column).distinct().where(column.is_not(None))
            )
            referenced.update(r[0] for r in rows)
    missing = referenced - available
    if missing:
        if not settings.allow_missing_key_version:
            raise RuntimeError(
                f"key version(s) {sorted(missing)} referenced but absent from the keyring; "
                "restore them or set CUSTOS_ALLOW_MISSING_KEY_VERSION=1 for degraded mode"
            )
        logging.getLogger("custos").warning(
            "degraded mode: key version(s) %s missing; affected reads/writes fail closed",
            sorted(missing),
        )


async def _assert_schema_head(engine: AsyncEngine) -> None:
    try:
        async with engine.connect() as conn:
            rows = (
                await conn.execute(text("SELECT version_num FROM alembic_version"))
            ).scalars().all()
    except ProgrammingError as exc:
        raise RuntimeError("schema version table missing; run migrations") from exc
    heads = _head_revisions()
    if not rows or set(rows) != heads:
        raise RuntimeError(
            f"schema version mismatch: database at {rows!r}, code expects heads {sorted(heads)!r}"
        )


async def _run_migrations(settings: Settings) -> None:
    # Alembic's env.py runs asyncio.run internally; invoke it out-of-process so
    # the app's own event loop is untouched. DSN travels via env, never argv.
    # Spawn alembic directly with the running interpreter: the killed pid is
    # the migration itself (no uv wrapper grandchild), and production images
    # need no uv. DSN travels via env, never argv; stderr passes through.
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "alembic", "upgrade", "head",
        cwd=str(_REPO_ROOT),
        env={
            **os.environ,
            "CUSTOS_DATABASE_URL": settings.database_url,
            "CUSTOS_TEST_DSN": "",  # a stale test DSN must never win in the child
            "CUSTOS_DATABASE_URL_FILE": "",  # DSN already resolved; both-set aborts env.py
        },
        stdout=asyncio.subprocess.DEVNULL,
        stderr=None,
    )
    try:
        await asyncio.wait_for(proc.wait(), timeout=120)
    except TimeoutError:
        proc.kill()
        await proc.wait()  # reap the killed child
        raise RuntimeError("alembic upgrade head timed out after 120s") from None
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise
    if proc.returncode != 0:
        raise RuntimeError("alembic upgrade head failed (see server stderr)")


class _NoStoreMiddleware:
    """Cache-Control: no-store + Vary on /api/* and /mcp (design §3)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and (
            scope["path"].startswith("/api/")
            or scope["path"] == "/mcp"
            or scope["path"].startswith("/mcp/")
        ):
            async def _send(message: Any) -> None:
                if message["type"] == "http.response.start":
                    headers = message.setdefault("headers", [])
                    headers.append((b"cache-control", b"no-store"))
                    headers.append((b"vary", b"Cookie, Authorization"))
                await send(message)

            await self.app(scope, receive, _send)
        else:
            await self.app(scope, receive, send)


def create_app(settings: Settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.skip_migrate:
            engine = make_engine(settings)
            try:
                await _assert_schema_head(engine)
            finally:
                await engine.dispose()
        else:
            await _run_migrations(settings)
        from custos.telemetry import instrument_engine

        engine = make_engine(settings)
        try:
            await _assert_key_versions(engine, settings)
        except Exception:
            await engine.dispose()
            raise
        instrument_engine(engine.sync_engine)
        app.state.engine = engine
        app.state.session_maker = make_session_maker(engine)
        app.state.rate_limiter = RateLimiter()
        app.state.ledger_budget = LedgerBudget()
        app.state.failure_counter = FailureCounter()
        # global argon2 concurrency cap (§5): 2 concurrent password verifications
        app.state.auth_semaphore = asyncio.Semaphore(2)
        from concurrent.futures import ThreadPoolExecutor

        app.state.auth_executor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="argon2"
        )
        from custos.operator.login import default_factor_hook

        app.state.login_factor_hook = default_factor_hook
        # long-lived siteverify client (one TLS pool, not per-login handshake)
        import httpx as _httpx

        app.state.turnstile_client = (
            _httpx.AsyncClient(timeout=5.0, trust_env=False) if settings.turnstile_secret else None
        )
        app.state.vault = Vault(parse_keyring(settings.keyring_raw))
        # provision the setup code at first startup (§5), only while no
        # account exists — never recreate a consumed code
        from sqlalchemy import select as _select

        from custos.db.models import OperatorAccount as _Acct
        from custos.operator.account import ensure_setup_code as _ensure

        async with app.state.session_maker() as _s:
            _acct = (await _s.execute(_select(_Acct))).scalar_one_or_none()
        app.state.setup_code = None
        if _acct is None:
            try:
                app.state.setup_code = _ensure(settings)
            except OSError as exc:
                # setup routes surface the error; the agent plane still starts
                logging.getLogger("custos").warning(
                    "setup-code provisioning deferred; data dir unusable: %s", exc
                )
        from custos.mcp_surface import mount_mcp

        mcp_sub, mcp_gate = mount_mcp(app)
        app.state.mcp_sub = mcp_gate
        try:
            # the MCP session manager runs inside the sub-app's lifespan
            async with mcp_sub.router.lifespan_context(mcp_sub):
                yield
        finally:
            app.state.auth_executor.shutdown(wait=False)
            if app.state.turnstile_client is not None:
                await app.state.turnstile_client.aclose()
            await engine.dispose()

    app = FastAPI(
        title="Custos", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.settings = settings
    install_error_handlers(app)
    from custos.telemetry import install_telemetry, instrument_fastapi

    install_telemetry()
    instrument_fastapi(app)  # before any add_middleware / first request

    from custos.admin.auth import router as admin_auth_router
    from custos.admin.routes_items import router as admin_items_router
    from custos.admin.routes_keys import router as admin_keys_router
    from custos.admin.routes_maintenance import router as admin_maint_router
    from custos.operator.routes_auth import router as auth_router
    from custos.routes_agent import router as agent_router

    app.include_router(agent_router)
    app.include_router(auth_router)
    app.include_router(admin_auth_router)
    app.include_router(admin_items_router)
    app.include_router(admin_keys_router)
    app.include_router(admin_maint_router)

    class _MCPDispatch:
        """Route /mcp to the Streamable HTTP sub-app (auth middleware intact)."""

        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            path = scope.get("path", "")
            if scope["type"] in ("http", "websocket") and (
                path == "/mcp" or path.startswith("/mcp/")
            ):
                sub = getattr(scope["app"].state, "mcp_sub", None)  # gate-wrapped
                if sub is not None:
                    await sub(scope, receive, send)
                    return
            await self.app(scope, receive, send)

    app.add_middleware(_MCPDispatch)

    # Pure ASGI middleware: BaseHTTPMiddleware breaks SSE disconnect
    # propagation for the /mcp mount (Task 8).
    app.add_middleware(_NoStoreMiddleware)

    async def _get_session() -> AsyncIterator[AsyncSession]:
        async with app.state.session_maker() as session:
            yield session

    app.dependency_overrides[get_session] = _get_session

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    from custos.console import mount_console

    mount_console(app, settings)  # AFTER the routers: the fallback shadows nothing

    return app
