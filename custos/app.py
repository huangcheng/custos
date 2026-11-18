"""Application factory. Routers and middleware are added by later tasks."""

from __future__ import annotations

import asyncio
import os
import re
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from custos.config import Settings
from custos.db.session import get_session, make_engine, make_session_maker
from custos.errors import install_error_handlers

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
        engine = make_engine(settings)
        app.state.engine = engine
        app.state.session_maker = make_session_maker(engine)
        try:
            yield
        finally:
            await engine.dispose()

    app = FastAPI(
        title="Custos", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.settings = settings
    install_error_handlers(app)

    async def _get_session() -> AsyncIterator[AsyncSession]:
        async with app.state.session_maker() as session:
            yield session

    app.dependency_overrides[get_session] = _get_session

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
