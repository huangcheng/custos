"""Alembic environment (async engine over asyncpg — no extra driver dependency).

DSN resolution: CUSTOS_TEST_DSN, then CUSTOS_DATABASE_URL. Both may carry the
+asyncpg marker; a bare postgresql:// DSN is normalized to it.
"""

from __future__ import annotations

import asyncio
import os

from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context
from custos.db.models import Base

target_metadata = Base.metadata


def _normalize(dsn: str) -> str:
    if dsn.startswith("postgresql://"):
        return dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    return dsn


def _dsn() -> str:
    test_dsn = _normalize(os.environ.get("CUSTOS_TEST_DSN", ""))
    direct = os.environ.get("CUSTOS_DATABASE_URL", "")
    file_set = bool(os.environ.get("CUSTOS_DATABASE_URL_FILE", ""))
    if direct and file_set:
        raise RuntimeError(
            "CUSTOS_DATABASE_URL and CUSTOS_DATABASE_URL_FILE are mutually exclusive"
        )
    runtime_dsn = _normalize(direct)
    if not runtime_dsn and file_set:
        from custos.config import _secret_file

        runtime_dsn = _normalize(_secret_file(os.environ, "CUSTOS_DATABASE_URL_FILE") or "")
    if test_dsn and runtime_dsn and test_dsn != runtime_dsn:
        raise RuntimeError(
            "CUSTOS_TEST_DSN and CUSTOS_DATABASE_URL disagree; unset one before migrating"
        )
    dsn = runtime_dsn or test_dsn
    if not dsn:
        raise RuntimeError("CUSTOS_DATABASE_URL (or _FILE / CUSTOS_TEST_DSN) is required")
    return dsn


def _run(connection) -> None:  # noqa: ANN001 — alembic sync callback
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(_dsn())
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


asyncio.run(run_migrations_online())
