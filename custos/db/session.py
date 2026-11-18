"""Async engine/session factory. All DB access goes through this layer."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from custos.config import Settings


def make_engine(settings: Settings) -> AsyncEngine:
    return create_async_engine(settings.database_url, pool_pre_ping=True)


def make_session_maker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency marker; create_app overrides it with a session bound
    to app.state.session_maker. Calling it un-overridden is a wiring bug."""
    raise NotImplementedError("get_session must be overridden by create_app")
    yield  # pragma: no cover — makes this an async generator for typing
