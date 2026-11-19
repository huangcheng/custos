"""Session + CSRF contract (design §3/§5). Fake credentials only."""

import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.db.models import OperatorSession, StepUpToken
from custos.errors import AppError
from custos.operator.sessions import (
    check_csrf,
    create_session,
    resolve_session,
    revoke_all_sessions,
)

pytestmark = pytest.mark.usefixtures("pg_db")


@pytest.fixture
async def maker(pg_db: str):
    engine = create_async_engine(pg_db)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def test_cookie_shape_and_resolve(maker) -> None:
    async with maker() as s:
        row, cookie = await create_session(s)
        await s.commit()
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", cookie)
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", row.csrf_token)
    async with maker() as s:
        resolved = await resolve_session(s, cookie)
        assert resolved.id == row.id


async def test_wrong_cookie_uniform_401(maker) -> None:
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await resolve_session(s, "x" * 43)
        assert e.value.code == "unauthorized"


async def test_idle_and_absolute_expiry(maker) -> None:
    async with maker() as s:
        row, cookie = await create_session(s, idle_ttl=1, absolute_ttl=3600)
        row.last_seen_at = datetime.now(UTC) - timedelta(seconds=5)
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError):
            await resolve_session(s, cookie)
    async with maker() as s:
        row2, cookie2 = await create_session(s, idle_ttl=3600, absolute_ttl=1)
        row2.absolute_expires_at = datetime.now(UTC) - timedelta(seconds=5)
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError):
            await resolve_session(s, cookie2)


async def test_revoked_rejected(maker) -> None:
    async with maker() as s:
        row, cookie = await create_session(s)
        row.revoked_at = datetime.now(UTC)
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError):
            await resolve_session(s, cookie)


async def test_recovery_reset_fixed_window(maker) -> None:
    async with maker() as s:
        row, cookie = await create_session(
            s, purpose="recovery_reset", idle_ttl=0, absolute_ttl=1800
        )
        first_seen = row.last_seen_at
        await s.commit()
    async with maker() as s:
        resolved = await resolve_session(s, cookie)
        assert resolved.last_seen_at == first_seen  # never refreshed
        assert resolved.idle_ttl_seconds == 0


async def test_revoke_all_keeps_rows_deletes_stepups(maker) -> None:
    async with maker() as s:
        row, cookie = await create_session(s)
        s.add(StepUpToken(session_id=row.id, nonce_hash=b"n" * 32, kind="single",
                          expires_at=datetime.now(UTC) + timedelta(minutes=5)))
        await s.commit()
        sid = row.id
    async with maker() as s:
        await revoke_all_sessions(s)
        await s.commit()
    async with maker() as s:
        assert await s.get(OperatorSession, sid) is not None  # row survives
        tokens = (
            (await s.execute(select(StepUpToken).where(StepUpToken.session_id == sid)))
            .scalars().all()
        )
        assert tokens == []


async def test_csrf_constant_time_check(maker) -> None:
    async with maker() as s:
        row, cookie = await create_session(s)
        await s.commit()

    class FakeRequest:
        def __init__(self, token: str | None):
            self.headers = {"x-csrf-token": token} if token else {}

    check_csrf(FakeRequest(row.csrf_token), row)  # ok
    with pytest.raises(AppError):
        check_csrf(FakeRequest("wrong"), row)
    with pytest.raises(AppError):
        check_csrf(FakeRequest(None), row)

@pytest.fixture
def http_stack(pg_db: str):
    from contextlib import asynccontextmanager

    from custos.app import create_app
    from custos.config import load_settings
    from tests.test_config import env

    @asynccontextmanager
    async def build():
        settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1",
                                     CUSTOS_INSECURE_DEV="1"))
        app = create_app(settings)
        engine = create_async_engine(pg_db)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with app.router.lifespan_context(app):
            async with maker() as s:
                row, cookie = await create_session(s)
                await s.commit()
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test",
                cookies={"custos_session": cookie},
            )
            async with client:
                try:
                    yield client, maker, row, cookie, app
                finally:
                    await engine.dispose()

    return build


async def test_status_returns_csrf_with_live_cookie(http_stack) -> None:
    async with http_stack() as (client, maker, row, cookie, app):
        r = await client.get("/api/auth/status")
        assert r.status_code == 200
        assert r.json()["csrf_token"] == row.csrf_token


async def test_logout_revokes_and_clears(http_stack) -> None:
    async with http_stack() as (client, maker, row, cookie, app):
        r = await client.post("/api/auth/logout",
                              headers={"x-csrf-token": row.csrf_token})
        assert r.status_code == 200
        async with maker() as s:
            refreshed = await s.get(OperatorSession, row.id)
            assert refreshed.revoked_at is not None
        r2 = await client.get("/api/auth/status")
        assert "csrf_token" not in r2.json()


async def test_cookie_plus_bearer_401(http_stack) -> None:
    async with http_stack() as (client, maker, row, cookie, app):
        r = await client.post("/api/auth/logout", headers={
            "x-csrf-token": row.csrf_token,
            "Authorization": "Bearer cu-000000000000." + "A" * 43,
        })
        assert r.status_code == 401


async def test_cross_site_origin_403(http_stack) -> None:
    async with http_stack() as (client, maker, row, cookie, app):
        r = await client.post("/api/auth/logout", headers={
            "x-csrf-token": row.csrf_token, "Origin": "https://evil.example",
        })
        assert r.status_code == 403


async def test_mutation_without_csrf_401(http_stack) -> None:
    async with http_stack() as (client, maker, row, cookie, app):
        r = await client.post("/api/auth/logout")
        assert r.status_code == 401


async def test_recovery_reset_blocked_outside_allowlist(pg_db: str, http_stack) -> None:
    from custos.operator.sessions import create_session as _cs
    from custos.operator.sessions import require_session

    async with http_stack() as (client, maker, row, cookie, app):
        # register a session-only route outside the recovery_reset allowlist
        @app.get("/api/admin-probe")
        async def probe(sess=Depends(require_session)):
            return {"ok": True}

        async with maker() as s:
            rr, rr_cookie = await _cs(s, purpose="recovery_reset", idle_ttl=0,
                                      absolute_ttl=1800)
            await s.commit()
        c2 = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
            cookies={"custos_session": rr_cookie},
        )
        async with c2:
            r = await c2.get("/api/admin-probe")
            assert r.status_code == 403
            assert r.json()["code"] == "purpose_denied"
        # a full session passes the same route
        c3 = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
            cookies={"custos_session": cookie},
        )
        async with c3:
            assert (await c3.get("/api/admin-probe")).status_code == 200


async def test_rejected_mutation_does_not_extend_idle(pg_db: str, http_stack) -> None:
    async with http_stack() as (client, maker, row, cookie, app):
        old = row.last_seen_at
        await client.post("/api/auth/logout")  # no CSRF -> 401
        async with maker() as s:
            fresh = await s.get(OperatorSession, row.id)
            assert fresh.last_seen_at == old


async def test_cross_site_referer_403(http_stack) -> None:
    async with http_stack() as (client, maker, row, cookie, app):
        r = await client.post("/api/auth/logout", headers={
            "x-csrf-token": row.csrf_token, "Referer": "https://evil.example/path",
        })
        assert r.status_code == 403


async def test_logout_invalidates_bound_step_up_tokens(http_stack) -> None:
    async with http_stack() as (client, maker, row, cookie, app):
        async with maker() as s:
            s.add(StepUpToken(session_id=row.id, nonce_hash=b"q" * 32, kind="rekey_run",
                              expires_at=datetime.now(UTC) + timedelta(minutes=30)))
            await s.commit()
        r = await client.post("/api/auth/logout", headers={"x-csrf-token": row.csrf_token})
        assert r.status_code == 200
        async with maker() as s:
            rows = (await s.execute(select(StepUpToken))).scalars().all()
            assert not [t for t in rows if t.consumed_at is None]


async def test_recovery_reset_factory_enforces_fixed_window(maker) -> None:
    async with maker() as s:
        row, cookie = await create_session(s, purpose="recovery_reset")
        await s.commit()
        assert row.idle_ttl_seconds == 0
        assert row.absolute_expires_at <= datetime.now(UTC) + timedelta(seconds=1801)


async def test_recovery_reset_passkey_subtree_allowed(pg_db, http_stack) -> None:
    from custos.operator.sessions import check_purpose

    async with http_stack() as (client, maker, row, cookie, app):
        async with maker() as s:
            rr, _ = await create_session(s, purpose="recovery_reset")
            await s.commit()
        from types import SimpleNamespace
        # DELETE /api/auth/passkeys/{id} must stay within the allowlist
        req = SimpleNamespace(url=SimpleNamespace(path="/api/auth/passkeys/abc-123"))
        check_purpose(req, rr)  # must not raise
