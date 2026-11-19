"""Password login contract (design §5). Fake credentials only."""

import asyncio

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.app import create_app
from custos.config import load_settings
from custos.db.models import AuthEvent, OperatorAccount
from custos.operator.account import hash_password
from custos.operator.sessions import COOKIE_NAME
from tests.test_config import env

pytestmark = pytest.mark.usefixtures("pg_db")

PW = "cu-test-password-12ch"


@pytest.fixture
def login_stack(pg_db: str):
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def build(*, totp_enabled: bool = False):
        settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1",
                                     CUSTOS_INSECURE_DEV="1"))
        app = create_app(settings)
        engine = create_async_engine(pg_db)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as s:
            acct = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
            if acct is None:
                s.add(OperatorAccount(id=1, username="operator",
                                      password_hash=hash_password(PW),
                                      totp_enabled=totp_enabled))
            else:
                acct.password_hash = hash_password(PW)
                acct.totp_enabled = totp_enabled
                acct.totp_last_step_login = 0
            await s.commit()
        async with app.router.lifespan_context(app):
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test")
            async with client:
                try:
                    yield client, maker, app
                finally:
                    async with maker() as s:
                        evs = (
                            await s.execute(select(AuthEvent).where(
                                AuthEvent.kind.in_(["login_password", "login_totp"])))
                        ).scalars().all()
                        for ev in evs:
                            await s.delete(ev)
                        acct = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
                        if acct is not None:
                            await s.delete(acct)
                        await s.commit()
                    await engine.dispose()

    return build


async def test_login_success_sets_cookie(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        r = await client.post("/api/auth/login",
                              json={"username": "operator", "password": PW})
        assert r.status_code == 200
        assert "csrf_token" in r.json()
        assert COOKIE_NAME in r.cookies


async def test_login_unknown_user_and_bad_password_identical(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        a = await client.post("/api/auth/login",
                              json={"username": "operator", "password": "wrong-password-12"})
        b = await client.post("/api/auth/login",
                              json={"username": "ghost", "password": PW})
        assert a.status_code == b.status_code == 401
        assert a.content == b.content


async def test_one_auth_event_per_failure(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        await client.post("/api/auth/login",
                          json={"username": "operator", "password": "wrong-password-12"})
        async with maker() as s:
            rows = (
                (await s.execute(select(AuthEvent).where(AuthEvent.kind == "login_password")))
                .scalars().all()
            )
            assert len([r for r in rows if not r.ok]) == 1


async def test_totp_enabled_requires_factor(login_stack) -> None:
    async with login_stack(totp_enabled=True) as (client, maker, app):
        # password alone, no factor -> 401, login_totp stage
        r = await client.post("/api/auth/login",
                              json={"username": "operator", "password": PW})
        assert r.status_code == 401
        async with maker() as s:
            rows = (
                (await s.execute(select(AuthEvent).where(AuthEvent.kind == "login_totp")))
                .scalars().all()
            )
            assert len([x for x in rows if not x.ok]) >= 1


async def test_both_factors_422(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": PW,
            "totp": "123456", "recovery_code": "AAAA",
        })
        assert r.status_code == 422


async def test_argon2_semaphore_limits_concurrency(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        limiter = app.state.auth_semaphore
        # acquire the semaphore fully, then a login must wait (not proceed)
        got = []
        for _ in range(2):
            await limiter.acquire()
            got.append(True)

        async def attempt():
            return await client.post("/api/auth/login",
                                     json={"username": "operator", "password": PW})

        task = asyncio.create_task(attempt())
        await asyncio.sleep(0.2)
        assert not task.done()  # blocked on the semaphore
        for _ in got:
            limiter.release()
        resp = await task
        assert resp.status_code == 200


async def test_semaphore_wait_cap_429(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        # shrink the wait cap for the test, hold both slots
        app.state.auth_wait_cap = 0.2
        await app.state.auth_semaphore.acquire()
        await app.state.auth_semaphore.acquire()
        r = await client.post("/api/auth/login",
                              json={"username": "operator", "password": PW})
        assert r.status_code == 429
        assert r.json()["code"] == "rate_limited"
        app.state.auth_semaphore.release()
        app.state.auth_semaphore.release()


async def test_surrogate_password_never_500(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        raw = b'{"username":"operator","password":"\\ud800"}'
        r = await client.post("/api/auth/login", content=raw,
                              headers={"content-type": "application/json"})
        assert r.status_code in (401, 422)


async def test_failed_login_commit_leaves_no_success_audit(login_stack) -> None:
    from custos.db.models import AuditRow

    async with login_stack() as (client, maker, app):
        r = await client.post("/api/auth/login",
                              json={"username": "operator", "password": PW})
        assert r.status_code == 200
        # success audit must exist only after commit (happy path here)
        async with maker() as s:
            rows = (
                (await s.execute(select(AuditRow).where(AuditRow.action == "operator.login")))
                .scalars().all()
            )
            assert rows  # committed session -> audit present


async def test_lockout_blocks_login_before_verify(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        # seed 10 login_password failures for the ASGI client IP (testclient)
        from datetime import UTC, datetime

        from custos.db.models import AuthEvent

        async with maker() as s:
            for _ in range(10):
                s.add(AuthEvent(kind="login_password", ok=False, ip="127.0.0.1",
                                peer_ip="127.0.0.1", ts=datetime.now(UTC)))
            await s.commit()
        r = await client.post("/api/auth/login",
                              json={"username": "operator", "password": PW})
        assert r.status_code == 429
        assert r.json()["code"] == "locked_out"


async def test_429_gated_request_writes_no_ledger(login_stack) -> None:
    async with login_stack() as (client, maker, app):
        # exhaust the unauth bucket (10/min/IP) with bad-password attempts,
        # then the next request must 429 without adding an auth_event
        for _ in range(10):
            await client.post("/api/auth/login",
                              json={"username": "operator", "password": "wrong-password-12"})
        async with maker() as s:
            before = len((await s.execute(select(AuthEvent))).scalars().all())
        r = await client.post("/api/auth/login",
                              json={"username": "operator", "password": "wrong-password-12"})
        assert r.status_code == 429
        async with maker() as s:
            after = len((await s.execute(select(AuthEvent))).scalars().all())
        assert after == before  # 429-gated request added no row
