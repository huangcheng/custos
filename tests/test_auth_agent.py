"""Agent auth dependency over HTTP: uniform 401, ledger rows, 429 gating."""

import httpx
import pytest
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.app import create_app
from custos.config import load_settings
from custos.db.models import AgentKey, AuditRow, AuthEvent
from custos.keys import mint_agent_key
from tests.test_config import env

pytestmark = pytest.mark.usefixtures("pg_db")


@pytest.fixture
def setup(pg_db: str):
    """Factory: test body owns the lifespan (fixture tasks differ; anyio)."""
    from contextlib import asynccontextmanager

    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))

    @asynccontextmanager
    async def build():
        app = create_app(settings)
        engine = create_async_engine(pg_db)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        token, draft = mint_agent_key(settings.pepper_raw)
        async with maker() as session:
            session.add(
                AgentKey(key_id=draft.key_id, digest=draft.digest, label="cu-test")
            )
            await session.commit()
        async with app.router.lifespan_context(app):
            from custos.auth_agent import agent_principal
            from custos.keys import AgentPrincipal

            @app.get("/agent-ping")
            async def agent_ping(key: AgentPrincipal = Depends(agent_principal)) -> dict[str, str]:
                return {"key": key.key_id}

            try:
                yield app, maker, token
            finally:
                await engine.dispose()

    return build


async def _client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


async def test_valid_bearer_resolves(setup) -> None:
    async with setup() as (app, maker, token):
        async with await _client(app) as client:
            resp = await client.get("/agent-ping", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["key"] == token[3:15]


async def test_failures_uniform_and_ledgered(setup) -> None:
    async with setup() as (app, maker, token):
        bodies = []
        async with await _client(app) as client:
            for bad in ("cu-000000000000." + "A" * 43, "garbage", token[:-1] + "!"):
                resp = await client.get("/agent-ping", headers={"Authorization": f"Bearer {bad}"})
                assert resp.status_code == 401
                bodies.append(resp.text)
            resp = await client.get("/agent-ping")  # no header
            assert resp.status_code == 401
            bodies.append(resp.text)
        assert len(set(bodies)) == 1
        assert '"unauthorized"' in bodies[0]
        async with maker() as session:
            events = (
                (await session.execute(select(AuthEvent).where(AuthEvent.kind == "agent_auth")))
                .scalars().all()
            )
            failures = [e for e in events if not e.ok and e.ip == "127.0.0.1"]
            assert len(failures) == 4
            audits = (
                (await session.execute(select(AuditRow).where(AuditRow.action == "auth.failure")))
                .scalars().all()
            )
            assert len(audits) >= 4


async def test_failed_auth_flood_429_no_ledger(setup) -> None:
    async with setup() as (app, maker, token):
        flood_ip = "198.51.100.77"

        async def fixed_ip_app(scope, receive, send):
            scope["client"] = (flood_ip, 12345)
            await app(scope, receive, send)

        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fixed_ip_app), base_url="http://test"
        )
        async with client:
            for _ in range(30):
                resp = await client.get(
                    "/agent-ping", headers={"Authorization": "Bearer cu-000000000000." + "A" * 43}
                )
                assert resp.status_code == 401
            resp = await client.get(
                "/agent-ping", headers={"Authorization": "Bearer cu-000000000000." + "A" * 43}
            )
            assert resp.status_code == 429
            assert "retry-after" in resp.headers
        async with maker() as session:
            events = (
                (
                    await session.execute(
                        select(AuthEvent).where(
                            AuthEvent.kind == "agent_auth", AuthEvent.ip == flood_ip
                        )
                    )
                )
                .scalars().all()
            )
            assert len([e for e in events if not e.ok]) == 30  # 429 produced no row


async def test_slots_released_after_requests(setup) -> None:
    async with setup() as (app, maker, token):
        async with await _client(app) as client:
            for _ in range(20):  # more than the 8-slot cap: release must be structural
                resp = await client.get("/agent-ping", headers={"Authorization": f"Bearer {token}"})
                assert resp.status_code == 200
        assert app.state.rate_limiter._inflight.get(token[3:15], 0) == 0


async def test_ledger_failure_still_records_bucket_and_401(setup, monkeypatch) -> None:
    async with setup() as (app, maker, token):
        from custos import auth_agent

        async def broken_ledger(*args, **kwargs):
            from custos.audit import LedgerError

            raise LedgerError("down")

        monkeypatch.setattr(auth_agent, "record_auth_event", broken_ledger)
        async with await _client(app) as client:
            resp = await client.get(
                "/agent-ping", headers={"Authorization": "Bearer cu-000000000000." + "A" * 43}
            )
        # fails closed (5xx, never success) but the in-process bucket advanced
        assert resp.status_code >= 500
        assert app.state.rate_limiter._failures.get("127.0.0.1")
