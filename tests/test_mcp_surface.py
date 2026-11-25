"""Remote MCP surface contract (design §7): per-request bearer, engine parity."""

from contextlib import AsyncExitStack, asynccontextmanager

import anyio
import httpx2
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.app import create_app
from custos.config import load_settings
from custos.db.models import AgentKey, AuditRow
from custos.keys import mint_agent_key
from tests.test_config import env

pytestmark = pytest.mark.usefixtures("pg_db")


@pytest.fixture
def stack_factory(pg_db: str):
    """Builds app+keys; the TEST BODY owns the lifespan (pytest-asyncio runs
    fixture setup/teardown in different tasks — anyio cancel scopes require
    one task for enter+exit)."""
    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))

    async def mint(maker) -> tuple[str, str]:
        token, draft = mint_agent_key(settings.pepper_raw)
        async with maker() as s:
            s.add(AgentKey(key_id=draft.key_id, digest=draft.digest, label="cu-test"))
            await s.commit()
        return token, draft.key_id

    @asynccontextmanager
    async def build():
        app = create_app(settings)
        engine = create_async_engine(pg_db)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        rw, rw_id = await mint(maker)
        ro, _ = await mint(maker)
        async with app.router.lifespan_context(app):
            try:
                yield app, maker, {"rw": rw, "rw_id": rw_id, "ro": ro}
            finally:
                await engine.dispose()

    return build


def _http(app, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="http://testserver",
        headers=headers,
    )


@asynccontextmanager
async def _mcp_client(app, token: str | None):
    """One task owns the whole transport lifecycle (anyio cancel scopes)."""
    from mcp.client.streamable_http import streamable_http_client

    from mcp import Client

    class _ASGITransportCM:
        async def __aenter__(self):
            # own exit stack: __aexit__ runs in the same task as __aenter__
            self._stack = AsyncExitStack()
            await self._stack.__aenter__()
            http = await self._stack.enter_async_context(_http(app, token))
            return await self._stack.enter_async_context(
                streamable_http_client("http://testserver/mcp", http_client=http)
            )

        async def __aexit__(self, *exc):
            return await self._stack.__aexit__(*exc)

    async with Client(_ASGITransportCM()) as client:
        yield client


async def test_mcp_put_get_roundtrip(stack_factory) -> None:
    async with stack_factory() as (app, maker, tokens):
        async with _mcp_client(app, tokens["rw"]) as client:
            tools = await client.list_tools()
            names = {t.name for t in tools.tools}
            assert {"custos_list_items", "custos_get_item", "custos_search",
                    "custos_put_item", "custos_patch_item", "custos_delete_item",
                    "custos_env"} <= names
            r = await client.call_tool("custos_put_item", {
                "name": "mcp-item", "notes": "", "fields": [
                    {"name": "K", "secret": True, "value": "cu-test.mcp"},
                ],
            })
            assert not r.is_error
            g = await client.call_tool("custos_get_item", {"name": "mcp-item"})
            assert "cu-test.mcp" in str(g.content)
        async with maker() as s:
            rows = (
                (await s.execute(select(AuditRow).where(AuditRow.item_name == "mcp-item")))
                .scalars().all()
            )
            assert "create" in [r.action for r in rows]  # upsert-create audited create
        async with _mcp_client(app, tokens["rw"]) as client:
            await client.call_tool("custos_put_item", {
                "name": "mcp-item", "notes": "x", "fields": [
                    {"name": "K", "secret": True, "value": "cu-test.mcp2"},
                ],
            })
        async with maker() as s:
            rows = (
                (await s.execute(select(AuditRow).where(AuditRow.item_name == "mcp-item")))
                .scalars().all()
            )
            assert "put" in [r.action for r in rows]


async def test_mcp_unauthenticated_401(stack_factory) -> None:
    async with stack_factory() as (app, maker, tokens):
        async with _http(app, None) as http:
            resp = await http.post("/mcp", json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
            })
        assert resp.status_code == 401


async def test_mcp_deleted_key_401_next_request(stack_factory) -> None:
    async with stack_factory() as (app, maker, tokens), _mcp_client(app, tokens["rw"]) as client:
        await client.call_tool("custos_list_items", {})
        async with maker() as s:
            key = (
                await s.execute(select(AgentKey).where(AgentKey.key_id == tokens["rw_id"]))
            ).scalar_one()
            # hard-delete revocation (rev 38): the key is unknown afterwards
            await s.delete(key)
            await s.commit()
        from mcp.shared.exceptions import MCPError

        with pytest.raises((MCPError, httpx2.HTTPStatusError, anyio.ClosedResourceError)):
            await client.call_tool("custos_list_items", {})


async def test_mcp_denial_audited(stack_factory) -> None:
    async with stack_factory() as (app, maker, tokens), _mcp_client(app, tokens["rw"]) as client:
        from mcp.shared.exceptions import MCPError

        with pytest.raises(MCPError):
            await client.call_tool("custos_get_item", {"name": "mcp-never-was"})
    async with maker() as s:
        rows = (
            (await s.execute(select(AuditRow).where(
                AuditRow.item_name == "mcp-never-was", AuditRow.ok.is_(False))))
            .scalars().all()
        )
        assert rows and rows[0].detail.get("reason") == "not_found"


async def test_mcp_concurrency_slot_cap(stack_factory) -> None:
    async with stack_factory() as (app, maker, tokens):
        # exhaust the key's 8 slots externally, then a tool request must 429
        key_id = tokens["rw_id"]
        for _ in range(8):
            app.state.rate_limiter.acquire_agent_slot(key_id)
        async with _http(app, tokens["rw"]) as http:
            resp = await http.post("/mcp", json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
            })
        assert resp.status_code == 429
        for _ in range(8):
            app.state.rate_limiter.release_agent_slot(key_id)


async def test_mcp_sse_get_exempt_from_slots(stack_factory) -> None:
    async with stack_factory() as (app, maker, tokens):
        key_id = tokens["rw_id"]
        for _ in range(8):
            app.state.rate_limiter.acquire_agent_slot(key_id)
        # informational GET stream must NOT be slot-gated (§7)
        async with _http(app, tokens["rw"]) as http:
            resp = await http.get("/mcp", headers={"accept": "text/event-stream"})
        assert resp.status_code != 429
        for _ in range(8):
            app.state.rate_limiter.release_agent_slot(key_id)


async def test_mcp_unverified_prefix_does_not_burn_bucket(stack_factory) -> None:
    async with stack_factory() as (app, maker, tokens):
        key_id = tokens["rw_id"]
        junk = f"cu-{key_id}." + "B" * 43
        async with _http(app, junk) as http:
            for _ in range(3):
                resp = await http.post("/mcp", json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
                })
                assert resp.status_code == 401
        # victim's request bucket untouched by unverified prefixes
        events = app.state.rate_limiter._requests.get(key_id)
        assert not events


async def test_mcp_small_page_and_tool_descriptions(stack_factory) -> None:
    """rev 40: an agent asking for a small page must not be rejected, and the
    tools advertise what they do (a gateway shows these descriptions)."""
    async with stack_factory() as (app, maker, tokens), _mcp_client(app, tokens["rw"]) as client:
        r = await client.call_tool("custos_list_items", {"limit": 5})
        assert not r.is_error
        listed = await client.list_tools()
        by_name = {t.name: t for t in listed.tools}
        assert by_name["custos_list_items"].description
        assert "1..100" in by_name["custos_list_items"].description
        assert by_name["custos_get_item"].description
