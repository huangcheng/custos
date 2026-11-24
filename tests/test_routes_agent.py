"""Agent-plane HTTP contract (design §6) against real postgres."""

import httpx
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
def stack(pg_db: str):
    """Factory: the TEST BODY owns the app lifespan (pytest-asyncio runs
    fixture setup/teardown in different tasks; anyio scopes need one task)."""
    from contextlib import asynccontextmanager

    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))

    @asynccontextmanager
    async def build():
        app = create_app(settings)
        engine = create_async_engine(pg_db)
        maker = async_sessionmaker(engine, expire_on_commit=False)

        async def mint() -> tuple[str, str]:
            token, draft = mint_agent_key(settings.pepper_raw)
            async with maker() as s:
                s.add(AgentKey(key_id=draft.key_id, digest=draft.digest, label="cu-test"))
                await s.commit()
            return token, draft.key_id

        rw, rw_id = await mint()
        second, second_id = await mint()
        async with app.router.lifespan_context(app):
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            )
            async with client:
                try:
                    yield client, maker, {"rw": rw, "ro": second, "scoped": second,
                                          "rw_id": rw_id, "second_id": second_id}
                finally:
                    await engine.dispose()

    return build


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def item_body(name: str | None = None, **kw) -> dict:
    b = {"notes": kw.get("notes", ""), "fields": kw.get("fields", [])}
    if name:
        b["name"] = name
    return b


async def test_create_get_roundtrip(stack) -> None:
    async with stack() as (client, maker, tokens):
        resp = await client.post("/api/items", headers=auth(tokens["rw"]), json=item_body(
            "http-aliyun", notes="n", fields=[
                {"name": "KEY", "secret": True, "value": "sk-fake-http"},
                {"name": "URL", "secret": False, "value": "https://example.invalid"},
            ]))
        assert resp.status_code == 201
        assert resp.json()["created"] is True
        assert resp.headers["etag"] == '"1"'
        got = await client.get("/api/items/http-aliyun", headers=auth(tokens["rw"]))
        assert got.status_code == 200
        values = {f["name"]: f["value"] for f in got.json()["fields"]}
        assert values["KEY"] == "sk-fake-http"


async def test_etag_if_match_flow(stack) -> None:
    async with stack() as (client, maker, tokens):
        r = await client.post("/api/items", headers=auth(tokens["rw"]), json=item_body("etag-http"))
        etag = r.headers["etag"]
        ok = await client.put("/api/items/etag-http",
                              headers={**auth(tokens["rw"]), "If-Match": etag}, json=item_body())
        assert ok.status_code == 200 and ok.headers["etag"] == '"2"'
        stale = await client.put("/api/items/etag-http",
                                 headers={**auth(tokens["rw"]), "If-Match": etag}, json=item_body())
        assert stale.status_code == 409


async def test_upsert_flow(stack) -> None:
    async with stack() as (client, maker, tokens):
        r = await client.put("/api/items/up-http?upsert=1", headers=auth(tokens["rw"]),
                             json=item_body())
        assert r.status_code == 201 and r.json()["created"] is True
        r2 = await client.put("/api/items/up-http?upsert=1", headers=auth(tokens["rw"]),
                              json=item_body(notes="x"))
        assert r2.status_code == 200 and r2.json()["created"] is False
        # plain PUT on missing stays 404
        r3 = await client.put("/api/items/up-missing", headers=auth(tokens["rw"]), json=item_body())
        assert r3.status_code == 404


async def test_delete_204_and_hidden(stack) -> None:
    async with stack() as (client, maker, tokens):
        await client.post("/api/items", headers=auth(tokens["rw"]), json=item_body("del-http"))
        d = await client.delete("/api/items/del-http", headers=auth(tokens["rw"]))
        assert d.status_code == 204 and d.content == b""
        g = await client.get("/api/items/del-http", headers=auth(tokens["rw"]))
        assert g.status_code == 404
        listing = await client.get("/api/items", headers=auth(tokens["rw"]))
        assert "del-http" not in [i["name"] for i in listing.json()["items"]]


async def test_list_metadata_only_truncated_notes(stack) -> None:
    async with stack() as (client, maker, tokens):
        await client.post("/api/items", headers=auth(tokens["rw"]), json=item_body(
            "list-http", notes="x" * 600,
            fields=[{"name": "S", "secret": True, "value": "sk-list-secret"}]))
        resp = await client.get("/api/items", headers=auth(tokens["rw"]))
        assert resp.status_code == 200
        row = next(i for i in resp.json()["items"] if i["name"] == "list-http")
        assert len(row["notes"]) == 256
        assert row["fields"] == [{"name": "S", "secret": True}]
        assert "sk-list-secret" not in resp.text


async def test_search_never_values_and_audit_count_only(stack) -> None:
    async with stack() as (client, maker, tokens):
        await client.post("/api/items", headers=auth(tokens["rw"]), json=item_body(
            "search-http", notes="findable-note",
            fields=[{"name": "FINDME", "secret": False, "value": "sk-search-secret"}]))
        r = await client.get("/api/search?q=findable", headers=auth(tokens["rw"]))
        assert r.status_code == 200
        assert "search-http" in [i["name"] for i in r.json()["items"]]
        by_value = await client.get("/api/search?q=sk-search-secret", headers=auth(tokens["rw"]))
        assert by_value.json()["items"] == []
        by_field = await client.get("/api/search?q=findme", headers=auth(tokens["rw"]))
        assert "search-http" in [i["name"] for i in by_field.json()["items"]]
        async with maker() as s:
            rows = (
                (await s.execute(select(AuditRow).where(AuditRow.action == "search")))
                .scalars().all()
            )
            assert rows
            for row in rows:
                assert "q" not in row.detail
                assert "findable" not in str(row.detail)
                assert "count" in row.detail


async def test_no_store_and_vary_on_all_api_responses(stack) -> None:
    async with stack() as (client, maker, tokens):
        for resp in [
            await client.get("/api/items", headers=auth(tokens["rw"])),
            await client.get("/api/items/none", headers=auth(tokens["rw"])),
            await client.get("/api/items", headers={"Authorization": "Bearer garbage"}),
        ]:
            assert resp.headers["cache-control"] == "no-store"
            assert "Cookie" in resp.headers["vary"] and "Authorization" in resp.headers["vary"]


async def test_env_endpoint(stack) -> None:
    async with stack() as (client, maker, tokens):
        await client.post("/api/items", headers=auth(tokens["rw"]), json=item_body(
            "env-http", fields=[
                {"name": "TOKEN", "secret": True, "value": "a'b"},
                {"name": "PATH", "secret": False, "value": "/evil"},
            ]))
        r = await client.get("/api/items/env-http/env", headers=auth(tokens["rw"]))
        assert r.status_code == 200
        assert "export TOKEN='a'\\''b'" in r.text
        assert "# refused hazardous name: PATH" in r.text
        # agent plane ignores the override flag
        r2 = await client.get("/api/items/env-http/env?allow_hazardous=1",
                              headers=auth(tokens["rw"]))
        assert "export PATH=" not in r2.text


async def test_pagination_cursor(stack) -> None:
    async with stack() as (client, maker, tokens):
        for i in range(3):
            await client.post("/api/items", headers=auth(tokens["rw"]),
                              json=item_body(f"page-{i}"))
        r = await client.get("/api/items?limit=50", headers=auth(tokens["rw"]))
        body = r.json()
        assert "items" in body
        # foreign cursor rejected
        bad = await client.get("/api/items?cursor=garbage", headers=auth(tokens["rw"]))
        assert bad.status_code == 422


async def test_cursor_pagination_roundtrip(stack) -> None:
    async with stack() as (client, maker, tokens):
        for i in range(60):
            await client.post("/api/items", headers=auth(tokens["rw"]),
                              json=item_body(f"zz-page-{i:03d}"))
        r1 = await client.get("/api/items?limit=50", headers=auth(tokens["rw"]))
        b1 = r1.json()
        assert b1["next_cursor"] is not None
        r2 = await client.get(f"/api/items?limit=50&cursor={b1['next_cursor']}",
                              headers=auth(tokens["rw"]))
        b2 = r2.json()
        names1 = {i["name"] for i in b1["items"]}
        names2 = {i["name"] for i in b2["items"]}
        assert not names1 & names2  # no repeats
        assert "zz-page-059" in names2  # tail reached


async def test_malformed_json_body_422(stack) -> None:
    async with stack() as (client, maker, tokens):
        r = await client.post("/api/items", headers={**auth(tokens["rw"]),
                              "content-type": "application/json"}, content=b"{broken")
        assert r.status_code == 422
        assert r.json()["code"] == "invalid"


async def test_oversize_body_413(stack) -> None:
    async with stack() as (client, maker, tokens):
        r = await client.post("/api/items", headers={**auth(tokens["rw"]),
                              "content-type": "application/json"},
                              content=b'{"name":"x","fields":[]}' + b" " * (2 * 1024 * 1024))
        assert r.status_code == 413


async def test_search_like_wildcards_literal(stack) -> None:
    async with stack() as (client, maker, tokens):
        await client.post("/api/items", headers=auth(tokens["rw"]),
                          json=item_body("pct-item", notes="has 100% literal"))
        r = await client.get("/api/search?q=100%25%20literal", headers=auth(tokens["rw"]))
        assert "pct-item" in [i["name"] for i in r.json()["items"]]
        r2 = await client.get("/api/search?q=%25", headers=auth(tokens["rw"]))
        # '%' alone must not match everything
        assert all("%" in (i["name"] + i["notes"]) for i in r2.json()["items"])


async def test_huge_name_probe_404_and_audited(stack) -> None:
    async with stack() as (client, maker, tokens):
        huge = "a" * 5000
        r = await client.get(f"/api/items/{huge}", headers=auth(tokens["scoped"]))
        assert r.status_code == 404  # not a 500 from the audit insert
        async with maker() as s:
            rows = (
                (await s.execute(select(AuditRow).where(AuditRow.ok.is_(False))))
                .scalars().all()
            )
            assert any(len(r.item_name or "") <= 200 and r.action == "get" for r in rows)


async def test_key_unavailable_read_audited(stack) -> None:
    async with stack() as (client, maker, tokens):
        from custos.db.models import Field, Item

        await client.post("/api/items", headers=auth(tokens["rw"]), json=item_body(
            "corrupt-http", fields=[{"name": "K", "secret": True, "value": "x"}]))
        async with maker() as s:
            item = (await s.execute(select(Item).where(Item.name == "corrupt-http"))).scalar_one()
            f = (await s.execute(select(Field).where(Field.item_id == item.id))).scalar_one()
            f.ciphertext = f.ciphertext[:-1] + bytes([f.ciphertext[-1] ^ 0xFF])
            await s.commit()
        r = await client.get("/api/items/corrupt-http", headers=auth(tokens["rw"]))
        assert r.status_code == 500
        async with maker() as s:
            rows = (
                (await s.execute(select(AuditRow).where(
                    AuditRow.item_name == "corrupt-http", AuditRow.ok.is_(False))))
                .scalars().all()
            )
            assert any(r.detail.get("reason") == "key_unavailable" for r in rows)


async def test_denial_reason_neutral_not_found(stack) -> None:
    async with stack() as (client, maker, tokens):
        r = await client.get("/api/items/never-was", headers=auth(tokens["rw"]))
        assert r.status_code == 404
        async with maker() as s:
            rows = (
                (await s.execute(select(AuditRow).where(AuditRow.item_name == "never-was")))
                .scalars().all()
            )
            assert rows and rows[0].detail.get("reason") == "not_found"
