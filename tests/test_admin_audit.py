"""Admin audit read (plan 3 Task 10): filtered keyset pages, never values."""

import pytest

from tests.admin_conftest import admin_stack, bearer

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]

SENTINEL = "cu-test-audit-sentinel-x7"


async def test_audit_filters_and_pagination(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        # >50 write rows: 60 creates
        for i in range(60):
            r = await client.post("/api/admin/items", headers=hdr,
                                  json={"name": f"ad-{i:03d}", "notes": "", "fields": [
                                      {"name": "K", "secret": True, "value": SENTINEL}]})
            assert r.status_code == 201, r.text
        r = await client.get("/api/admin/audit?action=create&limit=50")
        assert r.status_code == 200
        page1 = r.json()
        assert len(page1["items"]) == 50 and page1["next_cursor"]
        r = await client.get(
            f"/api/admin/audit?action=create&limit=50&cursor={page1['next_cursor']}")
        page2 = r.json()
        assert len(page2["items"]) == 10
        ids1 = {x["id"] for x in page1["items"]}
        assert not ids1 & {x["id"] for x in page2["items"]}
        # item filter
        r = await client.get("/api/admin/audit?item=ad-000")
        rows = r.json()["items"]
        assert rows and all(x["item_name"] == "ad-000" for x in rows)
        # actor filter (session uuid)
        actor = rows[0]["actor_id"]
        r = await client.get(f"/api/admin/audit?actor={actor}&action=create")
        assert all(x["actor_id"] == actor for x in r.json()["items"])
        # foreign cursor (different principal) → 422
        client.cookies.clear()  # cookie+bearer together is a pinned 401
        co = await h["mint_co"]()
        r = await client.get(
            f"/api/admin/audit?cursor={page1['next_cursor']}", headers=bearer(co))
        assert r.status_code == 422


async def test_audit_never_contains_values(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        await client.post("/api/admin/items", headers=hdr,
                          json={"name": "av", "notes": SENTINEL + "-notes", "fields": [
                              {"name": "K", "secret": True, "value": SENTINEL},
                              {"name": "P", "secret": False, "value": SENTINEL + "-p"}]})
        su = await h["step_up"](client, csrf)
        await client.get("/api/admin/items/av/reveal", headers={"x-step-up-token": su})
        r = await client.get("/api/admin/audit?limit=100")
        assert r.status_code == 200
        assert SENTINEL not in r.text  # no value, notes text, or search term
