"""Admin item reads (plan 3 Task 3): masked get/list, reveal/env gates,
history metadata + per-snapshot reveal, degraded-mode behavior."""

import pytest
from sqlalchemy import select, update

from custos.db.models import Field, Item
from tests.admin_conftest import admin_stack, bearer

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]

SECRET_VAL = "cu-test-sentinel-secret-value"


def body(name=None, notes="", fields=None):
    b = {"notes": notes, "fields": fields or []}
    if name:
        b["name"] = name
    return b


async def _seed(client, csrf, name="alpha"):
    r = await client.post("/api/admin/items", headers={"x-csrf-token": csrf},
                          json=body(name, notes="n" * 300, fields=[
                              {"name": "TOKEN", "secret": True, "value": SECRET_VAL},
                              {"name": "REGION", "secret": False, "value": "eu"},
                          ]))
    assert r.status_code == 201, r.text
    return r.json()


async def test_masked_get_and_list(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        created = await _seed(client, csrf)
        assert created["fields"] == [
            {"name": "REGION", "secret": False, "value": "eu"},
            {"name": "TOKEN", "secret": True},
        ]
        assert SECRET_VAL not in str(created)
        r = await client.get("/api/admin/items/alpha")
        assert r.status_code == 200
        got = r.json()
        assert got["notes"] == "n" * 300  # full notes on masked get
        assert {"name": "TOKEN", "secret": True} in got["fields"]
        assert SECRET_VAL not in r.text
        r = await client.get("/api/admin/items")
        row = r.json()["items"][0]
        assert row["deleted"] is False
        assert len(row["notes"]) <= 256
        assert all("value" not in f for f in row["fields"])


async def test_soft_deleted_visible_to_admin_reads(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        await _seed(client, csrf)
        r = await client.delete("/api/admin/items/alpha", headers={"x-csrf-token": csrf})
        assert r.status_code == 204
        r = await client.get("/api/admin/items/alpha")
        assert r.status_code == 200
        r = await client.get("/api/admin/items")
        assert r.json()["items"][0]["deleted"] is True
        # reveal works on soft-deleted too (with gate)
        su = await h["step_up"](client, csrf)
        r = await client.get("/api/admin/items/alpha/reveal",
                             headers={"x-step-up-token": su})
        assert r.status_code == 200
        assert SECRET_VAL in r.text


async def test_reveal_and_env_gate(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        await _seed(client, csrf)
        r = await client.get("/api/admin/items/alpha/reveal")
        assert r.status_code == 401 and r.json()["code"] == "step_up_required"
        su = await h["step_up"](client, csrf)
        r = await client.get("/api/admin/items/alpha/reveal",
                             headers={"x-step-up-token": su})
        assert r.status_code == 200
        assert any(f["value"] == SECRET_VAL for f in r.json()["fields"])
        # env: fresh step-up per call
        r = await client.get("/api/admin/items/alpha/env",
                             headers={"x-step-up-token": su})
        assert r.status_code == 401  # single-use consumed by reveal
        su = await h["step_up"](client, csrf)
        r = await client.get("/api/admin/items/alpha/env",
                             headers={"x-step-up-token": su})
        assert r.status_code == 200
        assert f"export TOKEN='{SECRET_VAL}'" in r.text
        # allow_sensitive token: no header; plain token: 401
        client.cookies.clear()  # cookie+bearer together is a pinned 401
        sens = await h["mint_co"](allow_sensitive=True)
        r = await client.get("/api/admin/items/alpha/reveal", headers=bearer(sens))
        assert r.status_code == 200
        plain = await h["mint_co"]()
        r = await client.get("/api/admin/items/alpha/reveal", headers=bearer(plain))
        assert r.status_code == 401


async def test_env_hazardous_override(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        await _seed(client, csrf, name="haz")
        r = await client.patch("/api/admin/items/haz", headers={"x-csrf-token": csrf},
                               json={"fields": [{"name": "PATH", "secret": False,
                                                 "value": "/cu-test/bin"}]})
        assert r.status_code == 200
        su = await h["step_up"](client, csrf)
        r = await client.get("/api/admin/items/haz/env",
                             headers={"x-step-up-token": su})
        assert "# refused hazardous name: PATH" in r.text
        assert "export PATH=" not in r.text
        su = await h["step_up"](client, csrf)
        r = await client.get("/api/admin/items/haz/env?allow_hazardous=1",
                             headers={"x-step-up-token": su})
        assert "export PATH='/cu-test/bin'" in r.text


async def test_history_list_and_reveal(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        await _seed(client, csrf)
        r = await client.put("/api/admin/items/alpha", headers={"x-csrf-token": csrf},
                             json=body(notes="n", fields=[
                                 {"name": "TOKEN", "secret": True, "value": "cu-test-new"},
                                 {"name": "REGION", "secret": False, "value": "eu"},
                             ]))
        assert r.status_code == 200
        r = await client.get("/api/admin/items/alpha/history")
        assert r.status_code == 200
        rows = r.json()["items"]
        assert len(rows) == 1
        snap = rows[0]
        assert snap["name"] == "TOKEN" and snap["secret"] is True
        assert "value" not in snap
        su = await h["step_up"](client, csrf)
        r = await client.get(f"/api/admin/items/alpha/history/{snap['id']}/reveal",
                             headers={"x-step-up-token": su})
        assert r.status_code == 200
        assert r.json()["value"] == SECRET_VAL  # the OLD value
        # same token again → 401 (one step-up per snapshot reveal)
        r = await client.get(f"/api/admin/items/alpha/history/{snap['id']}/reveal",
                             headers={"x-step-up-token": su})
        assert r.status_code == 401
        # snapshot under the wrong item name → 404
        await _seed(client, csrf, name="beta")
        su = await h["step_up"](client, csrf)
        r = await client.get(f"/api/admin/items/beta/history/{snap['id']}/reveal",
                             headers={"x-step-up-token": su})
        assert r.status_code == 404
        # unknown item history → 404
        r = await client.get("/api/admin/items/nope/history")
        assert r.status_code == 404


async def test_degraded_masked_get(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        await _seed(client, csrf)
        async with maker() as s:
            item = (await s.execute(select(Item).where(Item.name == "alpha"))).scalar_one()
            f = (await s.execute(select(Field).where(
                Field.item_id == item.id, Field.name == "TOKEN"))).scalar_one()
            blob = bytearray(f.ciphertext)
            blob[-1] ^= 0xFF  # corrupt the GCM tag
            await s.execute(update(Field).where(Field.id == f.id)
                            .values(ciphertext=bytes(blob)))
            await s.commit()
        r = await client.get("/api/admin/items/alpha")
        assert r.status_code == 200
        assert {"name": "TOKEN", "secret": True, "unavailable": True} in r.json()["fields"]
        su = await h["step_up"](client, csrf)
        r = await client.get("/api/admin/items/alpha/reveal",
                             headers={"x-step-up-token": su})
        assert r.status_code == 500 and r.json()["code"] == "key_unavailable"
        r = await client.get("/api/admin/items")
        assert r.status_code == 200
        assert all("unavailable" not in f for f in r.json()["items"][0]["fields"])
