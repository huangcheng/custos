"""Admin lifecycle (plan 3 Tasks 4-5): restore, purge, force-drop —
gates before state, metadata-only paths work in degraded mode."""

import pytest
from sqlalchemy import func, select, update

from custos.db.models import AuditRow, Field, FieldHistory, Item
from tests.admin_conftest import admin_stack, bearer

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]

SENTINEL = "cu-test-lifecycle-sentinel"


def body(name=None, notes="", fields=None):
    b = {"notes": notes, "fields": fields or []}
    if name:
        b["name"] = name
    return b


async def _seed(client, csrf, name="lc"):
    r = await client.post("/api/admin/items", headers={"x-csrf-token": csrf},
                          json=body(name, fields=[
                              {"name": "KEY", "secret": True, "value": SENTINEL}]))
    assert r.status_code == 201, r.text
    return r.json()


async def _corrupt(maker, name="lc"):
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == name))).scalar_one()
        f = (await s.execute(select(Field).where(
            Field.item_id == item.id, Field.name == "KEY"))).scalar_one()
        blob = bytearray(f.ciphertext)
        blob[-1] ^= 0xFF
        await s.execute(update(Field).where(Field.id == f.id).values(ciphertext=bytes(blob)))
        await s.commit()


async def test_restore_flow(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        created = await _seed(client, csrf)
        await client.delete("/api/admin/items/lc", headers=hdr)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/items/lc/restore",
                              headers={**hdr, "x-step-up-token": su})
        assert r.status_code == 200, r.text
        assert r.json()["revision"] == created["revision"] + 2  # delete + restore
        assert SENTINEL not in r.text  # masked response
        # live restore → 409
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/items/lc/restore",
                              headers={**hdr, "x-step-up-token": su})
        assert r.status_code == 409
        # allow_sensitive token restores without a step-up header
        await client.delete("/api/admin/items/lc", headers=hdr)
        client.cookies.clear()
        sens = await h["mint_co"](allow_sensitive=True)
        r = await client.post("/api/admin/items/lc/restore", headers=bearer(sens))
        assert r.status_code == 200


async def test_restore_gates(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        await _seed(client, csrf)
        await client.delete("/api/admin/items/lc", headers=hdr)
        r = await client.post("/api/admin/items/lc/restore", headers=hdr)
        assert r.status_code == 401 and r.json()["code"] == "step_up_required"
        client.cookies.clear()
        plain = await h["mint_co"]()
        r = await client.post("/api/admin/items/lc/restore", headers=bearer(plain))
        assert r.status_code == 401
        # absent name with valid gate → 404
        r = await client.post("/api/admin/items/nope/restore", headers=bearer(plain))
        assert r.status_code == 401  # gate before state


async def test_purge_session_only_before_state(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        await h["login"](client)
        client.cookies.clear()
        sens = await h["mint_co"](allow_sensitive=True)
        r = await client.delete("/api/admin/items/absent-name/purge", headers=bearer(sens))
        assert r.status_code == 403 and r.json()["code"] == "session_required"
        async with maker() as s:
            rows = (await s.execute(select(AuditRow).where(
                AuditRow.action == "auth.failure"))).scalars().all()
        assert any(r.detail.get("reason") == "session_required" for r in rows)


async def test_purge_hard_deletes(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        await _seed(client, csrf)
        # generate one history snapshot, then soft-delete
        await client.put("/api/admin/items/lc", headers=hdr,
                         json=body(fields=[{"name": "KEY", "secret": True,
                                            "value": SENTINEL + "2"}]))
        await client.delete("/api/admin/items/lc", headers=hdr)
        r = await client.delete("/api/admin/items/lc/purge", headers=hdr)
        assert r.status_code == 401  # no step-up
        su = await h["step_up"](client, csrf)
        r = await client.delete("/api/admin/items/lc/purge",
                                headers={**hdr, "x-step-up-token": su})
        assert r.status_code == 204
        async with maker() as s:
            assert (await s.execute(select(func.count()).select_from(Item)
                                    .where(Item.name == "lc"))).scalar_one() == 0
            assert (await s.execute(select(func.count()).select_from(Field))).scalar_one() == 0
            assert (await s.execute(select(func.count()).select_from(
                FieldHistory))).scalar_one() == 0
        # name reusable
        r = await client.post("/api/admin/items", headers=hdr, json=body("lc"))
        assert r.status_code == 201
        # absent → 404 with a valid gate
        su = await h["step_up"](client, csrf)
        r = await client.delete("/api/admin/items/ghost/purge",
                                headers={**hdr, "x-step-up-token": su})
        assert r.status_code == 404


async def test_degraded_restore_and_purge(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        await _seed(client, csrf)
        await _corrupt(maker)
        await client.delete("/api/admin/items/lc", headers=hdr)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/items/lc/restore",
                              headers={**hdr, "x-step-up-token": su})
        assert r.status_code == 200  # metadata-only: no decryption
        su = await h["step_up"](client, csrf)
        r = await client.delete("/api/admin/items/lc/purge",
                                headers={**hdr, "x-step-up-token": su})
        assert r.status_code == 204
