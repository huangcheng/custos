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
    """rev 41: the session alone reveals; no step-up, and a plain token is
    refused rather than prompted."""
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        await _seed(client, csrf)
        r = await client.get("/api/admin/items/alpha/reveal")
        assert r.status_code == 200, r.text
        assert any(f["value"] == SECRET_VAL for f in r.json()["fields"])
        # env: same session, no header, repeatable (nothing is consumed)
        for _ in range(2):
            r = await client.get("/api/admin/items/alpha/env")
            assert r.status_code == 200
            assert f"export TOKEN='{SECRET_VAL}'" in r.text
        # allow_sensitive token: no header; plain token: 403 forbidden
        client.cookies.clear()  # cookie+bearer together is a pinned 401
        sens = await h["mint_co"](allow_sensitive=True)
        r = await client.get("/api/admin/items/alpha/reveal", headers=bearer(sens))
        assert r.status_code == 200
        plain = await h["mint_co"]()
        r = await client.get("/api/admin/items/alpha/reveal", headers=bearer(plain))
        assert r.status_code == 403 and r.json()["code"] == "forbidden"


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
        # rev 41: the session alone reveals a snapshot, repeatably
        for _ in range(2):
            r = await client.get(f"/api/admin/items/alpha/history/{snap['id']}/reveal")
            assert r.status_code == 200
            assert r.json()["value"] == SECRET_VAL  # the OLD value
        # snapshot under the wrong item name → 404
        await _seed(client, csrf, name="beta")
        r = await client.get(f"/api/admin/items/beta/history/{snap['id']}/reveal")
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


async def test_env_hazardous_override_keeps_its_step_up(admin_stack) -> None:
    """rev 41 removed the prompt for the plain read, NOT for the override."""
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        r = await client.post("/api/admin/items", headers={"x-csrf-token": csrf},
                              json=body("haz", fields=[
                                  {"name": "PATH", "secret": False, "value": "/usr/bin"},
                              ]))
        assert r.status_code == 201, r.text
        # plain read: no step-up, hazardous name commented out
        r = await client.get("/api/admin/items/haz/env")
        assert r.status_code == 200
        assert "export PATH=" not in r.text
        # override without a step-up → 401 step_up_required
        r = await client.get("/api/admin/items/haz/env?allow_hazardous=1")
        assert r.status_code == 401 and r.json()["code"] == "step_up_required"
        # with a step-up → the hazardous line is emitted
        su = await h["step_up"](client, csrf)
        r = await client.get("/api/admin/items/haz/env?allow_hazardous=1",
                             headers={"x-step-up-token": su})
        assert r.status_code == 200
        assert "export PATH=" in r.text
        # an allow_sensitive token needs no header
        client.cookies.clear()
        sens = await h["mint_co"](allow_sensitive=True)
        r = await client.get("/api/admin/items/haz/env?allow_hazardous=1",
                             headers=bearer(sens))
        assert r.status_code == 200 and "export PATH=" in r.text


async def test_hazardous_gate_fires_before_materialisation(admin_stack) -> None:
    """A corrupt field must not be touched before the override's gate: the
    401 step_up_required wins over the 500 key_unavailable (§6 precedence)."""
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        r = await client.post("/api/admin/items", headers={"x-csrf-token": csrf},
                              json=body("hazbad", fields=[
                                  {"name": "PATH", "secret": True, "value": SECRET_VAL},
                              ]))
        assert r.status_code == 201, r.text
        async with maker() as s:
            item = (await s.execute(select(Item).where(Item.name == "hazbad"))).scalar_one()
            f = (await s.execute(select(Field).where(
                Field.item_id == item.id, Field.name == "PATH"))).scalar_one()
            blob = bytearray(f.ciphertext)
            blob[-1] ^= 0xFF  # corrupt the GCM tag
            await s.execute(update(Field).where(Field.id == f.id)
                            .values(ciphertext=bytes(blob)))
            await s.commit()
        r = await client.get("/api/admin/items/hazbad/env?allow_hazardous=1")
        assert r.status_code == 401 and r.json()["code"] == "step_up_required"


async def test_rename_item(admin_stack) -> None:
    """rev 43: rename keeps the row (fields, history, revision) — only the
    name moves; collisions and deleted targets are refused."""
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        assert (await client.post("/api/admin/items", headers=hdr,
                                 json=body("old-name"))).status_code == 201
        r = await client.post("/api/admin/items/old-name/rename", headers=hdr,
                              json={"name": "new-name"})
        assert r.status_code == 200, r.text
        assert r.json()["name"] == "new-name"
        assert (await client.get("/api/admin/items/old-name", headers=hdr)).status_code == 404
        moved = await client.get("/api/admin/items/new-name", headers=hdr)
        assert moved.status_code == 200
        assert moved.json()["deleted"] is False
        # collision with a live name → 409
        assert (await client.post("/api/admin/items", headers=hdr,
                                 json=body("other-name"))).status_code == 201
        r = await client.post("/api/admin/items/new-name/rename", headers=hdr,
                              json={"name": "other-name"})
        assert r.status_code == 409 and r.json()["code"] == "conflict"
        # a soft-deleted target name stays reserved → 409
        assert (await client.delete("/api/admin/items/other-name",
                                   headers=hdr)).status_code == 204
        r = await client.post("/api/admin/items/new-name/rename", headers=hdr,
                              json={"name": "other-name"})
        assert r.status_code == 409
        # invalid grammar → 422
        r = await client.post("/api/admin/items/new-name/rename", headers=hdr,
                              json={"name": "NOT VALID"})
        assert r.status_code == 422 and r.json()["code"] == "invalid"
        # the move is audited with the previous name
        from sqlalchemy import select as _select

        from custos.db.models import AuditRow

        async with maker() as s:
            row = (await s.execute(
                _select(AuditRow).where(AuditRow.action == "rename")
            )).scalars().first()
            assert row is not None and row.item_name == "new-name"
            assert row.detail.get("from") == "old-name"


async def test_cjk_item_names_round_trip(admin_stack) -> None:
    """rev 45: the app grammar and the DB CHECK both accept Han ideographs."""
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        r = await client.post("/api/admin/items", headers=hdr, json=body("密钥配置"))
        assert r.status_code == 201, r.text
        assert (await client.get("/api/admin/items/密钥配置")).status_code == 200
        r = await client.post("/api/admin/items/密钥配置/rename", headers=hdr,
                              json={"name": "阿里云-密钥"})
        assert r.status_code == 200, r.text
        assert r.json()["name"] == "阿里云-密钥"
        assert (await client.get("/api/admin/items/阿里云-密钥")).status_code == 200
        # outside the grammar is still refused
        for bad in ("BadName", "bad name", "密钥🚀"):
            r = await client.post("/api/admin/items", headers=hdr, json=body(bad))
            assert r.status_code == 422, bad


async def test_rename_field(admin_stack) -> None:
    """rev 46: a field rename moves only the name — the sealed value is never
    re-encrypted, history follows the field, revision bumps, the write is
    audited; collisions, bad grammar, unknown fields and deleted items are
    refused."""
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        created = await _seed(client, csrf, "field-rename")
        assert created["revision"] == 1
        # one value change so the field has a history row under its old name
        put = await client.put("/api/admin/items/field-rename", headers=hdr, json=body(
            notes="n" * 300, fields=[
                {"name": "TOKEN", "secret": True, "value": "cu-test-rotated"},
                {"name": "REGION", "secret": False, "value": "eu"},
            ]))
        assert put.status_code == 200, put.text
        assert put.json()["revision"] == 2
        hist = await client.get("/api/admin/items/field-rename/history")
        assert [row["name"] for row in hist.json()["items"]] == ["TOKEN"]

        # a sibling field already holds the name → 409, nothing moves
        r = await client.post("/api/admin/items/field-rename/fields/TOKEN/rename",
                              headers=hdr, json={"name": "REGION"})
        assert r.status_code == 409 and r.json()["code"] == "conflict"
        # field grammar → 422
        r = await client.post("/api/admin/items/field-rename/fields/TOKEN/rename",
                              headers=hdr, json={"name": "token"})
        assert r.status_code == 422 and r.json()["code"] == "invalid"
        # unknown field → 404
        r = await client.post("/api/admin/items/field-rename/fields/NOPE/rename",
                              headers=hdr, json={"name": "TOKEN"})
        assert r.status_code == 404
        # same name → a no-op that does not bump the revision
        r = await client.post("/api/admin/items/field-rename/fields/TOKEN/rename",
                              headers=hdr, json={"name": "TOKEN"})
        assert r.status_code == 200 and r.json()["revision"] == 2

        r = await client.post("/api/admin/items/field-rename/fields/TOKEN/rename",
                              headers=hdr, json={"name": "ACCESS_KEY"})
        assert r.status_code == 200, r.text
        assert r.json() == {"name": "field-rename", "revision": 3,
                            "field": {"name": "ACCESS_KEY", "secret": True}}
        got = await client.get("/api/admin/items/field-rename")
        assert [f["name"] for f in got.json()["fields"]] == ["ACCESS_KEY", "REGION"]
        assert {"name": "ACCESS_KEY", "secret": True} in got.json()["fields"]
        # the sealed value survived untouched (and only a reveal produces it)
        r = await client.get("/api/admin/items/field-rename/reveal")
        values = {f["name"]: f.get("value") for f in r.json()["fields"]}
        assert values["ACCESS_KEY"] == "cu-test-rotated"
        # history followed the field: listed under the new name, old name gone
        hist = await client.get("/api/admin/items/field-rename/history")
        assert [row["name"] for row in hist.json()["items"]] == ["ACCESS_KEY"]
        snap = hist.json()["items"][0]
        r = await client.get(f"/api/admin/items/field-rename/history/{snap['id']}/reveal")
        assert r.status_code == 200 and r.json()["value"] == SECRET_VAL
        # the move is audited with both names
        from sqlalchemy import select as _select

        from custos.db.models import AuditRow

        async with maker() as s:
            row = (await s.execute(
                _select(AuditRow).where(AuditRow.action == "field.rename")
            )).scalars().first()
            assert row is not None and row.item_name == "field-rename"
            assert row.detail["field"] == "ACCESS_KEY" and row.detail["from"] == "TOKEN"
            assert row.detail["pre_revision"] == 2 and row.detail["revision"] == 3
        # a stale edit drawer (old revision) fails its If-Match and changes nothing
        stale = {"x-csrf-token": csrf, "If-Match": '"2"'}
        r = await client.put("/api/admin/items/field-rename", headers=stale, json=body(
            notes="n" * 300, fields=[
                {"name": "ACCESS_KEY", "secret": True},
                {"name": "REGION", "secret": False, "value": "eu"},
            ]))
        assert r.status_code == 409 and "revision mismatch" in r.json()["message"]
        assert (await client.get("/api/admin/items/field-rename")).json()["revision"] == 3
        # gated like the item rename (rev 43): an admin token may rename too —
        # a token that can already PUT the item gains nothing from this route
        client.cookies.clear()  # cookie+bearer together is a pinned 401
        plain = await h["mint_co"]()
        r = await client.post("/api/admin/items/field-rename/fields/ACCESS_KEY/rename",
                              headers=bearer(plain), json={"name": "TOKEN"})
        assert r.status_code == 200, r.text
        assert r.json()["revision"] == 4
        # the session still works after the token write; soft-deleted items
        # cannot be renamed field-wise (restore first)
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        assert (await client.delete("/api/admin/items/field-rename",
                                   headers=hdr)).status_code == 204
        r = await client.post("/api/admin/items/field-rename/fields/TOKEN/rename",
                              headers=hdr, json={"name": "ACCESS_KEY"})
        assert r.status_code == 404
