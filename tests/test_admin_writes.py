"""Admin masked writes (plan 3 Task 3): every write response value-free
for secrets, downgrade pre-gate atomicity, shared engine validation."""

import pytest

from tests.admin_conftest import admin_stack

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]

SENTINEL = "cu-test-write-sentinel-9f3"


def body(name=None, notes="", fields=None):
    b = {"notes": notes, "fields": fields or []}
    if name:
        b["name"] = name
    return b


async def test_all_admin_write_responses_masked(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        r = await client.post("/api/admin/items", headers=hdr,
                              json=body("w1", fields=[
                                  {"name": "KEY", "secret": True, "value": SENTINEL}]))
        assert r.status_code == 201 and SENTINEL not in r.text
        assert r.json()["fields"] == [{"name": "KEY", "secret": True}]
        r = await client.put("/api/admin/items/w1", headers=hdr,
                             json=body(fields=[
                                 {"name": "KEY", "secret": True, "value": SENTINEL + "2"}]))
        assert r.status_code == 200 and SENTINEL not in r.text
        assert r.json()["fields"] == [{"name": "KEY", "secret": True}]
        r = await client.patch("/api/admin/items/w1", headers=hdr,
                               json={"fields": [{"name": "KEY", "secret": True,
                                                 "value": SENTINEL + "3"}]})
        assert r.status_code == 200 and SENTINEL not in r.text
        assert r.json()["fields"] == [{"name": "KEY", "secret": True}]
        # notes-only patch: kept secret still masked, no kept echo
        r = await client.patch("/api/admin/items/w1", headers=hdr, json={"notes": "x"})
        assert r.status_code == 200 and SENTINEL not in r.text
        assert {"name": "KEY", "secret": True} in r.json()["fields"]
        assert all("kept" not in f for f in r.json()["fields"])


async def test_downgrade_needs_gate_atomic(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        await client.post("/api/admin/items", headers=hdr,
                          json=body("d1", fields=[
                              {"name": "KEY", "secret": True, "value": SENTINEL}]))
        downgrade = {"fields": [
            {"name": "KEY", "value": None},
            {"name": "KEY", "secret": False, "value": "cu-test-plain"},
        ]}
        r = await client.patch("/api/admin/items/d1", headers=hdr, json=downgrade)
        assert r.status_code == 401 and r.json()["code"] == "step_up_required"
        # nothing applied: field still secret
        r = await client.get("/api/admin/items/d1")
        assert {"name": "KEY", "secret": True} in r.json()["fields"]
        # a rejected downgrade must NOT burn a presented-but-invalid gate:
        # with a valid step-up it succeeds and the field becomes plain
        su = await h["step_up"](client, csrf)
        hdr_su = {**hdr, "x-step-up-token": su}
        r = await client.patch("/api/admin/items/d1", headers=hdr_su, json=downgrade)
        assert r.status_code == 200
        assert {"name": "KEY", "secret": False, "value": "cu-test-plain"} in r.json()["fields"]
        # PUT-shaped downgrade follows the same gate
        await client.patch("/api/admin/items/d1", headers=hdr,
                           json={"fields": [{"name": "KEY", "value": None},
                                            {"name": "KEY", "secret": True,
                                             "value": SENTINEL}]})
        r = await client.put("/api/admin/items/d1", headers=hdr,
                             json=body(notes="", fields=[
                                 {"name": "KEY", "secret": False, "value": "p"}]))
        assert r.status_code == 401


async def test_write_echo_never_decrypts_kept(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        await client.post("/api/admin/items", headers=hdr,
                          json=body("k1", fields=[
                              {"name": "KEY", "secret": True, "value": SENTINEL}]))
        r = await client.put("/api/admin/items/k1", headers=hdr,
                             json=body(notes="", fields=[{"name": "KEY", "secret": True}]))
        assert r.status_code == 200 and SENTINEL not in r.text
        # value survived
        su = await h["step_up"](client, csrf)
        r = await client.get("/api/admin/items/k1/reveal",
                             headers={"x-step-up-token": su})
        assert any(f.get("value") == SENTINEL for f in r.json()["fields"])


async def test_etag_and_validation_shared(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        r = await client.post("/api/admin/items", headers=hdr, json=body("e1"))
        rev = r.json()["revision"]
        assert r.headers["etag"] == f'"{rev}"'
        r = await client.put("/api/admin/items/e1",
                             headers={**hdr, "If-Match": f'"{rev + 5}"'},
                             json=body(notes="x"))
        assert r.status_code == 409
        r = await client.post("/api/admin/items", headers=hdr,
                              json=body("e2", fields=[
                                  {"name": "A", "secret": False, "value": "1"},
                                  {"name": "A", "secret": False, "value": "2"}]))
        assert r.status_code == 422
