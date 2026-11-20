"""Rekey audit + verify sweep (plan 3 Task 8): SQL-only version counts,
trial-decrypt verification of ALL rows including newest-version ones."""

import base64

import pytest
from sqlalchemy import select, update

from custos.crypto import Vault, parse_keyring
from custos.db.models import AuditRow, Field
from tests.admin_conftest import admin_stack, bearer
from tests.test_config import FAKE_KEYRING

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]

K2 = "k2:" + base64.urlsafe_b64encode(bytes([9]) * 32).rstrip(b"=").decode()
RING2 = FAKE_KEYRING + "," + K2


async def _seed(client, csrf, name, value="cu-test-v"):
    r = await client.post("/api/admin/items", headers={"x-csrf-token": csrf},
                          json={"name": name, "notes": "", "fields": [
                              {"name": "KEY", "secret": True, "value": value},
                              {"name": "PLAIN", "secret": False, "value": "p"},
                          ]})
    assert r.status_code == 201, r.text


async def test_audit_sql_counts(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        csrf = await h["login"](client)
        await _seed(client, csrf, "au-1")  # sealed under k2 (newest)
        # move one field + add history under k1 via direct re-seal
        v1 = Vault(parse_keyring(FAKE_KEYRING))
        async with maker() as s:
            f = (await s.execute(select(Field).where(Field.secret.is_(True)))).scalars().first()
            blob, ver = v1.seal("field", str(f.id), b"cu-test-old")
            await s.execute(update(Field).where(Field.id == f.id)
                            .values(ciphertext=blob, key_version=ver))
            await s.commit()
        r = await client.get("/api/admin/rekey/audit")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["versions"]["fields"] == {"1": 1}  # k2 count 0? newest rows count too
        # ^ counts include ALL versions; only 1 secret field exists → {"1": 1}
        assert data["affected"] == {"1": ["au-1"]}
        assert data["newest"] == 2
        # plain field (NULL version) never counted
        assert "history" in data["versions"] and "operator" in data["versions"]
        # corrupt the k1 blob: SQL audit unchanged, verify reports unreadable
        async with maker() as s:
            f = (await s.execute(select(Field).where(Field.secret.is_(True)))).scalars().first()
            blob = bytearray(f.ciphertext)
            blob[-1] ^= 0xFF
            await s.execute(update(Field).where(Field.id == f.id)
                            .values(ciphertext=bytes(blob)))
            await s.commit()
        r = await client.get("/api/admin/rekey/audit")
        assert r.json()["versions"]["fields"] == {"1": 1}  # no decryption
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/rekey/verify",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su},
                              json={})
        assert r.status_code == 200, r.text
        assert r.json()["unreadable"]["fields"] == 1


async def test_verify_visits_newest_rows(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        csrf = await h["login"](client)
        await _seed(client, csrf, "vf-1")
        async with maker() as s:
            f = (await s.execute(select(Field).where(Field.secret.is_(True)))).scalars().first()
            original = f.ciphertext
            blob = bytearray(f.ciphertext)
            blob[-1] ^= 0xFF
            await s.execute(update(Field).where(Field.id == f.id)
                            .values(ciphertext=bytes(blob)))
            await s.commit()
        hdr = {"x-csrf-token": csrf}
        # rekey: nothing to do (all rows newest) — its run token drives both
        # endpoints (§4: one run kind accepted by rekey AND verify)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": su}, json={})
        assert r.status_code == 200 and r.json()["remaining"] == 0
        run_token = r.json()["run_token"]
        # verify: visits newest rows, finds the corruption, changes nothing
        r = await client.post("/api/admin/rekey/verify",
                              headers={**hdr, "x-step-up-token": run_token}, json={})
        assert r.status_code == 200
        data = r.json()
        assert data["unreadable"] == {"fields": 1, "history": 0, "operator": 0}
        assert data["remaining"] == 0
        async with maker() as s:
            f = (await s.execute(select(Field).where(Field.secret.is_(True)))).scalars().first()
            assert f.ciphertext != original  # still the corrupted bytes
            assert f.key_version == 2  # never re-sealed


async def test_verify_run_and_cursor(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        csrf = await h["login"](client)
        # 250 items → verify needs 2 batches
        for i in range(250):
            await _seed(client, csrf, f"vr-{i:04d}")
        hdr = {"x-csrf-token": csrf}
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/rekey/verify",
                              headers={**hdr, "x-step-up-token": su}, json={})
        assert r.status_code == 200
        first = r.json()
        run_token = first["run_token"]
        assert first["remaining"] > 0
        # same run token works on rekey too (one run kind, both endpoints)
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": run_token}, json={})
        assert r.status_code == 200
        # verify cursor on rekey endpoint → 401 (endpoint-tagged)
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": run_token},
                              json={"cursor": first["cursor"]})
        assert r.status_code == 401
        # verify cursor on verify → 200, completes
        r = await client.post("/api/admin/rekey/verify",
                              headers={**hdr, "x-step-up-token": run_token},
                              json={"cursor": first["cursor"]})
        assert r.status_code == 200
        assert r.json()["remaining"] == 0


async def test_verify_gates(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        csrf = await h["login"](client)
        r = await client.post("/api/admin/rekey/verify",
                              headers={"x-csrf-token": csrf}, json={})
        assert r.status_code == 401
        client.cookies.clear()
        plain = await h["mint_co"]()
        r = await client.post("/api/admin/rekey/verify", headers=bearer(plain), json={})
        assert r.status_code == 401
        sens = await h["mint_co"](allow_sensitive=True)
        r = await client.post("/api/admin/rekey/verify", headers=bearer(sens), json={})
        assert r.status_code == 200
        # verify run start audited once with allow_sensitive flag
        async with maker() as s:
            rows = (await s.execute(select(AuditRow).where(
                AuditRow.action == "rekey_verify"))).scalars().all()
        assert len(rows) == 1 and rows[0].detail.get("allow_sensitive") is True
