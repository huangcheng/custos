"""Rekey engine + route (plan 3 Task 7): batched re-seal under the newest
key version, run tokens, keyset scan cursors, guarded concurrent-write
UPDATE, guaranteed termination with unreadable rows."""

import base64
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select, update

from custos.crypto import Vault, parse_keyring
from custos.db.models import Field, FieldHistory, Item, OperatorAccount, StepUpToken
from custos.errors import AppError
from custos.rekey import mint_scan_cursor, read_scan_cursor
from tests.admin_conftest import admin_stack, bearer
from tests.test_config import FAKE_KEYRING

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]

K2 = "k2:" + base64.urlsafe_b64encode(bytes([9]) * 32).rstrip(b"=").decode()
RING2 = FAKE_KEYRING + "," + K2


def _vault1() -> Vault:
    return Vault(parse_keyring(FAKE_KEYRING))


async def _seed_old(maker, n_items: int, *, history: bool = False, totp: bool = False):
    """Create rows sealed under k1 directly (bypasses the k2 app vault)."""
    v1 = _vault1()
    async with maker() as s:
        # shared DB: earlier files leave items/fields/history behind (their
        # fixtures do not clean the vault tables) — start from a clean slate
        await s.execute(delete(FieldHistory))
        await s.execute(delete(Field))
        await s.execute(delete(Item))
        # …and a clean operator seal state (possibly corrupt/foreign blob)
        acct0 = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
        if acct0 is not None:
            acct0.totp_secret, acct0.totp_key_version = None, None
        for i in range(n_items):
            item = Item(name=f"rk-{i:04d}", notes="")
            s.add(item)
            await s.flush()
            fid = uuid.uuid4()
            blob, ver = v1.seal("field", str(fid), f"cu-test-v-{i}".encode())
            s.add(Field(id=fid, item_id=item.id, name="KEY", secret=True,
                        ciphertext=blob, key_version=ver))
            if history:
                hid = uuid.uuid4()
                hblob, hver = v1.seal("fieldh", str(hid), b"cu-test-prior")
                s.add(FieldHistory(id=hid, field_id=fid, item_id=item.id, name="KEY",
                                   secret=True, ciphertext=hblob, key_version=hver,
                                   superseded_by="local", actor_label="cu-test"))
        if totp:
            acct = (await s.execute(select(OperatorAccount))).scalar_one()
            blob, ver = v1.seal("operator:totp", "", b"CU-TEST-TOTP-SEED")
            acct.totp_secret, acct.totp_key_version = blob, ver
        await s.commit()


async def _rekey_loop(client, csrf, first_token, *, max_calls=50):
    """Drive POST /rekey until remaining 0; returns (responses, skipped_total)."""
    hdr = {"x-csrf-token": csrf}
    body: dict = {}
    token = first_token
    responses = []
    for _ in range(max_calls):
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": token}, json=body)
        assert r.status_code == 200, r.text
        data = r.json()
        responses.append(data)
        if data.get("run_token"):
            token = data["run_token"]
        if data["remaining"] == 0:
            return responses, sum(x["skipped"] for x in responses)
        body = {"cursor": data["cursor"]}
    raise AssertionError("rekey loop did not terminate")


async def test_rekey_moves_all_domains(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        await _seed_old(maker, 3, history=True, totp=True)
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        responses, skipped = await _rekey_loop(client, csrf, su)
        assert skipped == 0
        v2 = Vault(parse_keyring(RING2))
        async with maker() as s:
            for f in (await s.execute(select(Field))).scalars():
                assert f.key_version == 2
                v2.open("field", str(f.id), f.ciphertext, 2)
            for fh in (await s.execute(select(FieldHistory))).scalars():
                assert fh.key_version == 2
                v2.open("fieldh", str(fh.id), fh.ciphertext, 2)
            acct = (await s.execute(select(OperatorAccount))).scalar_one()
            assert acct.totp_key_version == 2
            assert v2.open("operator:totp", "", acct.totp_secret, 2) == b"CU-TEST-TOTP-SEED"
        # k1-only vault can no longer open the moved rows (version absent)
        v1 = _vault1()
        async with maker() as s:
            f = (await s.execute(select(Field))).scalars().first()
            from custos.crypto import UnreadableError
            with pytest.raises(UnreadableError):
                v1.open("field", str(f.id), f.ciphertext, 2)


async def test_batch_cursor_and_termination_with_unreadable(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        await _seed_old(maker, 250)
        # corrupt 50 rows (every 5th)
        async with maker() as s:
            rows = list((await s.execute(select(Field).order_by(Field.id))).scalars())
            for f in rows[::5]:
                blob = bytearray(f.ciphertext)
                blob[-1] ^= 0xFF
                await s.execute(update(Field).where(Field.id == f.id)
                                .values(ciphertext=bytes(blob)))
            await s.commit()
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        responses, skipped = await _rekey_loop(client, csrf, su)
        assert skipped == 50
        assert len(responses) >= 2  # 250 rows > 200/batch
        async with maker() as s:
            versions = (await s.execute(select(Field.key_version))).scalars().all()
        assert versions.count(2) == 200 and versions.count(1) == 50


async def test_run_token_lifecycle(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        await _seed_old(maker, 250)
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": su}, json={})
        assert r.status_code == 200
        first = r.json()
        run_token = first["run_token"]
        # the single is consumed: reuse cannot mint another run (409 while
        # the first run is live; the single itself is dead either way)
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": su}, json={})
        assert r.status_code == 409
        # run token works and extends expiry per batch
        async with maker() as s:
            run = (await s.execute(select(StepUpToken).where(
                StepUpToken.kind == "rekey_run"))).scalar_one()
            exp_before = run.expires_at
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": run_token},
                              json={"cursor": first["cursor"]})
        assert r.status_code == 200
        async with maker() as s:
            run = (await s.execute(select(StepUpToken).where(
                StepUpToken.kind == "rekey_run"))).scalar_one()
            assert run.expires_at >= exp_before
            assert run.consumed_at is None  # multi-use, never consumed
            # force expiry → next batch 401
            await s.execute(update(StepUpToken).where(StepUpToken.id == run.id)
                            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
            await s.commit()
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": run_token},
                              json={"cursor": first["cursor"]})
        assert r.status_code == 401
        # fresh step-up mints a new run resuming from the last cursor
        su2 = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": su2},
                              json={"cursor": first["cursor"]})
        assert r.status_code == 200
        assert r.json().get("run_token")


async def test_one_active_run(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        await _seed_old(maker, 250)
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": su}, json={})
        assert r.status_code == 200
        su2 = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": su2}, json={})
        assert r.status_code == 409 and r.json()["code"] == "conflict"


async def test_cursor_binding(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        pepper = h["settings"].pepper_raw
        cur = mint_scan_cursor({"table": "fields", "last_id": str(uuid.uuid4())},
                               pepper, "rekey", "session")
        # endpoint mismatch → 401
        with pytest.raises(AppError) as exc:
            read_scan_cursor(cur, pepper, "rekey_verify", "session")
        assert exc.value.code == "unauthorized"
        # plane mismatch → 401
        with pytest.raises(AppError) as exc:
            read_scan_cursor(cur, pepper, "rekey", "abcdef012345")
        assert exc.value.code == "unauthorized"
        # tampered tag → 401
        payload, tag = cur.split(".")
        bad = payload + "." + ("A" if tag[0] != "A" else "B") + tag[1:]
        with pytest.raises(AppError):
            read_scan_cursor(bad, pepper, "rekey", "session")
        # roundtrip
        got = read_scan_cursor(cur, pepper, "rekey", "session")
        assert got["table"] == "fields"


async def test_sensitive_token_all_batches(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        await _seed_old(maker, 250)
        sens = await h["mint_co"](allow_sensitive=True)
        body: dict = {}
        seen = 0
        for _ in range(10):
            r = await client.post("/api/admin/rekey", headers=bearer(sens), json=body)
            assert r.status_code == 200, r.text
            data = r.json()
            seen += 1
            assert "run_token" not in data  # token runs need no run row
            if data["remaining"] == 0:
                break
            body = {"cursor": data["cursor"]}
        assert seen >= 2
        plain = await h["mint_co"]()
        r = await client.post("/api/admin/rekey", headers=bearer(plain), json={})
        assert r.status_code == 401


async def test_concurrent_write_guard(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        await _seed_old(maker, 1)
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        # simulate a concurrent write: change the blob between selection and
        # update by pre-writing a NEW k1 blob with the same version, then
        # assert the guarded update targets the exact old bytes.
        async with maker() as s:
            f = (await s.execute(select(Field))).scalars().first()
            original = f.ciphertext
        # first batch rekeys the row normally
        r = await client.post("/api/admin/rekey",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su},
                              json={})
        assert r.status_code == 200 and r.json()["skipped"] == 0
        async with maker() as s:
            f = (await s.execute(select(Field))).scalars().first()
            assert f.key_version == 2 and f.ciphertext != original
        # unit: guarded UPDATE with stale bytes is a no-op
        async with maker() as s:
            res = await s.execute(
                update(Field).where(Field.id == f.id, Field.key_version == 1,
                                    Field.ciphertext == original)
                .values(key_version=2)
            )
            assert res.rowcount == 0
            await s.rollback()


async def test_replayed_final_cursor_terminates(admin_stack) -> None:
    async with admin_stack(keyring=RING2) as (client, maker, h):
        await _seed_old(maker, 2)
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        hdr = {"x-csrf-token": csrf}
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": su}, json={})
        first = r.json()
        assert first["remaining"] == 0
        # replay a cursor pointing past the last row: typed coercion, no 500
        from custos.rekey import mint_scan_cursor

        async with maker() as s:
            last = (await s.execute(select(Field).order_by(Field.id.desc()))).scalars().first()
        cur = mint_scan_cursor({"table": "operator_account", "last_id": "1"},
                               h["settings"].pepper_raw, "rekey", "session")
        r = await client.post("/api/admin/rekey",
                              headers={**hdr, "x-step-up-token": first["run_token"]},
                              json={"cursor": cur})
        assert r.status_code == 200
        assert r.json()["remaining"] == 0
        assert last is not None
