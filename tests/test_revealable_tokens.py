"""Revealable credentials (§5) + audit-fix regressions.

Covers: sealed token storage + session-only reveal (key.reveal /
token.reveal), revoked/legacy refusal, rekey coverage of the new domains,
AAD domain separation, the uniform-401 TOTP guard, the hardened setup-code
reader, MCP failed-auth fail-closed parity, in-transaction force_drop and
operator success audits.
"""

from __future__ import annotations

import base64
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pyotp
import pytest
from sqlalchemy import func, select, text, update

from custos.config import ConfigError, load_settings
from custos.crypto import UnreadableError, Vault, parse_keyring
from custos.db.models import AgentKey, AuditRow, AuthEvent, Field, Item, RecoveryCode
from custos.keys import mint_agent_key
from custos.operator.account import ensure_setup_code
from tests.admin_conftest import PW, admin_stack, bearer
from tests.test_config import FAKE_KEYRING, env

__all__ = ["admin_stack"]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


K2_RING = FAKE_KEYRING + ",k2:" + _b64url(bytes([1]) * 32)
BAD_BEARER = "Bearer cu-000000000000." + "A" * 43


def hdr(csrf: str, su: str | None = None) -> dict:
    h = {"x-csrf-token": csrf}
    if su is not None:
        h["x-step-up-token"] = su
    return h


async def _mint_key(client, h, csrf: str, label: str) -> dict:
    su = await h["step_up"](client, csrf)
    r = await client.post(
        "/api/admin/keys", headers=hdr(csrf, su),
        json={"label": label},
    )
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------- crypto


def test_key_and_token_domains_are_separated() -> None:
    vault = Vault(parse_keyring(FAKE_KEYRING))
    blob, ver = vault.seal("key", "aabbccddeeff", b"cu-test-secret")
    assert vault.open("key", "aabbccddeeff", blob, ver) == b"cu-test-secret"
    for domain, row_id in (("token", "aabbccddeeff"), ("key", "ffeeddccbbaa"),
                           ("field", "aabbccddeeff")):
        with pytest.raises(UnreadableError):
            vault.open(domain, row_id, blob, ver)


# ---------------------------------------------------------------- reveal


async def test_key_mint_seals_and_reveal_roundtrip(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        minted = await _mint_key(client, h, csrf, "cu-test-reveal")
        async with maker() as s:
            row = (await s.execute(
                select(AgentKey).where(AgentKey.key_id == minted["key_id"])
            )).scalar_one()
            assert row.secret_ciphertext is not None
            assert row.secret_key_version is not None
        listing = await client.get("/api/admin/keys", headers=hdr(csrf))
        assert listing.status_code == 200
        listed = next(k for k in listing.json()["keys"] if k["key_id"] == minted["key_id"])
        assert listed["has_secret"] is True
        su = await h["step_up"](client, csrf)
        r = await client.get(
            f"/api/admin/keys/{minted['key_id']}/reveal", headers=hdr(csrf, su)
        )
        assert r.status_code == 200, r.text
        assert r.json()["token"] == minted["token"]
        async with maker() as s:
            audits = (await s.execute(
                select(AuditRow).where(AuditRow.action == "key.reveal")
            )).scalars().all()
            assert len(audits) == 1 and audits[0].ok is True
            assert audits[0].detail["key_id"] == minted["key_id"]


async def test_reveal_gates(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        minted = await _mint_key(client, h, csrf, "cu-test-gates")
        key_id = minted["key_id"]
        # rev 39: the session alone reveals — no step-up header at all
        r = await client.get(f"/api/admin/keys/{key_id}/reveal", headers=hdr(csrf))
        assert r.status_code == 200, r.text
        assert r.json()["token"] == minted["token"]
        # bearer requests must NOT carry the session cookie (cookie XOR bearer)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=h["app"]), base_url="http://test"
        ) as bc:
            # credential reveal is session-only: ANY bearer -> 403 before state
            plain = await h["mint_co"](allow_sensitive=False)
            r = await bc.get(f"/api/admin/keys/{key_id}/reveal", headers=bearer(plain))
            assert r.status_code == 403 and r.json()["code"] == "session_required"
            sensitive = await h["mint_co"](allow_sensitive=True)
            r = await bc.get(f"/api/admin/keys/{key_id}/reveal", headers=bearer(sensitive))
            assert r.status_code == 403 and r.json()["code"] == "session_required"
        # unknown key -> 404, audited ok:false (session alone)
        r = await client.get("/api/admin/keys/000000000000/reveal", headers=hdr(csrf))
        assert r.status_code == 404


async def test_reveal_revoked_and_legacy_refused(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        key_id = (await _mint_key(client, h, csrf, "cu-test-rev"))["key_id"]
        su = await h["step_up"](client, csrf)
        r = await client.delete(f"/api/admin/keys/{key_id}", headers=hdr(csrf, su))
        assert r.status_code == 204
        # hard delete (rev 38): the row is gone — reveal is a plain 404 and
        # the inventory no longer lists the key
        su = await h["step_up"](client, csrf)
        r = await client.get(f"/api/admin/keys/{key_id}/reveal", headers=hdr(csrf, su))
        assert r.status_code == 404
        listing = await client.get("/api/admin/keys", headers=hdr(csrf))
        assert all(k["key_id"] != key_id for k in listing.json()["keys"])
        # legacy digest-only token (direct insert, no sealed copy) -> 409
        legacy = await h["mint_co"](allow_sensitive=True)
        legacy_id = legacy.split(".")[0].removeprefix("co-")
        listing = await client.get("/api/admin/tokens", headers=hdr(csrf))
        assert listing.status_code == 200
        listed = next(t for t in listing.json()["tokens"] if t["key_id"] == legacy_id)
        assert listed["has_secret"] is False
        su = await h["step_up"](client, csrf)
        r = await client.get(f"/api/admin/tokens/{legacy_id}/reveal", headers=hdr(csrf, su))
        assert r.status_code == 409
        # expired-but-unrevoked credential -> 409 (never hand back a dead token)
        expired = await _mint_key(client, h, csrf, "cu-test-expired")
        async with maker() as s:
            await s.execute(
                update(AgentKey)
                .where(AgentKey.key_id == expired["key_id"])
                .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
            await s.commit()
        su = await h["step_up"](client, csrf)
        r = await client.get(
            f"/api/admin/keys/{expired['key_id']}/reveal", headers=hdr(csrf, su)
        )
        assert r.status_code == 409


async def test_token_reveal_roundtrip(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        expires = (datetime.now(UTC) + timedelta(days=7)).isoformat()
        r = await client.post(
            "/api/admin/tokens", headers=hdr(csrf, su),
            json={"label": "cu-test-tok", "expires_at": expires, "allow_sensitive": False},
        )
        assert r.status_code == 201, r.text
        minted = r.json()
        su = await h["step_up"](client, csrf)
        r = await client.get(
            f"/api/admin/tokens/{minted['key_id']}/reveal", headers=hdr(csrf, su)
        )
        assert r.status_code == 200 and r.json()["token"] == minted["token"]
        async with maker() as s:
            row = (await s.execute(
                select(AuditRow).where(AuditRow.action == "token.reveal")
            )).scalar_one()
            assert row.ok is True and row.detail["key_id"] == minted["key_id"]


async def test_rekey_reseals_key_and_token_secrets(admin_stack) -> None:
    async with admin_stack(keyring=K2_RING) as (client, maker, h):
        settings = h["settings"]
        vault_k1 = Vault(parse_keyring(FAKE_KEYRING))
        # seed a row sealed under the OLD version k1 (newest is k2)
        token, draft = mint_agent_key(settings.pepper_raw)
        blob, ver = vault_k1.seal("key", draft.key_id, token.encode())
        async with maker() as s:
            s.add(AgentKey(key_id=draft.key_id, digest=draft.digest, label="cu-test-old",
                           secret_ciphertext=blob, secret_key_version=ver))
            await s.commit()
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/rekey", headers=hdr(csrf, su), json={})
        assert r.status_code == 200 and r.json()["remaining"] == 0, r.text
        async with maker() as s:
            row = (await s.execute(
                select(AgentKey).where(AgentKey.key_id == draft.key_id)
            )).scalar_one()
            assert row.secret_key_version == 2
        su = await h["step_up"](client, csrf)
        r = await client.get(f"/api/admin/keys/{draft.key_id}/reveal", headers=hdr(csrf, su))
        assert r.status_code == 200 and r.json()["token"] == token


# ------------------------------------------------- fix 1: TOTP uniform 401


async def test_non_ascii_totp_is_uniform_401(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/auth/totp/setup", headers=hdr(csrf, su))
        secret = r.json()["secret"]
        code = pyotp.TOTP(secret).now()
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/auth/totp/confirm", headers=hdr(csrf, su),
                              json={"code": code})
        assert r.status_code == 200, r.text
        # wrong password + non-ASCII totp -> uniform 401 + login_password row
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": "cu-test-wrong-guess", "totp": "１２３４５６",
        })
        assert r.status_code == 401 and r.json()["code"] == "unauthorized"
        # correct password + non-ASCII totp -> SAME 401 (no 500 oracle) + login_totp row
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": PW, "totp": "１２３４５６",
        })
        assert r.status_code == 401 and r.json()["code"] == "unauthorized"
        async with maker() as s:
            kinds = [e.kind for e in (await s.execute(select(AuthEvent))).scalars().all()]
            assert "login_password" in kinds and "login_totp" in kinds


# ------------------------------------- fix 2: setup-code reader contract


def _settings_for(data_dir):
    return load_settings(env(CUSTOS_DATA_DIR=str(data_dir), CUSTOS_SETUP_CODE=""))


def test_setup_code_reuse_enforces_secret_file_contract(tmp_path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    data.chmod(0o700)
    code_file = data / "setup-code"
    code = "cu-test-setup-code-AAAAAAAAAAAAAAAA"
    code_file.write_text(code + "\n")
    code_file.chmod(0o600)
    assert ensure_setup_code(_settings_for(data)) == code
    # loose mode refused
    code_file.chmod(0o644)
    with pytest.raises(ConfigError):
        ensure_setup_code(_settings_for(data))
    code_file.chmod(0o600)
    # symlink refused
    target = tmp_path / "elsewhere"
    target.write_text(code + "\n")
    target.chmod(0o600)
    code_file.unlink()
    code_file.symlink_to(target)
    with pytest.raises(ConfigError):
        ensure_setup_code(_settings_for(data))
    code_file.unlink()
    # FIFO refused without blocking (O_NONBLOCK + S_ISREG)
    os.mkfifo(code_file, 0o600)
    with pytest.raises(ConfigError):
        ensure_setup_code(_settings_for(data))
    code_file.unlink()
    # short file fails closed
    code_file.write_text("short\n")
    code_file.chmod(0o600)
    with pytest.raises(ConfigError):
        ensure_setup_code(_settings_for(data))


def test_setup_code_refuses_loose_data_dir(tmp_path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    # group/other-WRITABLE dir lets a local user plant/replace the code file
    # (0755 is only traversable, not plantable — the file mode check covers that)
    data.chmod(0o777)
    code_file = data / "setup-code"
    code_file.write_text("cu-test-setup-code-AAAAAAAAAAAAAAAA\n")
    code_file.chmod(0o600)
    with pytest.raises(ConfigError):
        ensure_setup_code(_settings_for(data))


# ------------------------------------- fix 5: MCP failed-auth fail-closed


async def test_mcp_auth_failure_fails_closed_on_ledger_error(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        probe = {"Authorization": BAD_BEARER, "Content-Type": "application/json"}
        body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        # healthy baseline: 401 + ledger pair
        r = await client.post("/mcp", headers=probe, json=body)
        assert r.status_code == 401
        async with maker() as s:
            await s.execute(text(
                "CREATE FUNCTION ledger_boom() RETURNS trigger LANGUAGE plpgsql AS "
                "$$ BEGIN RAISE EXCEPTION 'ledger down'; END $$"
            ))
            await s.execute(text(
                "CREATE TRIGGER ledger_boom_tr BEFORE INSERT ON auth_events "
                "FOR EACH ROW EXECUTE FUNCTION ledger_boom()"
            ))
            await s.commit()
        try:
            r = await client.post("/mcp", headers=probe, json=body)
            assert r.status_code == 500 and r.json()["code"] == "internal_error", r.text
            # REST parity: same fail-closed shape
            r = await client.get("/api/items", headers={"Authorization": BAD_BEARER})
            assert r.status_code == 500 and r.json()["code"] == "internal_error"
        finally:
            async with maker() as s:
                await s.execute(text("DROP TRIGGER IF EXISTS ledger_boom_tr ON auth_events"))
                await s.execute(text("DROP FUNCTION IF EXISTS ledger_boom()"))
                await s.commit()
        r = await client.post("/mcp", headers=probe, json=body)
        assert r.status_code == 401  # recovered


# ------------------------- fix 4: force_drop audit commits with the drop


async def test_force_drop_audit_rolls_back_with_the_write(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        vault = h["app"].state.vault
        async with maker() as s:
            item = Item(name="cu-test-fd", notes="")
            s.add(item)
            await s.flush()
            s.add(Field(id=uuid.uuid4(), item_id=item.id, name="K", secret=True,
                        ciphertext=b"x" * 40, key_version=1))
            await s.commit()
        from custos.items import force_drop

        p = SimpleNamespace(actor_id=str(uuid.uuid4()), actor_label="operator")
        async with maker() as s:
            dropped = await force_drop(
                s, maker, vault, p, "cu-test-fd", actor_kind="operator_session"
            )
            assert dropped == 1
            await s.rollback()  # outer commit fails
        async with maker() as s:
            n = (await s.execute(
                select(func.count()).select_from(AuditRow)
                .where(AuditRow.action == "force_drop")
            )).scalar_one()
            assert n == 0  # no phantom ok:true row
            item_id = (await s.execute(
                select(Item.id).where(Item.name == "cu-test-fd")
            )).scalar_one()
            f = (await s.execute(
                select(Field).where(Field.item_id == item_id)
            )).scalars().first()
            assert f is not None  # the drop rolled back too
        async with maker() as s:
            dropped = await force_drop(
                s, maker, vault, p, "cu-test-fd", actor_kind="operator_session"
            )
            assert dropped == 1
            await s.commit()
        async with maker() as s:
            n = (await s.execute(
                select(func.count()).select_from(AuditRow)
                .where(AuditRow.action == "force_drop")
            )).scalar_one()
            assert n == 1


# ------------------- fix 3: operator success audits are atomic with the write


async def test_recovery_regen_rolls_back_on_ledger_error(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        # shared DB may retain codes from earlier tests: compare deltas
        async with maker() as s:
            baseline = (await s.execute(
                select(func.count()).select_from(RecoveryCode)
            )).scalar_one()
        # pre-mint a step-up with a healthy ledger, then degrade and regen
        su = await h["step_up"](client, csrf)
        async with maker() as s:
            await s.execute(text(
                "CREATE FUNCTION ledger_boom() RETURNS trigger LANGUAGE plpgsql AS "
                "$$ BEGIN RAISE EXCEPTION 'ledger down'; END $$"
            ))
            await s.execute(text(
                "CREATE TRIGGER ledger_boom_tr BEFORE INSERT ON audit "
                "FOR EACH ROW EXECUTE FUNCTION ledger_boom()"
            ))
            await s.commit()
        try:
            # Starlette re-raises after sending the 500; tolerate it to read
            # the response (the shared admin_stack client re-raises)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=h["app"], raise_app_exceptions=False),
                base_url="http://test",
            ) as dc:
                dc.cookies.update(client.cookies)
                r = await dc.post("/api/auth/recovery/regen", headers=hdr(csrf, su))
            assert r.status_code == 500 and r.json()["code"] == "internal_error", r.text
            async with maker() as s:
                n = (await s.execute(
                    select(func.count()).select_from(RecoveryCode)
                )).scalar_one()
                # mutation rolled back WITH the audit — no consumed/undelivered codes
                assert n == baseline
        finally:
            async with maker() as s:
                await s.execute(text("DROP TRIGGER IF EXISTS ledger_boom_tr ON audit"))
                await s.execute(text("DROP FUNCTION IF EXISTS ledger_boom()"))
                await s.commit()
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/auth/recovery/regen", headers=hdr(csrf, su))
        assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10
