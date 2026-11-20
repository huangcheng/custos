"""Admin key/token management (plan 3 Task 6): session+step-up mints and
revokes, masked inventories audited, revocation cascades bound step-ups."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from custos.db.models import AuditRow, OperatorToken, StepUpToken
from tests.admin_conftest import admin_stack, bearer

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]


def _iso(days: float) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


async def test_key_mint_once_and_agent_auth(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/keys",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su},
                              json={"label": "cu-test-agent", "mode": "read-write",
                                    "scopes": ["*"]})
        assert r.status_code == 201, r.text
        minted = r.json()
        token = minted["token"]
        assert token.startswith("cu-")
        # the returned token authenticates on the agent plane
        client.cookies.clear()
        r = await client.get("/api/items", headers=bearer(token))
        assert r.status_code == 200
        # inventory never carries token or digest material
        await h["login"](client)
        r = await client.get("/api/admin/keys")
        assert r.status_code == 200
        assert token not in r.text and token.split(".")[1] not in r.text
        row = r.json()["keys"][0]
        assert row["key_id"] == minted["key_id"] and row["mode"] == "read-write"
        async with maker() as s:
            rows = (await s.execute(select(AuditRow).where(
                AuditRow.action == "key.mint"))).scalars().all()
        assert rows and rows[0].detail["key_id"] == minted["key_id"]


async def test_mint_revoke_session_only(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        client.cookies.clear()
        for sensitive in (False, True):
            co = await h["mint_co"](allow_sensitive=sensitive)
            r = await client.post("/api/admin/keys", headers=bearer(co),
                                  json={"label": "x", "mode": "read", "scopes": []})
            assert r.status_code == 403 and r.json()["code"] == "session_required"
            r = await client.post("/api/admin/tokens", headers=bearer(co),
                                  json={"label": "x", "expires_at": _iso(1)})
            assert r.status_code == 403
        async with maker() as s:
            rows = (await s.execute(select(AuditRow).where(
                AuditRow.action == "auth.failure"))).scalars().all()
        assert sum(r.detail.get("reason") == "session_required" for r in rows) == 4
        # session without step-up → 401; step-up single-use
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        r = await client.post("/api/admin/keys", headers=hdr,
                              json={"label": "x", "mode": "read", "scopes": []})
        assert r.status_code == 401
        su = await h["step_up"](client, csrf)
        hdr_su = {**hdr, "x-step-up-token": su}
        r = await client.post("/api/admin/keys", headers=hdr_su,
                              json={"label": "x", "mode": "read", "scopes": []})
        assert r.status_code == 201
        r = await client.post("/api/admin/keys", headers=hdr_su,
                              json={"label": "y", "mode": "read", "scopes": []})
        assert r.status_code == 401  # consumed exactly once


async def test_revoke_bites_next_request(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/keys",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su},
                              json={"label": "r", "mode": "read", "scopes": ["*"]})
        token, key_id = r.json()["token"], r.json()["key_id"]
        client.cookies.clear()
        assert (await client.get("/api/items", headers=bearer(token))).status_code == 200
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.delete(f"/api/admin/keys/{key_id}",
                                headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 204
        client.cookies.clear()
        assert (await client.get("/api/items", headers=bearer(token))).status_code == 401
        # unknown key_id → 404 with a valid gate
        await h["login"](client)
        r = await client.get("/api/auth/status")
        csrf = r.json()["csrf_token"]
        su = await h["step_up"](client, csrf)
        r = await client.delete("/api/admin/keys/000000000000",
                                headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 404


async def test_token_expiry_caps_http(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        hdr = {"x-csrf-token": csrf}
        for payload, want in [
            ({"label": "t"}, 422),
            ({"label": "t", "expires_at": _iso(91)}, 422),
            ({"label": "t", "expires_at": _iso(31), "allow_sensitive": True}, 422),
            ({"label": "t", "expires_at": _iso(-1)}, 422),
            ({"label": "t", "expires_at": _iso(30), "allow_sensitive": True}, 201),
            ({"label": "t", "expires_at": _iso(90)}, 201),
        ]:
            su = await h["step_up"](client, csrf)
            r = await client.post("/api/admin/tokens",
                                  headers={**hdr, "x-step-up-token": su}, json=payload)
            assert r.status_code == want, (payload, r.text)
            if want == 201:
                assert r.json()["token"].startswith("co-")


async def test_token_revoke_kills_bound_run_and_stepup(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        co = await h["mint_co"]()
        raw = secrets.token_urlsafe(32)
        async with maker() as s:
            tok = (await s.execute(select(OperatorToken))).scalars().first()
            s.add(StepUpToken(operator_token_id=tok.id,
                              nonce_hash=hashlib.sha256(raw.encode()).digest(),
                              kind="single",
                              expires_at=datetime.now(UTC) + timedelta(minutes=5)))
            await s.commit()
            tok_id = tok.id
        key_id = co.split(".")[0][3:]
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.delete(f"/api/admin/tokens/{key_id}",
                                headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 204
        async with maker() as s:
            bound = (await s.execute(select(StepUpToken).where(
                StepUpToken.operator_token_id == tok_id))).scalars().all()
        assert bound == []  # cascade-deleted in the same transaction
        client.cookies.clear()
        r = await client.get("/api/admin/ping", headers=bearer(co))
        assert r.status_code == 401


async def test_inventory_audited(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        co = await h["mint_co"]()
        r = await client.get("/api/admin/keys", headers=bearer(co))
        assert r.status_code == 200
        r = await client.get("/api/admin/tokens", headers=bearer(co))
        assert r.status_code == 200
        assert co not in r.text and co.split(".")[1] not in r.text
        async with maker() as s:
            actions = (await s.execute(select(AuditRow.action))).scalars().all()
        assert "key.list" in actions and "token.list" in actions
