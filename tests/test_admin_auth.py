"""Admin dual-auth layer (plan 3 Task 2): session XOR co- token, the
authority matrix gates, presenter-bound step-up for both principal kinds."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from custos.admin.auth import (
    AdminPrincipal,
    require_admin,
    require_sensitive,
    require_session_only,
)
from custos.db.models import AuditRow, OperatorSession, OperatorToken, StepUpToken
from custos.errors import AppError
from custos.operator.sessions import create_session
from custos.operator.stepup import consume_step_up
from custos.ratelimit import RateLimiter
from tests.admin_conftest import admin_stack, bearer

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]


async def test_session_and_token_both_reach_ping(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        await h["login"](client)
        r = await client.get("/api/admin/ping")
        assert r.status_code == 200 and r.json() == {"ok": True}
        client.cookies.clear()
        co = await h["mint_co"]()
        r = await client.get("/api/admin/ping", headers=bearer(co))
        assert r.status_code == 200


async def test_cookie_plus_bearer_401(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        await h["login"](client)
        co = await h["mint_co"]()
        r = await client.get("/api/admin/ping", headers=bearer(co))
        assert r.status_code == 401


async def test_bad_token_uniform_401(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        co = await h["mint_co"]()
        bad = co[:-1] + ("A" if co[-1] != "A" else "B")
        bodies = []
        for presented in (bad, "co-000000000000." + "A" * 43, "garbage"):
            r = await client.get("/api/admin/ping", headers=bearer(presented))
            assert r.status_code == 401
            bodies.append(r.text)
        assert bodies[0] == bodies[1] == bodies[2]
        # audited auth.failure, never an auth_events lockout row
        async with maker() as s:
            rows = (await s.execute(
                select(AuditRow).where(AuditRow.action == "auth.failure"))).scalars().all()
        assert any(r.detail.get("reason") == "admin_auth" for r in rows)


async def test_admin_bad_token_flood_gated(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        # §5: failed admin auth feeds the 30/min/IP gate — the 31st try is
        # 429 BEFORE verification, and gated tries write no audit rows
        for _ in range(30):
            r = await client.get("/api/admin/ping", headers=bearer("garbage"))
            assert r.status_code == 401
        r = await client.get("/api/admin/ping", headers=bearer("garbage"))
        assert r.status_code == 429
        async with maker() as s:
            rows = (await s.execute(
                select(AuditRow).where(AuditRow.action == "auth.failure"))).scalars().all()
        assert sum(r.detail.get("reason") == "admin_auth" for r in rows) == 30


async def test_csrf_required_on_session_mutation(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        await h["login"](client)
        # absent Origin is allowed (same-origin); missing CSRF → uniform 401
        r = await client.post("/api/auth/logout")
        assert r.status_code == 401
        # cross-site Origin → 403 before CSRF is even considered
        r = await client.post("/api/auth/logout", headers={"Origin": "http://evil.example"})
        assert r.status_code == 403


async def test_recovery_reset_session_denied_on_admin(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        async with maker() as s:
            _, cookie = await create_session(s, purpose="recovery_reset")
            await s.commit()
        client.cookies.set("custos_session", cookie)
        r = await client.get("/api/admin/ping")
        assert r.status_code == 403
        assert r.json()["code"] == "purpose_denied"


def _fake_request(app, headers: dict | None = None) -> SimpleNamespace:
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    return SimpleNamespace(
        app=app,
        headers=SimpleNamespace(
            get=lambda k, d=None: hdrs.get(k.lower(), d),
            getlist=lambda k: [hdrs[k.lower()]] if k.lower() in hdrs else [],
        ),
        cookies={}, method="GET",
        url=SimpleNamespace(path="/api/admin/ping"), client=None,
        state=SimpleNamespace(),
    )


async def test_session_only_matrix_precedes_state(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        for sensitive in (False, True):
            co = await h["mint_co"](allow_sensitive=sensitive)
            req = _fake_request(h["app"], bearer(co))
            with pytest.raises(AppError) as exc:
                await require_session_only(req)
            assert exc.value.code == "session_required"
        async with maker() as s:
            rows = (await s.execute(
                select(AuditRow).where(AuditRow.action == "auth.failure"))).scalars().all()
        assert sum(r.detail.get("reason") == "session_required" for r in rows) == 2


async def test_sensitive_gate(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        # session without header → 401 step_up_required
        req = _fake_request(h["app"])
        req.cookies = {"custos_session": client.cookies["custos_session"]}
        with pytest.raises(AppError) as exc:
            await require_sensitive(req)
        assert exc.value.code == "step_up_required"
        # plain token → 401 step_up_required
        plain = await h["mint_co"]()
        with pytest.raises(AppError) as exc:
            await require_sensitive(_fake_request(h["app"], bearer(plain)))
        assert exc.value.code == "step_up_required"
        # allow_sensitive token → passes, marks request.state
        sens = await h["mint_co"](allow_sensitive=True)
        req = _fake_request(h["app"], bearer(sens))
        p = await require_sensitive(req)
        assert p.actor_kind == "operator_token"
        assert req.state.allow_sensitive is True
        # session WITH a real step-up → passes
        token = await h["step_up"](client, csrf)
        req = _fake_request(h["app"], {"x-step-up-token": token})
        req.cookies = {"custos_session": client.cookies["custos_session"]}
        p = await require_sensitive(req)
        assert p.actor_kind == "operator_session"


async def test_peek_step_up_does_not_burn(admin_stack) -> None:
    from custos.admin.auth import peek_step_up

    async with admin_stack() as (client, maker, h):
        csrf = await h["login"](client)
        token = await h["step_up"](client, csrf)
        req = _fake_request(h["app"], {"x-step-up-token": token})
        req.cookies = {"custos_session": client.cookies["custos_session"]}
        p = await require_admin(req)
        await peek_step_up(req, p)
        await peek_step_up(req, p)  # still valid — nothing consumed
        async with maker() as s:
            rows = (await s.execute(select(StepUpToken))).scalars().all()
        assert all(r.consumed_at is None for r in rows)
        # and the real gate can still consume it afterwards
        p2 = await require_sensitive(req)
        assert p2.actor_kind == "operator_session"


async def test_step_up_bound_to_token_principal(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        await h["mint_co"]()
        raw = secrets.token_urlsafe(32)
        async with maker() as s:
            tok = (await s.execute(select(OperatorToken))).scalars().first()
            s.add(StepUpToken(operator_token_id=tok.id,
                              nonce_hash=hashlib.sha256(raw.encode()).digest(),
                              kind="single",
                              expires_at=datetime.now(UTC) + timedelta(minutes=5)))
            _, cookie = await create_session(s)
            await s.commit()
            sess = (await s.execute(select(OperatorSession).where(
                OperatorSession.id != tok.id))).scalars().first()
        # from a session → refused (binding mismatch)
        async with maker() as s:
            sess_row = await s.get(OperatorSession, sess.id)
            with pytest.raises(AppError):
                await consume_step_up(s, raw, sess_row)
        # from the bound token → consumed
        async with maker() as s:
            tok_row = await s.get(OperatorToken, tok.id)
            row = await consume_step_up(s, raw, tok_row)
            await s.commit()
        assert row.consumed_at is not None
        # revoked token → refused even for a fresh bound token
        raw2 = secrets.token_urlsafe(32)
        async with maker() as s:
            tok_row = await s.get(OperatorToken, tok.id)
            tok_row.revoked_at = datetime.now(UTC)
            s.add(StepUpToken(operator_token_id=tok.id,
                              nonce_hash=hashlib.sha256(raw2.encode()).digest(),
                              kind="single",
                              expires_at=datetime.now(UTC) + timedelta(minutes=5)))
            await s.commit()
            with pytest.raises(AppError):
                await consume_step_up(s, raw2, tok_row)


async def test_admin_rate_limit() -> None:
    limiter = RateLimiter()
    for _ in range(300):
        limiter.check_admin_request("admin:operator_token:x")
    with pytest.raises(AppError) as exc:
        limiter.check_admin_request("admin:operator_token:x")
    assert exc.value.code == "rate_limited"
    limiter.check_admin_request("admin:operator_token:y")  # separate bucket


async def test_admin_principal_satisfies_engine_protocol(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        co = await h["mint_co"](allow_sensitive=True)
        p = await require_admin(_fake_request(h["app"], bearer(co)))
        assert isinstance(p, AdminPrincipal)
        assert p.mode == "read-write" and p.scopes == ("*",)
        assert p.actor_kind == "operator_token" and len(p.actor_id) == 12
        assert p.plane == p.key_id
        await client.get("/api/admin/ping", headers=bearer(co))
