"""Recovery codes + recovery_reset promotion contract (design §5)."""

import asyncio
from datetime import UTC, datetime

import pytest
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.db.models import (
    DeviceCode,
    OperatorAccount,
    OperatorSession,
    OperatorToken,
    RecoveryCode,
    StepUpToken,
    WebAuthnChallenge,
)
from custos.errors import AppError
from custos.operator.recovery import (
    change_password,
    consume_code,
    issue_codes,
    normalize_code,
)

pytestmark = pytest.mark.usefixtures("pg_db")

PEPPER = bytes([7]) * 32
PW = "cu-test-password-12ch"


@pytest.fixture
async def maker(pg_db: str):
    from custos.operator.account import hash_password

    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
        if acct is None:
            s.add(OperatorAccount(id=1, username="operator", password_hash=hash_password(PW)))
        else:
            acct.password_hash = hash_password(PW)
            acct.totp_enabled = False
        from sqlalchemy import delete

        from custos.db.models import AgentKey

        await s.execute(delete(AgentKey))
        await s.execute(delete(StepUpToken))  # before sessions (FK)
        await s.execute(delete(WebAuthnChallenge))
        await s.execute(delete(RecoveryCode))
        await s.execute(delete(DeviceCode))
        await s.execute(delete(OperatorSession))
        await s.execute(delete(OperatorToken))
        await s.commit()
    yield maker
    await engine.dispose()


def test_normalization() -> None:
    # I/L->1, O->0, dashes/spaces stripped, uppercased; length must be 16
    assert normalize_code("IL0O1234EFGH5678") == "11001234EFGH5678"
    code = "ABCD1234EFGH5678"
    assert normalize_code("  abcd-1234 efgh-5678 ") == code
    assert normalize_code(code.replace("A", "U")) is None  # U rejected
    assert normalize_code("!!!!") is None
    assert normalize_code("ABCD") is None  # too short


async def test_issue_and_consume(maker) -> None:
    async with maker() as s:
        codes = await issue_codes(s, PEPPER)
        await s.commit()
    assert len(codes) == 10
    async with maker() as s:
        assert await consume_code(s, PEPPER, codes[0])
        await s.commit()
    async with maker() as s:
        assert not await consume_code(s, PEPPER, codes[0])  # single use


async def test_consume_normalized_form(maker) -> None:
    async with maker() as s:
        codes = await issue_codes(s, PEPPER)
        await s.commit()
    # present with dashes/lowercase — normalization maps to the stored form
    presented = codes[0][:4].lower() + "-" + codes[0][4:]
    async with maker() as s:
        assert await consume_code(s, PEPPER, presented)
        await s.commit()


async def test_concurrent_consume_one_winner(maker) -> None:
    async with maker() as s:
        codes = await issue_codes(s, PEPPER)
        await s.commit()

    async def attempt() -> bool:
        async with maker() as s:
            ok = await consume_code(s, PEPPER, codes[0])
            await s.commit()
            return ok

    results = await asyncio.gather(*[attempt() for _ in range(5)])
    assert sum(results) == 1


async def test_regen_consumes_prior(maker) -> None:
    async with maker() as s:
        first = await issue_codes(s, PEPPER)
        await s.commit()
    async with maker() as s:
        second = await issue_codes(s, PEPPER)
        await s.commit()
    async with maker() as s:
        assert not await consume_code(s, PEPPER, first[0])  # prior consumed
        assert await consume_code(s, PEPPER, second[0])
        await s.commit()


async def test_change_password_revokes_and_promotes(maker) -> None:
    from custos.operator.sessions import create_session

    async with maker() as s:
        codes = await issue_codes(s, PEPPER)
        rr, cookie = await create_session(s, purpose="recovery_reset")
        full, full_cookie = await create_session(s, purpose="full")
        s.add(OperatorToken(key_id="abcdef012345", digest=b"d" * 32, label="t",
                            expires_at=datetime.now(UTC)))
        from custos.db.models import PasskeyCredential

        s.add(PasskeyCredential(credential_id=b"cu-test-cred", public_key=b"cu-test-pk",
                                label="attacker-registered"))
        await s.commit()
        rr_id = rr.id
    async with maker() as s:
        rr_row = await s.get(OperatorSession, rr_id)
        new_sess, fresh_codes, _cookie = await change_password(
            s, rr_row, current=PW, new="cu-test-new-password-12ch", pepper=PEPPER
        )
        await s.commit()
    assert len(fresh_codes) == 10
    async with maker() as s:
        # recovery_reset promoted to full
        promoted = await s.get(OperatorSession, rr_id)
        assert promoted.purpose == "full"
        # sibling full session revoked
        sibling = (
            await s.execute(select(OperatorSession).where(OperatorSession.id == full.id))
        ).scalar_one()
        assert sibling.revoked_at is not None
        # operator tokens revoked
        tok = (await s.execute(select(OperatorToken))).scalar_one()
        assert tok.revoked_at is not None
        # attacker-registered passkeys never survive promotion (§5)
        from custos.db.models import PasskeyCredential

        assert (await s.execute(select(PasskeyCredential))).scalars().all() == []
        # old codes consumed, new ones work
        assert not await consume_code(s, PEPPER, codes[0])
        assert await consume_code(s, PEPPER, fresh_codes[0])
        await s.commit()
        # new password verifies
        acct = (await s.execute(select(OperatorAccount))).scalar_one()
        from custos.operator.account import verify_password

        assert verify_password(acct.password_hash, "cu-test-new-password-12ch")


async def test_change_password_requires_current(maker) -> None:
    from custos.operator.sessions import create_session

    async with maker() as s:
        rr, _ = await create_session(s, purpose="recovery_reset")
        await s.commit()
        rr_id = rr.id
    async with maker() as s:
        rr_row = await s.get(OperatorSession, rr_id)
        with pytest.raises(AppError):
            await change_password(s, rr_row, current="wrong-password-12",
                                  new="cu-test-new-password-12ch", pepper=PEPPER)

@pytest.fixture
def rec_http(pg_db: str):
    from contextlib import asynccontextmanager

    import httpx

    from custos.app import create_app
    from custos.config import load_settings
    from custos.operator.account import hash_password
    from tests.test_config import env

    @asynccontextmanager
    async def build():
        settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1",
                                     CUSTOS_INSECURE_DEV="1"))
        app = create_app(settings)
        engine = create_async_engine(pg_db)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as s:
            acct = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
            if acct is None:
                acct = OperatorAccount(id=1, username="operator",
                                       password_hash=hash_password(PW))
                s.add(acct)
                await s.flush()
            acct.password_hash = hash_password(PW)
            acct.totp_enabled = True  # force recovery path
            from sqlalchemy import delete

            from custos.db.models import AuthEvent, StepUpToken, WebAuthnChallenge
            await s.execute(delete(StepUpToken))  # before sessions (FK)
            await s.execute(delete(WebAuthnChallenge))
            await s.execute(delete(AuthEvent))
            await s.execute(delete(RecoveryCode))
            await s.execute(delete(DeviceCode))
            await s.execute(delete(OperatorSession))
            codes = await issue_codes(s, settings.pepper_raw)
            await s.commit()
        async with app.router.lifespan_context(app):
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test")
            async with client:
                try:
                    yield client, maker, codes, app, settings
                finally:
                    await engine.dispose()

    return build


async def test_recovery_login_and_password_change(rec_http) -> None:
    async with rec_http() as (client, maker, codes, app, settings):
        # TOTP enabled: password+recovery code -> recovery_reset session
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": PW, "recovery_code": codes[0]})
        assert r.status_code == 200
        csrf = r.json()["csrf_token"]
        # recovery_reset may change password (waiver: current password, no step-up)
        r2 = await client.post("/api/auth/password-change",
                               headers={"x-csrf-token": csrf},
                               json={"current_password": PW,
                                     "new_password": "cu-test-new-password-12ch"})
        assert r2.status_code == 200
        fresh = r2.json()["recovery_codes"]
        assert len(fresh) == 10
        # promoted session can now log in with the new password (TOTP disabled)
        r3 = await client.post("/api/auth/login", json={
            "username": "operator", "password": "cu-test-new-password-12ch"})
        assert r3.status_code == 200


async def test_recovery_reset_cannot_reach_other_routes(rec_http) -> None:
    async with rec_http() as (client, maker, codes, app, settings):
        await client.post("/api/auth/login", json={
            "username": "operator", "password": PW, "recovery_code": codes[1]})
        # totp/setup is in the allowlist, but a non-allowlisted route is denied
        from custos.operator.sessions import require_session

        @app.get("/api/admin-probe")
        async def probe(sess=Depends(require_session)):
            return {"ok": True}

        r2 = await client.get("/api/admin-probe")
        assert r2.status_code == 403
        assert r2.json()["code"] == "purpose_denied"


async def test_full_session_password_change_sets_new_cookie(rec_http) -> None:
    async with rec_http() as (client, maker, codes, app, settings):
        # disable TOTP so a normal full login works
        async with maker() as s:
            acct = (await s.execute(select(OperatorAccount))).scalar_one()
            acct.totp_enabled = False
            await s.commit()
        r = await client.post("/api/auth/login",
                              json={"username": "operator", "password": PW})
        csrf = r.json()["csrf_token"]
        old_cookie = client.cookies.get("custos_session")
        su = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                               json={"password": PW})
        r2 = await client.post("/api/auth/password-change",
                               headers={"x-csrf-token": csrf,
                                        "x-step-up-token": su.json()["step_up_token"]},
                               json={"current_password": PW,
                                     "new_password": "cu-test-new-password-12ch"})
        assert r2.status_code == 200
        new_cookie = client.cookies.get("custos_session")
        assert new_cookie and new_cookie != old_cookie  # replacement cookie set
        # the new cookie authenticates (old one revoked)
        st = await client.get("/api/auth/status")
        assert "csrf_token" in st.json()


async def test_password_change_revokes_step_up_tokens(rec_http) -> None:
    from custos.db.models import StepUpToken

    async with rec_http() as (client, maker, codes, app, settings):
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": PW, "recovery_code": codes[2]})
        csrf = r.json()["csrf_token"]
        async with maker() as s:
            sess = (await s.execute(select(OperatorSession).where(
                OperatorSession.purpose == "recovery_reset"))).scalar_one()
            s.add(StepUpToken(session_id=sess.id, nonce_hash=b"z" * 32, kind="single",
                              expires_at=datetime.now(UTC)))
            await s.commit()
        await client.post("/api/auth/password-change", headers={"x-csrf-token": csrf},
                          json={"current_password": PW,
                                "new_password": "cu-test-new-password-12ch"})
        async with maker() as s:
            tokens = (await s.execute(select(StepUpToken))).scalars().all()
            assert not [t for t in tokens if t.consumed_at is None]


async def test_failed_current_password_audited(rec_http) -> None:
    from custos.db.models import AuditRow

    async with rec_http() as (client, maker, codes, app, settings):
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": PW, "recovery_code": codes[3]})
        csrf = r.json()["csrf_token"]
        r2 = await client.post("/api/auth/password-change",
                               headers={"x-csrf-token": csrf},
                               json={"current_password": "wrong-password-12",
                                     "new_password": "cu-test-new-password-12ch"})
        assert r2.status_code == 401
        async with maker() as s:
            rows = (await s.execute(select(AuditRow).where(
                AuditRow.action == "operator.password_change",
                AuditRow.ok.is_(False)))).scalars().all()
            assert rows  # failure audited


async def test_full_session_change_returns_csrf(rec_http) -> None:
    async with rec_http() as (client, maker, codes, app, settings):
        async with maker() as s:
            acct = (await s.execute(select(OperatorAccount))).scalar_one()
            acct.totp_enabled = False
            await s.commit()
        r = await client.post("/api/auth/login",
                              json={"username": "operator", "password": PW})
        csrf = r.json()["csrf_token"]
        su = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                               json={"password": PW})
        r2 = await client.post("/api/auth/password-change",
                               headers={"x-csrf-token": csrf,
                                        "x-step-up-token": su.json()["step_up_token"]},
                               json={"current_password": PW,
                                     "new_password": "cu-test-new-password-12ch"})
        assert r2.status_code == 200
        assert "csrf_token" in r2.json()  # replacement session's token


async def test_password_change_lockout_gated(rec_http) -> None:
    from custos.db.models import AuthEvent

    async with rec_http() as (client, maker, codes, app, settings):
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": PW, "recovery_code": codes[4]})
        csrf = r.json()["csrf_token"]
        async with maker() as s:
            for _ in range(10):
                s.add(AuthEvent(kind="login_password", ok=False, ip="127.0.0.1",
                                peer_ip="127.0.0.1", ts=datetime.now(UTC)))
            await s.commit()
        r2 = await client.post("/api/auth/password-change",
                               headers={"x-csrf-token": csrf},
                               json={"current_password": PW,
                                     "new_password": "cu-test-new-password-12ch"})
        assert r2.status_code == 429
        assert r2.json()["code"] == "locked_out"


async def test_agent_keys_survive_a_password_change(maker) -> None:
    """§11: agent keys are never revoked by operator credential resets.

    Rotation is per-key (revoke); a mass revocation would break every working
    agent the moment the operator rotates a compromised password.
    """
    from custos.db.models import AgentKey
    from custos.operator.sessions import create_session

    async with maker() as s:
        # two agent keys, one already revoked, plus the operator's own session
        s.add(AgentKey(key_id="aaaaaaaaaaaa", digest=bytes(32), label="live-agent",
                       mode="read", scopes=["*"]))
        s.add(AgentKey(key_id="bbbbbbbbbbbb", digest=bytes(32), label="dead-agent",
                       mode="read", scopes=["*"]))
        row_full, _ = await create_session(s)
        await s.commit()
        full_id = row_full.id

    async with maker() as s:
        s2 = await s.get(OperatorSession, full_id)
        await change_password(
            s, s2, current=PW, new="cu-test-new-password-12ch", pepper=PEPPER
        )
        await s.commit()

    async with maker() as s:
        keys = (await s.execute(select(AgentKey))).scalars().all()
        assert len(keys) == 2, "no agent key was deleted"
        live = next(k for k in keys if k.key_id == "aaaaaaaaaaaa")
        assert live.revoked_at is None, "a password change must not revoke agent keys"
        # the row survives with its digest intact (still verifiable)
        assert live.digest == bytes(32)


async def test_status_recovery_available_follows_live_codes(rec_http) -> None:
    from sqlalchemy import update

    from custos.db.models import RecoveryCode

    async with rec_http() as (client, maker, codes, app, settings):
        st = (await client.get("/api/auth/status")).json()
        assert st["recovery_available"] is True
        async with maker() as s:
            await s.execute(
                update(RecoveryCode).values(consumed_at=datetime.now(UTC))
            )
            await s.commit()
        st = (await client.get("/api/auth/status")).json()
        assert st["recovery_available"] is False
