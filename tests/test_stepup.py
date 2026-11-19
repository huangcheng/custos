"""Step-up token contract (design §5): single-use, presenter-bound."""

from datetime import UTC, datetime, timedelta

import httpx
import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.app import create_app
from custos.config import load_settings
from custos.crypto import Vault, parse_keyring
from custos.db.models import (
    AuthEvent,
    OperatorAccount,
    OperatorSession,
    StepUpToken,
    WebAuthnChallenge,
)
from custos.errors import AppError
from custos.operator.account import hash_password
from custos.operator.stepup import consume_step_up, mint_step_up
from custos.operator.totp import begin_totp_setup, confirm_totp
from tests.test_config import FAKE_KEYRING, env

pytestmark = pytest.mark.usefixtures("pg_db")
PW = "cu-test-password-12ch"


@pytest.fixture
async def env2(pg_db: str):
    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    vault = Vault(parse_keyring(FAKE_KEYRING))
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
        if acct is None:
            acct = OperatorAccount(id=1, username="operator", password_hash=hash_password(PW))
            s.add(acct)
            await s.flush()
        acct.password_hash = hash_password(PW)
        acct.totp_enabled = False
        acct.totp_secret = None
        acct.totp_last_step_stepup = 0
        acct.totp_last_step_confirm = 0
        acct.totp_last_step_login = 0
        from sqlalchemy import delete

        await s.execute(delete(StepUpToken))
        await s.execute(delete(WebAuthnChallenge))
        await s.execute(delete(OperatorSession))
        await s.execute(delete(AuthEvent))
        await s.commit()
    yield maker, vault
    await engine.dispose()


async def _session(maker):
    from custos.operator.sessions import create_session

    async with maker() as s:
        row, cookie = await create_session(s)
        await s.commit()
        return row


async def _enable_totp(maker, vault) -> str:
    async with maker() as s:
        secret, _ = await begin_totp_setup(s, vault)
        await s.commit()
    async with maker() as s:
        await confirm_totp(s, vault, pyotp.TOTP(secret).now())
        await s.commit()
    return secret


async def test_password_only_when_totp_enabled_fails(env2) -> None:
    maker, vault = env2
    await _enable_totp(maker, vault)
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        with pytest.raises(AppError):
            await mint_step_up(s, maker, row, password=PW, vault=vault)
        await s.rollback()
    async with maker() as s:
        evs = (
            (await s.execute(select(AuthEvent).where(AuthEvent.kind == "step_up"))).scalars().all()
        )
        assert len([e for e in evs if not e.ok]) == 1


async def test_password_plus_totp_mints(env2) -> None:
    maker, vault = env2
    secret = await _enable_totp(maker, vault)
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        token = await mint_step_up(
            s, maker, row, password=PW, totp=pyotp.TOTP(secret).now(), vault=vault
        )
        await s.commit()
    assert len(token) == 43


async def test_single_use(env2) -> None:
    maker, vault = env2
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        token = await mint_step_up(s, maker, row, password=PW, vault=vault)
        await s.commit()
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        await consume_step_up(s, token, row)
        await s.commit()
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        with pytest.raises(AppError) as e:
            await consume_step_up(s, token, row)
        assert e.value.code == "step_up_required"


async def test_wrong_presenter_rejected(env2) -> None:
    maker, vault = env2
    sess = await _session(maker)
    other = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        token = await mint_step_up(s, maker, row, password=PW, vault=vault)
        await s.commit()
    async with maker() as s:
        other_row = await s.get(OperatorSession, other.id)
        with pytest.raises(AppError):
            await consume_step_up(s, token, other_row)


async def test_expired_rejected(env2) -> None:
    maker, vault = env2
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        token = await mint_step_up(s, maker, row, password=PW, vault=vault)
        await s.commit()
    async with maker() as s:
        tok = (await s.execute(select(StepUpToken))).scalar_one()
        tok.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        with pytest.raises(AppError):
            await consume_step_up(s, token, row)


async def test_recovery_alternative_consumes_one(env2) -> None:
    maker, vault = env2
    await _enable_totp(maker, vault)
    from custos.operator.recovery import issue_codes

    async with maker() as s:
        codes = await issue_codes(s, FAKE_KEYRING and bytes([7]) * 32)
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        token = await mint_step_up(
            s, maker, row, password=PW, recovery_code=codes[0], vault=vault, pepper=bytes([7]) * 32
        )
        await s.commit()
    assert token
    async with maker() as s:
        from custos.operator.recovery import consume_code

        assert not await consume_code(s, bytes([7]) * 32, codes[0])  # consumed


@pytest.fixture
def su_http(pg_db: str):
    from contextlib import asynccontextmanager


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
            acct.totp_enabled = False
            from sqlalchemy import delete

            await s.execute(delete(AuthEvent))
            await s.execute(delete(StepUpToken))
            await s.commit()
        async with app.router.lifespan_context(app):
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test")
            async with client:
                r = await client.post("/api/auth/login",
                                      json={"username": "operator", "password": PW})
                csrf = r.json()["csrf_token"]
                try:
                    yield client, maker, csrf, app
                finally:
                    await engine.dispose()

    return build


async def test_management_route_requires_step_up(su_http) -> None:
    async with su_http() as (client, maker, csrf, app):
        # totp/setup without a step-up token -> 401 step_up_required
        r = await client.post("/api/auth/totp/setup", headers={"x-csrf-token": csrf}, json={})
        assert r.status_code == 401
        assert r.json()["code"] == "step_up_required"
        # mint a step-up, then it works
        su = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                               json={"password": PW})
        token = su.json()["step_up_token"]
        r2 = await client.post("/api/auth/totp/setup",
                               headers={"x-csrf-token": csrf, "x-step-up-token": token}, json={})
        assert r2.status_code == 200
        # token is single-use: reuse -> 401
        r3 = await client.post("/api/auth/totp/setup",
                               headers={"x-csrf-token": csrf, "x-step-up-token": token}, json={})
        assert r3.status_code == 401


async def test_full_session_password_change_requires_step_up(su_http) -> None:
    async with su_http() as (client, maker, csrf, app):
        # full session: password-change without step-up -> 401
        r = await client.post("/api/auth/password-change", headers={"x-csrf-token": csrf},
                              json={"current_password": PW,
                                    "new_password": "cu-test-new-password-12ch"})
        assert r.status_code == 401
        assert r.json()["code"] == "step_up_required"
        su = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                               json={"password": PW})
        r2 = await client.post("/api/auth/password-change",
                               headers={"x-csrf-token": csrf,
                                        "x-step-up-token": su.json()["step_up_token"]},
                               json={"current_password": PW,
                                     "new_password": "cu-test-new-password-12ch"})
        assert r2.status_code == 200


async def test_step_up_lockout_blocks(su_http) -> None:
    async with su_http() as (client, maker, csrf, app):
        from custos.db.models import AuthEvent

        async with maker() as s:
            for _ in range(10):
                s.add(AuthEvent(kind="step_up", ok=False, ip="127.0.0.1",
                                peer_ip="127.0.0.1", ts=datetime.now(UTC)))
            await s.commit()
        r = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                              json={"password": PW})
        assert r.status_code == 429
        assert r.json()["code"] == "locked_out"


async def test_rekey_run_token_not_consumed_as_single(env2) -> None:
    maker, vault = env2
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        token = await mint_step_up(s, maker, row, password=PW, vault=vault, kind="rekey_run")
        await s.commit()
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        with pytest.raises(AppError):
            await consume_step_up(s, token, row)  # single-use consume rejects rekey_run


async def test_recovery_code_step_up_when_totp_disabled(env2) -> None:
    maker, vault = env2
    from custos.operator.recovery import issue_codes

    pepper = bytes([7]) * 32
    async with maker() as s:
        codes = await issue_codes(s, pepper)
        await s.commit()
    sess = await _session(maker)
    # TOTP disabled: an INVALID recovery code must still fail (not password-only)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        with pytest.raises(AppError):
            await mint_step_up(s, maker, row, password=PW, recovery_code="0000000000000000",
                               vault=vault, pepper=pepper)
        await s.rollback()
    # a VALID code mints and is consumed
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        token = await mint_step_up(s, maker, row, password=PW, recovery_code=codes[0],
                                   vault=vault, pepper=pepper)
        await s.commit()
    assert token
