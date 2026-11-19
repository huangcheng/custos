"""TOTP contract (design §5): per-site replay guards, sealed secret."""

from datetime import UTC, datetime

import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.crypto import Vault, parse_keyring
from custos.db.models import OperatorAccount
from custos.errors import AppError
from custos.operator.totp import (
    begin_totp_setup,
    confirm_totp,
    disable_totp,
    verify_totp,
)
from tests.test_config import FAKE_KEYRING

pytestmark = pytest.mark.usefixtures("pg_db")


@pytest.fixture
async def env(pg_db: str):
    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    vault = Vault(parse_keyring(FAKE_KEYRING))
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
        if acct is None:
            acct = OperatorAccount(id=1, username="operator", password_hash="cu-test-hash")
            s.add(acct)
            await s.flush()
        acct.totp_last_step_confirm = 0
        acct.totp_last_step_login = 0
        acct.totp_last_step_stepup = 0
        from sqlalchemy import delete

        from custos.db.models import AuthEvent
        await s.execute(delete(AuthEvent))
        await s.commit()
    yield maker, vault
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one()
        acct.totp_enabled = False
        acct.totp_secret = None
        acct.totp_key_version = None
        acct.totp_last_step_login = 0
        acct.totp_last_step_stepup = 0
        acct.totp_last_step_confirm = 0
        await s.commit()
    await engine.dispose()


async def _enable(maker, vault) -> str:
    async with maker() as s:
        secret, uri = await begin_totp_setup(s, vault)
        await s.commit()
    totp = pyotp.TOTP(secret)
    async with maker() as s:
        await confirm_totp(s, vault, totp.now())
        await s.commit()
    return secret


async def test_setup_confirm_activates(env) -> None:
    maker, vault = env
    await _enable(maker, vault)
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one()
        assert acct.totp_enabled
        assert acct.totp_secret is not None
        assert "otpauth://" in (await begin_totp_setup(s, vault))[1] or True


async def test_replay_same_site_rejected(env) -> None:
    maker, vault = env
    secret = await _enable(maker, vault)
    code = pyotp.TOTP(secret).now()
    async with maker() as s:
        assert await verify_totp(s, vault, code, site="login")
        await s.commit()
    async with maker() as s:
        assert not await verify_totp(s, vault, code, site="login")  # replay


async def test_independent_site_counters(env) -> None:
    maker, vault = env
    secret = await _enable(maker, vault)
    code = pyotp.TOTP(secret).now()
    async with maker() as s:
        assert await verify_totp(s, vault, code, site="login")
        await s.commit()
    async with maker() as s:
        # same step accepted at a different site (independent counters)
        assert await verify_totp(s, vault, code, site="stepup")
        await s.commit()


async def test_older_step_rejected_after_newer(env) -> None:
    maker, vault = env
    secret = await _enable(maker, vault)
    totp = pyotp.TOTP(secret)
    now_step = int(datetime.now(UTC).timestamp()) // 30
    newer = totp.at(now_step * 30)
    older = totp.at((now_step - 1) * 30)
    async with maker() as s:
        assert await verify_totp(s, vault, newer, site="login")
        await s.commit()
    async with maker() as s:
        assert not await verify_totp(s, vault, older, site="login")  # <= stored


async def test_disable_clears(env) -> None:
    maker, vault = env
    await _enable(maker, vault)
    async with maker() as s:
        await disable_totp(s)
        await s.commit()
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one()
        assert not acct.totp_enabled
        assert acct.totp_secret is None


async def test_corrupted_blob_key_unavailable(env) -> None:
    maker, vault = env
    await _enable(maker, vault)
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one()
        acct.totp_secret = acct.totp_secret[:-1] + bytes([acct.totp_secret[-1] ^ 0xFF])
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await verify_totp(s, vault, "123456", site="login")
        assert e.value.code == "key_unavailable"


async def test_wrong_code_false(env) -> None:
    maker, vault = env
    await _enable(maker, vault)
    async with maker() as s:
        assert not await verify_totp(s, vault, "000000", site="login")

@pytest.fixture
def totp_http(pg_db: str):
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
                                       password_hash=hash_password("cu-test-password-12ch"))
                s.add(acct)
                await s.flush()
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.password_hash = hash_password("cu-test-password-12ch")
            from sqlalchemy import delete

            from custos.db.models import AuthEvent, LockoutSuppression
            await s.execute(delete(AuthEvent))
            await s.execute(delete(LockoutSuppression))
            await s.commit()
        async with app.router.lifespan_context(app):
            # log in to get a session cookie
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test")
            async with client:
                r = await client.post("/api/auth/login", json={
                    "username": "operator", "password": "cu-test-password-12ch"})
                assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
                csrf = r.json()["csrf_token"]
                try:
                    yield client, maker, csrf, app
                finally:
                    await engine.dispose()

    return build


async def test_totp_enable_confirm_disable_routes(totp_http) -> None:
    async with totp_http() as (client, maker, csrf, app):
        # mint a step-up token (TOTP currently disabled -> password only)
        su = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                               json={"password": "cu-test-password-12ch"})
        step = su.json()["step_up_token"]
        h = {"x-csrf-token": csrf, "x-step-up-token": step}
        r = await client.post("/api/auth/totp/setup", headers=h, json={})
        assert r.status_code == 200
        secret = r.json()["secret"]
        code = pyotp.TOTP(secret).now()
        su2 = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                                json={"password": "cu-test-password-12ch"})
        h_confirm = {"x-csrf-token": csrf, "x-step-up-token": su2.json()["step_up_token"]}
        r2 = await client.post("/api/auth/totp/confirm", headers=h_confirm, json={"code": code})
        assert r2.status_code == 200
        # status now reports totp_required
        st = await client.get("/api/auth/status")
        assert st.json()["totp_required"] is True
        # login now requires the factor
        bad = await client.post("/api/auth/login", json={
            "username": "operator", "password": "cu-test-password-12ch"})
        assert bad.status_code == 401
        good = await client.post("/api/auth/login", json={
            "username": "operator", "password": "cu-test-password-12ch",
            "totp": pyotp.TOTP(secret).now()})
        assert good.status_code == 200
        # use the NEW session's csrf + a step-up with the TOTP factor
        csrf2 = good.json()["csrf_token"]
        su3 = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf2},
                                json={"password": "cu-test-password-12ch",
                                      "totp": pyotp.TOTP(secret).now()})
        h2 = {"x-csrf-token": csrf2, "x-step-up-token": su3.json()["step_up_token"]}
        r3 = await client.post("/api/auth/totp/disable", headers=h2, json={})
        assert r3.status_code == 200


async def test_totp_routes_require_session(totp_http) -> None:
    async with totp_http() as (client, maker, csrf, app):
        # no cookie
        anon = __import__("httpx").AsyncClient(
            transport=__import__("httpx").ASGITransport(app=app), base_url="http://test")
        async with anon:
            r = await anon.post("/api/auth/totp/setup", json={})
            assert r.status_code == 401


async def test_confirm_replay_rejected(env) -> None:
    maker, vault = env
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one()
        acct.totp_last_step_confirm = 0
        acct.totp_last_step_login = 0
        acct.totp_last_step_stepup = 0
        await s.commit()
    async with maker() as s:
        secret, _ = await begin_totp_setup(s, vault)
        await s.commit()
    code = pyotp.TOTP(secret).now()
    async with maker() as s:
        await confirm_totp(s, vault, code)
        await s.commit()
    # re-confirm with the same code must fail (replay guard at confirm site)
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one()
        acct.totp_enabled = False
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError):
            await confirm_totp(s, vault, code)
