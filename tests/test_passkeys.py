"""Passkey contract (design §5) using a soft ES256 authenticator."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.config import load_settings
from custos.db.models import OperatorAccount, PasskeyCredential, WebAuthnChallenge
from custos.errors import AppError
from custos.operator import passkeys
from custos.operator.account import hash_password
from tests.soft_authenticator import SoftAuthenticator
from tests.test_config import env

pytestmark = pytest.mark.usefixtures("pg_db")


@pytest.fixture
async def env3(pg_db: str):
    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_INSECURE_DEV="1",
                                 CUSTOS_WEBAUTHN_RP_ID="localhost"))
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
        if acct is None:
            acct = OperatorAccount(id=1, username="operator",
                                   password_hash=hash_password("cu-test-password-12ch"))
            s.add(acct)
            await s.flush()
        from sqlalchemy import delete

        await s.execute(delete(PasskeyCredential))
        await s.execute(delete(WebAuthnChallenge))
        await s.commit()
    yield maker, settings
    await engine.dispose()


async def _register(maker, settings, auth: SoftAuthenticator) -> None:
    async with maker() as s:
        opts = await passkeys.registration_options(s, settings, None)
        await s.commit()
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    challenge = base64url_to_bytes(opts["challenge"])
    cred = auth.register(challenge)
    async with maker() as s:
        await passkeys.register_verify(s, settings, None, cred)
        await s.commit()


async def test_register_and_assert(env3) -> None:
    maker, settings = env3
    auth = SoftAuthenticator()
    await _register(maker, settings, auth)
    async with maker() as s:
        opts = await passkeys.assertion_options(s, settings)
        await s.commit()
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    challenge = base64url_to_bytes(opts["challenge"])
    assertion = auth.authenticate(challenge)
    async with maker() as s:
        row = await passkeys.assertion_verify(s, settings, assertion)
        await s.commit()
        assert row.sign_count == 1


async def test_challenge_replay_rejected(env3) -> None:
    maker, settings = env3
    auth = SoftAuthenticator()
    await _register(maker, settings, auth)
    async with maker() as s:
        opts = await passkeys.assertion_options(s, settings)
        await s.commit()
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    challenge = base64url_to_bytes(opts["challenge"])
    assertion = auth.authenticate(challenge)
    async with maker() as s:
        await passkeys.assertion_verify(s, settings, assertion)
        await s.commit()
    # replay the same assertion (challenge consumed)
    async with maker() as s:
        with pytest.raises(AppError):
            await passkeys.assertion_verify(s, settings, assertion)


async def test_counter_zero_accepted_twice(env3) -> None:
    maker, settings = env3
    auth = SoftAuthenticator()
    await _register(maker, settings, auth)
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    for _ in range(2):
        async with maker() as s:
            opts = await passkeys.assertion_options(s, settings)
            await s.commit()
        assertion = auth.authenticate(base64url_to_bytes(opts["challenge"]), sign_count=0)
        async with maker() as s:
            await passkeys.assertion_verify(s, settings, assertion)
            await s.commit()


async def test_sign_count_rollback_rejected(env3) -> None:
    maker, settings = env3
    auth = SoftAuthenticator()
    await _register(maker, settings, auth)
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    async with maker() as s:
        opts = await passkeys.assertion_options(s, settings)
        await s.commit()
    a1 = auth.authenticate(base64url_to_bytes(opts["challenge"]), sign_count=5)
    async with maker() as s:
        await passkeys.assertion_verify(s, settings, a1)
        await s.commit()
    async with maker() as s:
        opts2 = await passkeys.assertion_options(s, settings)
        await s.commit()
    a2 = auth.authenticate(base64url_to_bytes(opts2["challenge"]), sign_count=3)
    async with maker() as s:
        with pytest.raises(AppError):
            await passkeys.assertion_verify(s, settings, a2)


async def test_uv_missing_rejected(env3) -> None:
    maker, settings = env3
    auth = SoftAuthenticator()
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    async with maker() as s:
        opts = await passkeys.registration_options(s, settings, None)
        await s.commit()
    cred = auth.register(base64url_to_bytes(opts["challenge"]), uv=False)
    async with maker() as s:
        with pytest.raises(AppError):
            await passkeys.register_verify(s, settings, None, cred)


async def test_expired_challenge_rejected(env3) -> None:
    maker, settings = env3
    auth = SoftAuthenticator()
    async with maker() as s:
        opts = await passkeys.registration_options(s, settings, None)
        await s.commit()
    async with maker() as s:
        ch = (await s.execute(select(WebAuthnChallenge))).scalar_one()
        ch.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    cred = auth.register(base64url_to_bytes(opts["challenge"]))
    async with maker() as s:
        with pytest.raises(AppError):
            await passkeys.register_verify(s, settings, None, cred)


@pytest.fixture
def pk_http(pg_db: str):
    from contextlib import asynccontextmanager

    import httpx

    from custos.app import create_app

    @asynccontextmanager
    async def build():
        settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1",
                                     CUSTOS_INSECURE_DEV="1", CUSTOS_WEBAUTHN_RP_ID="localhost"))
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
            acct.password_hash = hash_password("cu-test-password-12ch")
            acct.totp_enabled = False
            from sqlalchemy import delete

            from custos.db.models import AuthEvent
            await s.execute(delete(AuthEvent))
            await s.execute(delete(PasskeyCredential))
            await s.execute(delete(WebAuthnChallenge))
            await s.commit()
        async with app.router.lifespan_context(app):
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test")
            async with client:
                r = await client.post("/api/auth/login", json={
                    "username": "operator", "password": "cu-test-password-12ch"})
                csrf = r.json()["csrf_token"]
                try:
                    yield client, maker, csrf, app
                finally:
                    await engine.dispose()

    return build


async def test_passkey_register_and_login_http(pk_http) -> None:
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    async with pk_http() as (client, maker, csrf, app):
        su = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                               json={"password": "cu-test-password-12ch"})
        h = {"x-csrf-token": csrf, "x-step-up-token": su.json()["step_up_token"]}
        opts = (await client.post("/api/auth/passkeys/register/options", headers=h, json={})).json()
        auth = SoftAuthenticator()
        cred = auth.register(base64url_to_bytes(opts["challenge"]))
        # register/verify needs its own step-up (single-use)
        su2 = await client.post("/api/auth/step-up", headers={"x-csrf-token": csrf},
                                json={"password": "cu-test-password-12ch"})
        h2 = {"x-csrf-token": csrf, "x-step-up-token": su2.json()["step_up_token"]}
        r = await client.post("/api/auth/passkeys/register/verify", headers=h2, json=cred)
        assert r.status_code == 200
        # assertion login (no session needed)
        ao = (await client.post("/api/auth/passkeys/assert/options", json={})).json()
        assertion = auth.authenticate(base64url_to_bytes(ao["challenge"]))
        r2 = await client.post("/api/auth/passkeys/assert/verify", json=assertion)
        assert r2.status_code == 200
        assert "csrf_token" in r2.json()
        assert "custos_session" in client.cookies


async def test_passkeys_disabled_404(pg_db: str) -> None:
    import httpx

    from custos.app import create_app

    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))
    app = create_app(settings)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/auth/passkeys/assert/options", json={})
        assert r.status_code == 404
        st = await c.get("/api/auth/status")
        assert st.json()["passkey_available"] is False


async def test_status_passkey_flags_follow_registration(env3) -> None:
    """Login option needs a registered credential; management needs config."""
    import dataclasses

    import httpx

    from custos.app import create_app

    maker, settings = env3
    settings = dataclasses.replace(settings, skip_migrate=True)
    app = create_app(settings)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        st = (await c.get("/api/auth/status")).json()
        assert st["passkey_configured"] is True
        assert st["passkey_available"] is False  # configured, nothing registered
        await _register(maker, settings, SoftAuthenticator())
        st = (await c.get("/api/auth/status")).json()
        assert st["passkey_available"] is True


async def test_sign_count_never_decreases(env3) -> None:
    maker, settings = env3
    auth = SoftAuthenticator()
    await _register(maker, settings, auth)
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    async with maker() as s:
        opts = await passkeys.assertion_options(s, settings)
        await s.commit()
    a1 = auth.authenticate(base64url_to_bytes(opts["challenge"]), sign_count=5)
    async with maker() as s:
        await passkeys.assertion_verify(s, settings, a1)
        await s.commit()
    # counter-0 assertion accepted but must NOT erase the high-water mark
    async with maker() as s:
        opts2 = await passkeys.assertion_options(s, settings)
        await s.commit()
    a2 = auth.authenticate(base64url_to_bytes(opts2["challenge"]), sign_count=0)
    async with maker() as s:
        await passkeys.assertion_verify(s, settings, a2)
        await s.commit()
    async with maker() as s:
        row = (await s.execute(select(PasskeyCredential))).scalar_one()
        assert row.sign_count == 5  # preserved


async def test_malformed_credential_422(env3) -> None:
    maker, settings = env3
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await passkeys.assertion_verify(s, settings, {"id": "!!!"})
        assert e.value.code in ("invalid", "unauthorized")


async def test_passkey_assert_failure_ledgered(pk_http) -> None:
    from custos.db.models import AuthEvent

    async with pk_http() as (client, maker, csrf, app):
        ao = (await client.post("/api/auth/passkeys/assert/options", json={})).json()
        from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

        auth = SoftAuthenticator()  # unregistered credential
        assertion = auth.authenticate(base64url_to_bytes(ao["challenge"]))
        r = await client.post("/api/auth/passkeys/assert/verify", json=assertion)
        assert r.status_code == 401
        async with maker() as s:
            evs = (await s.execute(select(AuthEvent).where(
                AuthEvent.kind == "login_passkey"))).scalars().all()
            assert len([e for e in evs if not e.ok]) == 1
