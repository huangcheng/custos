"""Turnstile contract (design §5): fail-closed siteverify, config matrix."""

import httpx
import pytest
from sqlalchemy import select

from custos.config import ConfigError, load_settings
from custos.errors import AppError
from custos.operator.turnstile import verify_turnstile
from tests.test_config import env

SECRET = "cu-test-turnstile-secret"
SITEKEY = "cu-test-sitekey"
HOST = "console.example"


def _settings(**extra):
    base = env(CUSTOS_TURNSTILE_SECRET=SECRET, CUSTOS_TURNSTILE_SITEKEY=SITEKEY,
               CUSTOS_TURNSTILE_HOSTNAMES=HOST)
    return load_settings({**base, **extra})


class _FakeTransport(httpx.AsyncBaseTransport):
    def __init__(self, payload: dict, *, status: int = 200, raise_exc: bool = False):
        self.payload = payload
        self.status = status
        self.raise_exc = raise_exc
        self.last_request = None

    async def handle_async_request(self, request):
        self.last_request = request
        if self.raise_exc:
            raise httpx.ConnectError("boom")
        return httpx.Response(self.status, json=self.payload)


async def _verify(payload, **kw):
    transport = _FakeTransport(payload, **kw)
    async with httpx.AsyncClient(transport=transport) as client:
        await verify_turnstile(_settings(), "token", "203.0.113.1", client=client)
    return transport


async def test_success_passes_and_binds_remoteip() -> None:
    t = await _verify({"success": True, "hostname": HOST})
    body = t.last_request.content.decode()
    assert "remoteip=203.0.113.1" in body
    assert "secret=" + SECRET in body


async def test_failure_rejected() -> None:
    with pytest.raises(AppError) as e:
        await _verify({"success": False, "error-codes": ["invalid-input-response"]})
    assert e.value.code == "turnstile_failed"


async def test_already_spent_rejected() -> None:
    with pytest.raises(AppError):
        await _verify({"success": False, "error-codes": ["timeout-or-duplicate"]})


async def test_hostname_mismatch_rejected() -> None:
    with pytest.raises(AppError):
        await _verify({"success": True, "hostname": "evil.example"})


async def test_hostname_missing_rejected() -> None:
    with pytest.raises(AppError):
        await _verify({"success": True})


async def test_transport_error_rejected() -> None:
    with pytest.raises(AppError):
        await _verify({}, raise_exc=True)


async def test_missing_token_rejected() -> None:
    async with httpx.AsyncClient(transport=_FakeTransport({"success": True})) as client:
        with pytest.raises(AppError) as e:
            await verify_turnstile(_settings(), None, "203.0.113.1", client=client)
        assert e.value.code == "turnstile_failed"


def test_config_both_or_neither() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TURNSTILE_SECRET=SECRET))  # sitekey missing
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TURNSTILE_SITEKEY=SITEKEY))  # secret missing


def test_config_hostnames_required() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TURNSTILE_SECRET=SECRET, CUSTOS_TURNSTILE_SITEKEY=SITEKEY))


def test_config_dev_conflict() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TURNSTILE_SECRET=SECRET, CUSTOS_TURNSTILE_SITEKEY=SITEKEY,
                          CUSTOS_TURNSTILE_HOSTNAMES=HOST, CUSTOS_INSECURE_DEV="1"))

@pytest.fixture
def ts_http(pg_db: str, monkeypatch):
    from contextlib import asynccontextmanager

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from custos.app import create_app
    from custos.db.models import OperatorAccount
    from custos.operator.account import hash_password

    @asynccontextmanager
    async def build():
        settings = load_settings(env(
            CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1",
            CUSTOS_TURNSTILE_SECRET=SECRET, CUSTOS_TURNSTILE_SITEKEY=SITEKEY,
            CUSTOS_TURNSTILE_HOSTNAMES=HOST))
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
            await s.commit()
        async with app.router.lifespan_context(app):
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test")
            async with client:
                try:
                    yield client, maker, app
                finally:
                    await engine.dispose()

    return build


async def test_login_turnstile_failure_before_credentials(ts_http, monkeypatch) -> None:
    from custos.db.models import AuditRow, AuthEvent
    from custos.operator import turnstile as ts_mod

    async with ts_http() as (client, maker, app):
        calls = {"verify": 0}

        async def fake_verify(settings, token, ip, **kw):
            calls["verify"] += 1
            raise AppError("turnstile_failed", "no")

        monkeypatch.setattr(ts_mod, "verify_turnstile", fake_verify)
        # route imports verify_turnstile locally; patch the module attribute it reads
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": "cu-test-password-12ch"})
        assert r.status_code == 422
        assert r.json()["code"] == "turnstile_failed"
        async with maker() as s:
            # no credential auth_event (turnstile is audit-only)
            evs = (await s.execute(select(AuthEvent).where(
                AuthEvent.kind == "login_password"))).scalars().all()
            assert not evs
            audits = (await s.execute(select(AuditRow).where(
                AuditRow.action == "auth.failure"))).scalars().all()
            assert any(a.detail.get("reason") == "turnstile" for a in audits)


def test_hostnames_empty_after_parse_rejected() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TURNSTILE_SECRET=SECRET, CUSTOS_TURNSTILE_SITEKEY=SITEKEY,
                          CUSTOS_TURNSTILE_HOSTNAMES=" , "))


def test_hostnames_scheme_rejected() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TURNSTILE_SECRET=SECRET, CUSTOS_TURNSTILE_SITEKEY=SITEKEY,
                          CUSTOS_TURNSTILE_HOSTNAMES="https://console.example"))
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TURNSTILE_SECRET=SECRET, CUSTOS_TURNSTILE_SITEKEY=SITEKEY,
                          CUSTOS_TURNSTILE_HOSTNAMES="console.example:443"))


async def test_non_object_payload_rejected() -> None:
    with pytest.raises(AppError):
        await _verify([1, 2, 3])  # JSON list, not object
    with pytest.raises(AppError):
        await _verify(None)


async def test_truthy_non_bool_success_rejected() -> None:
    # Spec §5: success:false rejects — require the literal boolean, not truthiness.
    for fake in ("true", 1, "yes", [True]):
        with pytest.raises(AppError):
            await _verify({"success": fake, "hostname": HOST})


async def test_non_2xx_rejected() -> None:
    for status in (400, 500, 503):
        with pytest.raises(AppError):
            await _verify({"success": True, "hostname": HOST}, status=status)


async def test_overlong_token_rejected_before_siteverify() -> None:
    transport = _FakeTransport({"success": True, "hostname": HOST})
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(AppError):
            await verify_turnstile(_settings(), "x" * 2049, "203.0.113.1", client=client)
    assert transport.last_request is None  # never sent to Cloudflare


async def test_non_string_turnstile_token_422(ts_http) -> None:
    async with ts_http() as (client, maker, app):
        r = await client.post("/api/auth/login", json={
            "username": "operator", "password": "cu-test-password-12ch",
            "turnstile": {"nested": "object"}})
        assert r.status_code == 422
