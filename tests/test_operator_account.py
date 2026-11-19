"""Operator account + one-shot setup contract (design §5). Fake values only."""

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.app import create_app
from custos.config import ConfigError, load_settings
from custos.db.models import AuthEvent, OperatorAccount
from custos.errors import AppError
from custos.operator.account import hash_password, validate_password, verify_password
from tests.test_config import env

pytestmark = pytest.mark.usefixtures("pg_db")

FAKE_CODE = "cu-test-setup-code-0123456789abcdef"  # obviously fake


def test_phc_parameters_pinned() -> None:
    phc = hash_password("cu-test-password-12ch")
    assert phc.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_hash_verify_roundtrip() -> None:
    phc = hash_password("cu-test-password-12ch")
    assert verify_password(phc, "cu-test-password-12ch")
    assert not verify_password(phc, "wrong-password-12ch")
    assert not verify_password(phc, "")


def test_password_policy() -> None:
    validate_password("x" * 12)
    with pytest.raises(AppError) as e:
        validate_password("x" * 11)
    assert e.value.code == "invalid"


@pytest.fixture
def stack(pg_db: str, tmp_path):
    from contextlib import asynccontextmanager

    data_dir = tmp_path / "data"
    data_dir.mkdir()

    @asynccontextmanager
    async def build(extra: dict | None = None):
        base = env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1",
                   CUSTOS_DATA_DIR=str(data_dir), CUSTOS_SETUP_CODE=FAKE_CODE)
        settings = load_settings({**base, **(extra or {})})
        app = create_app(settings)
        engine = create_async_engine(pg_db)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with app.router.lifespan_context(app):
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            )
            async with client:
                try:
                    yield client, maker, data_dir
                finally:
                    await engine.dispose()
                    # cleanup account for reruns
                    async with maker() as s:
                        acct = (
                            await s.execute(select(OperatorAccount))
                        ).scalar_one_or_none()
                        if acct is not None:
                            await s.delete(acct)
                        # setup auth-events are per-run; clear to keep tests order-free
                        evs = (
                            await s.execute(select(AuthEvent).where(AuthEvent.kind == "setup"))
                        ).scalars().all()
                        for ev in evs:
                            await s.delete(ev)
                        await s.commit()

    return build


async def test_setup_success_and_single_shot(stack) -> None:
    async with stack() as (client, maker, data_dir):
        r = await client.post("/api/auth/setup", json={
            "username": "operator", "password": "cu-test-password-12ch",
            "setup_code": FAKE_CODE,
        })
        assert r.status_code == 200
        async with maker() as s:
            acct = (await s.execute(select(OperatorAccount))).scalar_one()
            assert acct.username == "operator"
            assert verify_password(acct.password_hash, "cu-test-password-12ch")
        r2 = await client.post("/api/auth/setup", json={
            "username": "second", "password": "cu-test-password-12ch",
            "setup_code": FAKE_CODE,
        })
        assert r2.status_code == 403
        assert r2.json()["code"] == "setup_complete"


async def test_setup_wrong_code_uniform_401_and_ledger(stack) -> None:
    async with stack() as (client, maker, data_dir):
        r = await client.post("/api/auth/setup", json={
            "username": "operator", "password": "cu-test-password-12ch",
            "setup_code": "wrong-code",
        })
        assert r.status_code == 401
        async with maker() as s:
            rows = (
                (await s.execute(select(AuthEvent).where(AuthEvent.kind == "setup")))
                .scalars().all()
            )
            assert len([x for x in rows if not x.ok]) == 1


async def test_setup_short_password_422(stack) -> None:
    async with stack() as (client, maker, data_dir):
        r = await client.post("/api/auth/setup", json={
            "username": "operator", "password": "short", "setup_code": FAKE_CODE,
        })
        assert r.status_code == 422


async def test_setup_body_and_env_password_conflict(stack) -> None:
    async with stack({"CUSTOS_OPERATOR_PASSWORD": "cu-test-bootstrap-12ch"}) as (
        client, maker, data_dir
    ):
        r = await client.post("/api/auth/setup", json={
            "username": "operator", "password": "cu-test-password-12ch",
            "setup_code": FAKE_CODE,
        })
        assert r.status_code == 422
        # env-only works
        r2 = await client.post("/api/auth/setup", json={
            "username": "operator", "setup_code": FAKE_CODE,
        })
        assert r2.status_code == 200


async def test_setup_both_absent_422(stack) -> None:
    async with stack() as (client, maker, data_dir):
        r = await client.post("/api/auth/setup", json={
            "username": "operator", "setup_code": FAKE_CODE,
        })
        assert r.status_code == 422


def test_bootstrap_password_policy_at_startup() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_OPERATOR_PASSWORD="short"))


def test_generated_code_file_lifecycle(pg_db: str, tmp_path) -> None:

    from custos.operator.account import ensure_setup_code

    data_dir = tmp_path / "gen"
    data_dir.mkdir()
    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db,
                                 CUSTOS_DATA_DIR=str(data_dir)))
    code1 = ensure_setup_code(settings)
    assert len(code1) >= 22
    f = data_dir / "setup-code"
    assert f.exists()
    assert (f.stat().st_mode & 0o777) == 0o600
    code2 = ensure_setup_code(settings)  # restart reuses
    assert code1 == code2


def test_empty_setup_code_file_rejected(pg_db: str, tmp_path) -> None:
    from custos.operator.account import ensure_setup_code

    data_dir = tmp_path / "empty"
    data_dir.mkdir()
    (data_dir / "setup-code").write_text("  \n")
    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db,
                                 CUSTOS_DATA_DIR=str(data_dir)))
    with pytest.raises(ConfigError):
        ensure_setup_code(settings)


async def test_post_setup_requests_never_recreate_code_file(stack) -> None:
    async with stack({"CUSTOS_SETUP_CODE": ""}) as (client, maker, data_dir):
        # startup provisions the file; complete setup consumes it
        code = (data_dir / "setup-code").read_text().strip()
        r = await client.post("/api/auth/setup", json={
            "username": "operator", "password": "cu-test-password-12ch",
            "setup_code": code,
        })
        assert r.status_code == 200
        assert not (data_dir / "setup-code").exists()
        r2 = await client.post("/api/auth/setup", json={
            "username": "x", "password": "cu-test-password-12ch", "setup_code": "x",
        })
        assert r2.status_code == 403
        assert not (data_dir / "setup-code").exists()  # never recreated


async def test_surrogate_setup_code_422(stack) -> None:
    async with stack() as (client, maker, data_dir):
        raw = (
            b'{"username":"operator","password":"cu-test-password-12ch",'
            b'"setup_code":"\\ud800"}'
        )
        r = await client.post("/api/auth/setup", content=raw,
                              headers={"content-type": "application/json"})
        assert r.status_code in (401, 422)  # never 500
