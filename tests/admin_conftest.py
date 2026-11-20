"""Shared admin-plane test fixture (plan 3). The TEST BODY owns the app
lifespan; helpers do real setup/login/step-up over HTTP where possible.
Shared session-scoped DB: teardown clears auth state in FK-safe order."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.app import create_app
from custos.config import load_settings
from custos.db.models import (
    AuditRow,
    AuthEvent,
    DeviceCode,
    LockoutSuppression,
    OperatorAccount,
    OperatorSession,
    OperatorToken,
    StepUpToken,
    WebAuthnChallenge,
)
from custos.operator.account import hash_password
from custos.operator_tokens import mint_operator_token
from tests.test_config import env

PW = "cu-test-password-12ch"


@pytest.fixture
def admin_stack(pg_db: str):
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
                s.add(OperatorAccount(id=1, username="operator",
                                      password_hash=hash_password(PW)))
            else:
                acct.password_hash = hash_password(PW)
                acct.totp_enabled = False
                acct.totp_last_step_login = 0
                acct.totp_last_step_stepup = 0
                acct.totp_last_step_confirm = 0
            await s.commit()

        async def login(client: httpx.AsyncClient) -> str:
            r = await client.post("/api/auth/login",
                                  json={"username": "operator", "password": PW})
            assert r.status_code == 200, r.text
            return r.json()["csrf_token"]

        async def step_up(client: httpx.AsyncClient, csrf: str) -> str:
            r = await client.post("/api/auth/step-up",
                                  json={"password": PW},
                                  headers={"x-csrf-token": csrf})
            assert r.status_code == 200, r.text
            return r.json()["step_up_token"]

        async def mint_co(*, allow_sensitive: bool = False, days: int = 30) -> str:
            token, draft = mint_operator_token(
                settings.pepper_raw,
                expires_at=datetime.now(UTC) + timedelta(days=days),
                allow_sensitive=allow_sensitive,
            )
            async with maker() as s:
                s.add(OperatorToken(key_id=draft.key_id, digest=draft.digest,
                                    label="cu-test-co", allow_sensitive=allow_sensitive,
                                    expires_at=draft.expires_at))
                await s.commit()
            return token

        async with app.router.lifespan_context(app):
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test")
            async with client:
                try:
                    yield client, maker, {
                        "login": login, "step_up": step_up, "mint_co": mint_co,
                        "settings": settings, "app": app, "password": PW,
                    }
                finally:
                    async with maker() as s:
                        await s.execute(delete(StepUpToken))
                        await s.execute(delete(WebAuthnChallenge))
                        await s.execute(delete(DeviceCode))
                        await s.execute(delete(OperatorSession))
                        await s.execute(delete(OperatorToken))
                        await s.execute(delete(AuthEvent))
                        await s.execute(delete(LockoutSuppression))
                        await s.execute(delete(AuditRow))
                        await s.commit()
                    await engine.dispose()

    return build


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
