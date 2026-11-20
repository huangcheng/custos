"""Operator-token credentials (design §5): co- format, uniform failures,
mandatory expiry caps (90 d plain / 30 d allow_sensitive)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.config import load_settings
from custos.db.models import OperatorToken
from custos.errors import AppError
from custos.keys import mint_agent_key
from custos.operator_tokens import (
    OperatorAuthError,
    mint_operator_token,
    validate_expiry,
    verify_operator_token,
)
from tests.test_config import env

pytestmark = pytest.mark.usefixtures("pg_db")


@pytest.fixture
async def db(pg_db: str):
    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db))
    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield maker, settings.pepper_raw
    finally:
        await engine.dispose()


async def _store(maker, draft, **kw) -> OperatorToken:
    expires = kw.get("expires_at")
    if expires is None:
        expires = getattr(draft, "expires_at", None) or datetime.now(UTC) + timedelta(days=30)
    row = OperatorToken(
        key_id=draft.key_id,
        digest=draft.digest,
        label="cu-test",
        expires_at=expires,
        allow_sensitive=kw.get("allow_sensitive", getattr(draft, "allow_sensitive", False)),
        revoked_at=kw.get("revoked_at"),
    )
    async with maker() as s:
        s.add(row)
        await s.commit()
    return row


def _mint(pepper: bytes, **kw):
    kw.setdefault("expires_at", datetime.now(UTC) + timedelta(days=30))
    return mint_operator_token(pepper, **kw)


async def test_mint_verify_roundtrip(db) -> None:
    maker, pepper = db
    token, draft = _mint(pepper)
    assert token.startswith("co-")
    assert len(token.split(".")[1]) == 43
    await _store(maker, draft)
    async with maker() as s:
        row = await verify_operator_token(s, pepper, token)
    assert row.key_id == draft.key_id


async def test_wrong_secret_revoked_expired_unknown_all_raise_same(db) -> None:
    maker, pepper = db
    now = datetime.now(UTC)
    good, good_draft = _mint(pepper)
    await _store(maker, good_draft)
    revoked, revoked_draft = _mint(pepper)
    await _store(maker, revoked_draft, revoked_at=now)
    expired, expired_draft = _mint(pepper, expires_at=now + timedelta(days=1))
    await _store(maker, expired_draft, expires_at=now - timedelta(seconds=1))
    unknown, _ = _mint(pepper)
    bad_secret = good[:-1] + ("A" if good[-1] != "A" else "B")
    for presented in (bad_secret, revoked, expired, unknown, "garbage", ""):
        async with maker() as s:
            with pytest.raises(OperatorAuthError):
                await verify_operator_token(s, pepper, presented)


async def test_agent_key_never_verifies_as_operator_token(db) -> None:
    maker, pepper = db
    agent_token, agent_draft = mint_agent_key(pepper)
    # even with the same key_id/digest stored, the cu- prefix must fail
    await _store(
        maker,
        agent_draft,
        expires_at=datetime.now(UTC) + timedelta(days=30),
        allow_sensitive=False,
    )
    async with maker() as s:
        with pytest.raises(OperatorAuthError):
            await verify_operator_token(s, pepper, agent_token)


def test_expiry_caps() -> None:
    now = datetime.now(UTC)
    pepper = bytes(range(32))
    with pytest.raises(AppError):
        validate_expiry(None, False, now)
    with pytest.raises(AppError):
        validate_expiry(now - timedelta(seconds=1), False, now)
    with pytest.raises(AppError):
        validate_expiry(now + timedelta(days=91), False, now)
    validate_expiry(now + timedelta(days=90), False, now)
    with pytest.raises(AppError):
        validate_expiry(now + timedelta(days=31), True, now)
    validate_expiry(now + timedelta(days=30), True, now)
    # the cap is enforced at mint itself — no caller can bypass it
    with pytest.raises(AppError):
        mint_operator_token(pepper, expires_at=None)
    with pytest.raises(AppError):
        mint_operator_token(pepper, expires_at=now + timedelta(days=91), now=now)
    with pytest.raises(AppError):
        mint_operator_token(
            pepper, expires_at=now + timedelta(days=31), allow_sensitive=True, now=now
        )
    _, draft = mint_operator_token(
        pepper, expires_at=now + timedelta(days=30), allow_sensitive=True, now=now
    )
    assert draft.allow_sensitive is True
    # a naive injected clock is a 422, never a TypeError-driven 500
    with pytest.raises(AppError):
        mint_operator_token(
            pepper,
            expires_at=now + timedelta(days=1),
            now=datetime(2026, 1, 1),  # noqa: DTZ001 — naive on purpose
        )
