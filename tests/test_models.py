"""Schema contract tests (design §4) against a real throwaway postgres."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.db.models import (
    Field,
    FieldHistory,
    Item,
    OperatorAccount,
    OperatorSession,
    StepUpToken,
)

pytestmark = pytest.mark.usefixtures("pg_db")


@pytest.fixture
async def session_maker(pg_db: str):
    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    yield maker
    await engine.dispose()


async def _mk_item(maker, name: str = "aliyun") -> Item:
    async with maker() as session:
        item = Item(name=name, notes="")
        session.add(item)
        await session.commit()
        return item


async def test_fields_check(session_maker) -> None:
    item = await _mk_item(session_maker)
    async with session_maker() as session:
        session.add(Field(item_id=item.id, name="BAD1", secret=True, value="plain-not-allowed"))
        with pytest.raises(IntegrityError):
            await session.commit()
    async with session_maker() as session:
        session.add(
            Field(item_id=item.id, name="BAD2", secret=False, ciphertext=b"x", key_version=1)
        )
        with pytest.raises(IntegrityError):
            await session.commit()
    async with session_maker() as session:
        session.add(Field(item_id=item.id, name="OK_PLAIN", secret=False, value="v"))
        session.add(
            Field(item_id=item.id, name="OK_SECRET", secret=True, ciphertext=b"c", key_version=1)
        )
        await session.commit()


async def test_history_survives_delete(session_maker) -> None:
    item = await _mk_item(session_maker, "tencent-cloud")
    field_id = uuid.uuid4()
    async with session_maker() as session:
        field = Field(id=field_id, item_id=item.id, name="KEY", secret=False, value="v")
        session.add(field)
        session.add(
            FieldHistory(
                field_id=field_id,
                item_id=item.id,
                name="KEY",
                secret=False,
                value="old",
                superseded_by="local",
                actor_label="break-glass",
            )
        )
        await session.commit()
    async with session_maker() as session:
        await session.delete(await session.get(Field, field_id))
        await session.delete(await session.get(Item, item.id))
        await session.commit()
    async with session_maker() as session:
        rows = (await session.execute(select(FieldHistory))).scalars().all()
        assert any(r.field_id == field_id for r in rows)


async def test_operator_account_single_row(session_maker) -> None:
    async with session_maker() as session:
        session.add(OperatorAccount(username="operator", password_hash="cu-test-hash"))
        await session.commit()
    async with session_maker() as session:
        session.add(OperatorAccount(id=2, username="second", password_hash="cu-test-hash"))
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_step_up_exactly_one_principal(session_maker) -> None:
    async with session_maker() as session:
        acct_session = OperatorSession(
            token_hash=b"h" * 32,
            csrf_token="cu-test-csrf",
            purpose="full",
            absolute_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.add(acct_session)
        await session.commit()
    async with session_maker() as session:
        session.add(
            StepUpToken(
                session_id=None,
                operator_token_id=None,
                nonce_hash=b"n" * 32,
                kind="single",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()
    async with session_maker() as session:
        session.add(
            StepUpToken(
                session_id=acct_session.id,
                operator_token_id=uuid.uuid4(),
                nonce_hash=b"n" * 32,
                kind="single",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_session_revoke_keeps_row(session_maker) -> None:
    async with session_maker() as session:
        acct_session = OperatorSession(
            token_hash=b"g" * 32,
            csrf_token="cu-test-csrf2",
            purpose="full",
            absolute_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.add(acct_session)
        await session.commit()
        sid = acct_session.id
    async with session_maker() as session:
        row = await session.get(OperatorSession, sid)
        row.revoked_at = datetime.now(UTC)
        await session.commit()
    async with session_maker() as session:
        assert await session.get(OperatorSession, sid) is not None


async def test_session_dependency_yields_session(pg_db: str) -> None:
    from sqlalchemy import text as sa_text

    from custos.app import create_app
    from custos.config import load_settings
    from custos.db.session import get_session
    from tests.test_config import env

    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        dep = app.dependency_overrides[get_session]
        gen = dep()
        session = await gen.__anext__()
        assert (await session.execute(sa_text("SELECT 1"))).scalar_one() == 1
        await gen.aclose()
