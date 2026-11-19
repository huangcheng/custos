"""Device hand-off contract (design §5): mint/lookup/approve/exchange."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.db.models import AuthEvent, DeviceCode, OperatorAccount, OperatorSession
from custos.errors import AppError
from custos.operator.account import hash_password
from custos.operator.device import approve_device, exchange_device, lookup_device, mint_device
from custos.operator.sessions import create_session

pytestmark = pytest.mark.usefixtures("pg_db")
PW = "cu-test-password-12ch"


@pytest.fixture
async def env4(pg_db: str):
    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        acct = (await s.execute(select(OperatorAccount))).scalar_one_or_none()
        if acct is None:
            acct = OperatorAccount(id=1, username="operator", password_hash=hash_password(PW))
            s.add(acct)
            await s.flush()
        from sqlalchemy import delete

        await s.execute(delete(DeviceCode))
        await s.execute(delete(OperatorSession))
        await s.execute(delete(AuthEvent))
        await s.commit()
    yield maker
    await engine.dispose()


async def _session(maker):
    async with maker() as s:
        row, cookie = await create_session(s)
        await s.commit()
        return row


async def test_mint_lookup_approve_exchange(env4) -> None:
    maker = env4
    async with maker() as s:
        code, expires = await mint_device(s, ip="203.0.113.1", user_agent="cu-test-cli")
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        info = await lookup_device(s, code)
        assert info["client_ip"] == "203.0.113.1"
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        transfer = await approve_device(s, row, code)
        await s.commit()
    async with maker() as s:
        sess_row, cookie = await exchange_device(s, maker, code, transfer)
        await s.commit()
    assert sess_row.idle_ttl_seconds == 3600  # shortened
    assert cookie


async def test_reapprove_rejected(env4) -> None:
    maker = env4
    async with maker() as s:
        code, _ = await mint_device(s, ip="203.0.113.2", user_agent="cli")
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        await approve_device(s, row, code)
        await s.commit()
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        with pytest.raises(AppError) as e:
            await approve_device(s, row, code)
        assert e.value.code == "conflict"


async def test_exchange_attempt_cap(env4) -> None:
    maker = env4
    async with maker() as s:
        code, _ = await mint_device(s, ip="203.0.113.3", user_agent="cli")
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        transfer = await approve_device(s, row, code)
        await s.commit()
    for _ in range(5):
        async with maker() as s:
            with pytest.raises(AppError):
                await exchange_device(s, maker, code, "wrong-transfer-code")
            await s.commit()
    # 6th attempt: row dead even with the correct code
    async with maker() as s:
        with pytest.raises(AppError):
            await exchange_device(s, maker, code, transfer)


async def test_expired_device_rejected(env4) -> None:
    maker = env4
    async with maker() as s:
        code, _ = await mint_device(s, ip="203.0.113.4", user_agent="cli")
        await s.commit()
    async with maker() as s:
        dc = (await s.execute(select(DeviceCode))).scalar_one()
        dc.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        with pytest.raises(AppError):
            await approve_device(s, row, code)


async def test_flood_cap_live_rows(env4) -> None:
    maker = env4
    for _i in range(5):
        async with maker() as s:
            await mint_device(s, ip="203.0.113.5", user_agent="cli")
            await s.commit()
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await mint_device(s, ip="203.0.113.5", user_agent="cli")
        assert e.value.code == "rate_limited"


async def test_cross_row_codes_rejected(env4) -> None:
    maker = env4
    async with maker() as s:
        code_a, _ = await mint_device(s, ip="203.0.113.6", user_agent="cli")
        code_b, _ = await mint_device(s, ip="203.0.113.6", user_agent="cli")
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        transfer_b = await approve_device(s, row, code_b)
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError):
            await exchange_device(s, maker, code_a, transfer_b)


async def test_correct_after_four_wrong_then_dead(env4) -> None:
    maker = env4
    async with maker() as s:
        code, _ = await mint_device(s, ip="203.0.113.9", user_agent="cli")
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        transfer = await approve_device(s, row, code)
        await s.commit()
    for _ in range(4):
        async with maker() as s:
            with pytest.raises(AppError):
                await exchange_device(s, maker, code, "wrong")
            await s.commit()
    # 5th attempt with the CORRECT code succeeds (attempts becomes 5)
    async with maker() as s:
        sess_row, cookie = await exchange_device(s, maker, code, transfer)
        await s.commit()
    assert cookie


async def test_wrong_attempt_burns_try_without_caller_commit(env4) -> None:
    maker = env4
    async with maker() as s:
        code, _ = await mint_device(s, ip="203.0.113.20", user_agent="cli")
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        await approve_device(s, row, code)
        await s.commit()
    # wrong attempt: caller does NOT commit (simulates HTTP rollback path)
    async with maker() as s:
        with pytest.raises(AppError):
            await exchange_device(s, maker, code, "wrong")
        # no commit — the increment must already be durable independently
    async with maker() as s:
        dc = (await s.execute(select(DeviceCode))).scalar_one()
        assert dc.exchange_attempts == 1


async def test_transfer_window_clamped(env4) -> None:
    maker = env4
    async with maker() as s:
        code, _ = await mint_device(s, ip="203.0.113.21", user_agent="cli")
        await s.commit()
    sess = await _session(maker)
    async with maker() as s:
        row = await s.get(OperatorSession, sess.id)
        transfer = await approve_device(s, row, code)
        await s.commit()
    # push approved_at back beyond the 2-min transfer window (device expiry
    # was extended to now+2min at approval, so set both back)
    async with maker() as s:
        dc = (await s.execute(select(DeviceCode))).scalar_one()
        dc.approved_at = datetime.now(UTC) - timedelta(seconds=130)
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError):
            await exchange_device(s, maker, code, transfer)
