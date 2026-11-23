"""Credential lockout contract (design §5). Real postgres, fake events."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.db.models import AuthEvent, LockoutSuppression
from custos.errors import AppError
from custos.operator.lockout import check_lockout

pytestmark = pytest.mark.usefixtures("pg_db")

KINDS = ["login_password", "login_totp", "login_passkey", "login_recovery", "step_up", "setup"]


@pytest.fixture
async def maker(pg_db: str):
    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    # shared session DB: lockout tests need a clean failure ledger
    async with maker() as s:
        from sqlalchemy import delete

        await s.execute(delete(AuthEvent))
        await s.execute(delete(LockoutSuppression))
        await s.commit()
    yield maker
    await engine.dispose()


async def _fail(maker, ip: str, *, kind: str = "login_password", age_s: float = 0) -> None:
    async with maker() as s:
        s.add(AuthEvent(kind=kind, ok=False, ip=ip, peer_ip=ip,
                        ts=datetime.now(UTC) - timedelta(seconds=age_s)))
        await s.commit()


async def test_per_ip_block_at_10(maker) -> None:
    ip = "203.0.113.10"
    for _ in range(9):
        await _fail(maker, ip)
    async with maker() as s:
        await check_lockout(s, ip=ip, account_exists=True)  # 9 -> ok
    await _fail(maker, ip)  # 10th
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await check_lockout(s, ip=ip, account_exists=True)
        assert e.value.code == "locked_out"
        assert e.value.headers and "Retry-After" in e.value.headers


async def test_window_expiry_unblocks(maker) -> None:
    ip = "203.0.113.11"
    for _ in range(10):
        await _fail(maker, ip, age_s=16 * 60)  # older than 15-min window
    async with maker() as s:
        await check_lockout(s, ip=ip, account_exists=True)  # all expired -> ok


async def test_account_block_at_30_non_extending(maker) -> None:
    # 30 failures across many IPs -> account block
    for i in range(30):
        await _fail(maker, f"198.51.100.{i}")
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await check_lockout(s, ip="203.0.113.99", account_exists=True)
        assert e.value.code == "locked_out"
        first_retry = int(e.value.headers["Retry-After"])
    # more failures during the block must NOT extend it
    for i in range(5):
        await _fail(maker, f"198.51.100.{100 + i}")
    async with maker() as s:
        with pytest.raises(AppError) as e2:
            await check_lockout(s, ip="203.0.113.99", account_exists=True)
        assert int(e2.value.headers["Retry-After"]) <= first_retry


async def test_ip_wildcard_suppression(maker) -> None:
    ip = "203.0.113.12"
    for _ in range(10):
        await _fail(maker, ip)
    async with maker() as s:
        s.add(LockoutSuppression(scope="ip:*",
                                 suppressed_until_events_ts=datetime.now(UTC)))
        await s.commit()
    async with maker() as s:
        await check_lockout(s, ip=ip, account_exists=False)  # unblocked


async def test_account_suppression_only_account(maker) -> None:
    for i in range(30):
        await _fail(maker, f"198.51.100.{i}")
    async with maker() as s:
        s.add(LockoutSuppression(scope="account",
                                 suppressed_until_events_ts=datetime.now(UTC)))
        await s.commit()
    # account unblocked, but a single-IP block still stands
    ip = "203.0.113.13"
    for _ in range(10):
        await _fail(maker, ip)
    async with maker() as s:
        with pytest.raises(AppError):
            await check_lockout(s, ip=ip, account_exists=True)  # per-IP still blocks
    async with maker() as s:
        await check_lockout(s, ip="203.0.113.200", account_exists=True)  # account ok


async def test_setup_counts_per_ip_only(maker) -> None:
    # 30 setup failures from one IP: per-IP blocks, but no account (none exists)
    ip = "203.0.113.14"
    for _ in range(10):
        await _fail(maker, ip, kind="setup")
    async with maker() as s:
        with pytest.raises(AppError):
            await check_lockout(s, ip=ip, account_exists=False)
    # a different IP with no failures is unaffected (setup never counts account)
    async with maker() as s:
        await check_lockout(s, ip="203.0.113.15", account_exists=False)


async def test_agent_auth_not_counted(maker) -> None:
    ip = "203.0.113.16"
    for _ in range(50):
        await _fail(maker, ip, kind="agent_auth")
    async with maker() as s:
        await check_lockout(s, ip=ip, account_exists=True)  # agent_auth never counts


async def test_paced_account_block_lasts_full_window(maker) -> None:
    # 30 failures spaced 1 min apart: at check time the oldest is ~29 min old.
    # The block must still last ~30 min from the 30th (most recent) failure,
    # not collapse as the oldest rows age out of a trailing window.
    for i in range(30):
        await _fail(maker, f"198.51.100.{i}", age_s=(29 - i) * 60)
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await check_lockout(s, ip="203.0.113.99", account_exists=True)
        # newest failure is ~0s old -> block ~30 min remaining
        assert int(e.value.headers["Retry-After"]) > 25 * 60


async def test_flood_counter_fallback_blocks(maker) -> None:
    from custos.audit import FailureCounter

    counter = FailureCounter()
    # ledger empty (budget-exhausted flood path), counter carries the failures
    for _ in range(10):
        counter.record(ip="203.0.113.50")
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await check_lockout(s, ip="203.0.113.50", account_exists=True, counter=counter)
        assert e.value.code == "locked_out"




async def test_paced_ip_block_does_not_collapse(maker) -> None:
    # 10 failures: 9 spread over the prior 14 min, the 10th just now. As the
    # older rows age out, the block must NOT collapse — it is anchored at the
    # most recent failure (15 min from now), per the non-extending design.
    ip = "203.0.113.60"
    for i in range(9):
        await _fail(maker, ip, age_s=(14 - i) * 60)
    await _fail(maker, ip, age_s=0)  # 10th, now
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await check_lockout(s, ip=ip, account_exists=True)
        assert int(e.value.headers["Retry-After"]) > 14 * 60


async def test_burst_then_wait_keeps_block_until_anchor_plus_window(maker) -> None:
    # burst of 10 at t=-14min, then check at t=0: oldest still in window,
    # block anchored at the burst (10th) -> ~1 min remaining, NOT collapsed.
    ip = "203.0.113.61"
    for _ in range(10):
        await _fail(maker, ip, age_s=14 * 60)
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await check_lockout(s, ip=ip, account_exists=True)
        assert 0 < int(e.value.headers["Retry-After"]) <= 2 * 60


async def test_flood_counter_anchor_non_extending(maker) -> None:
    import collections
    import time as _time

    from custos.audit import FailureCounter

    counter = FailureCounter()
    key = "ip:203.0.113.70"
    # 9 failures 14 min ago + 1 fresh: the 10th-most-recent (anchor) is the
    # oldest, so the block has ~1 min left (900 - 840), NOT a fresh 15 min.
    old = _time.monotonic() - 14 * 60
    counter._events[key] = collections.deque([old] * 9, maxlen=30)
    counter.record(ip="203.0.113.70")  # 10th, now
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await check_lockout(s, ip="203.0.113.70", account_exists=False, counter=counter)
        assert 0 < int(e.value.headers["Retry-After"]) <= 2 * 60
    # a fresh burst of 10 now anchors at now -> ~full 15-min block
    counter2 = FailureCounter()
    for _ in range(10):
        counter2.record(ip="203.0.113.71")
    async with maker() as s:
        with pytest.raises(AppError) as e2:
            await check_lockout(s, ip="203.0.113.71", account_exists=False, counter=counter2)
        assert int(e2.value.headers["Retry-After"]) > 14 * 60


async def test_suppression_clears_counter_only_block(maker) -> None:
    """Break-glass unlock must work under ledger-budget exhaustion: the
    marker clears the in-process fallback counter, not just ledger rows."""
    from custos.audit import FailureCounter

    ip = "203.0.113.77"
    counter = FailureCounter()
    for _ in range(10):
        counter.record(ip=ip)
    for _ in range(30):
        counter.record(account=True)
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await check_lockout(s, ip=ip, account_exists=True, counter=counter)
        assert e.value.code == "locked_out"
    async with maker() as s:
        s.add(LockoutSuppression(scope="ip:*",
                                 suppressed_until_events_ts=datetime.now(UTC)))
        s.add(LockoutSuppression(scope="account",
                                 suppressed_until_events_ts=datetime.now(UTC)))
        await s.commit()
    async with maker() as s:
        await check_lockout(s, ip=ip, account_exists=True, counter=counter)
