"""Audit + auth-event ledger contract tests (design §4, §5 ledger budget)."""

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.audit import (
    ACTION_ENUM,
    DETAIL_KEYS,
    FailureCounter,
    LedgerBudget,
    LedgerError,
    record_audit,
    record_auth_event,
)
from custos.db.models import AuditRow, AuthEvent

pytestmark = pytest.mark.usefixtures("pg_db")


@pytest.fixture
async def maker(pg_db: str):
    engine = create_async_engine(pg_db)
    maker_ = async_sessionmaker(engine, expire_on_commit=False)
    # shared session-scoped DB: earlier files may leave audit/auth rows behind
    async with maker_() as s:
        await s.execute(delete(AuditRow))
        await s.execute(delete(AuthEvent))
        await s.commit()
    yield maker_
    await engine.dispose()


async def test_closed_action_enum(maker) -> None:
    assert "force_drop" in ACTION_ENUM
    assert "rekey_verify" in ACTION_ENUM
    with pytest.raises(ValueError):
        await record_audit(
            maker,
            actor_kind="agent",
            actor_id="abcdef012345",
            actor_label="cu-test",
            action="bogus",
            item_name=None,
            ok=True,
            detail={},
        )


async def test_detail_key_whitelist_and_length(maker) -> None:
    assert "evicted" in DETAIL_KEYS
    with pytest.raises(ValueError):
        await record_audit(
            maker,
            actor_kind="agent",
            actor_id="abcdef012345",
            actor_label="cu-test",
            action="put",
            item_name="aliyun",
            ok=True,
            detail={"value": "sk-leak"},
        )
    with pytest.raises(ValueError):
        await record_audit(
            maker,
            actor_kind="agent",
            actor_id="abcdef012345",
            actor_label="cu-test",
            action="put",
            item_name="aliyun",
            ok=True,
            detail={"reason": "x" * 257},
        )


async def test_independent_commit_survives_caller_rollback(maker) -> None:
    await record_audit(
        maker,
        actor_kind="anonymous",
        actor_id=None,
        actor_label="anonymous",
        action="auth.failure",
        item_name=None,
        ok=False,
        detail={"ip": "203.0.113.9"},
    )
    async with maker() as session:
        session.add(AuditRow(actor_kind="agent", actor_label="x", action="put", ok=True))
        await session.rollback()  # caller transaction dies
    async with maker() as session:
        rows = (
            (await session.execute(select(AuditRow).where(AuditRow.action == "auth.failure")))
            .scalars()
            .all()
        )
        assert len(rows) == 1


async def test_auth_event_written(maker) -> None:
    await record_auth_event(
        maker, kind="agent_auth", ok=False, ip="203.0.113.9", peer_ip="10.0.0.1"
    )
    async with maker() as session:
        rows = (await session.execute(select(AuthEvent))).scalars().all()
        assert any(r.ip == "203.0.113.9" and r.peer_ip == "10.0.0.1" for r in rows)


async def test_ledger_write_failure_raises_ledger_error() -> None:
    engine = create_async_engine("postgresql+asyncpg://custos:cu-test@127.0.0.1:1/none")
    bad_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        with pytest.raises(LedgerError):
            await record_auth_event(
                bad_maker, kind="agent_auth", ok=False, ip="203.0.113.9", peer_ip="10.0.0.1"
            )
    finally:
        await engine.dispose()


def test_budget_exhaustion_and_counter() -> None:
    budget = LedgerBudget(limit=600)
    counter = FailureCounter()
    for _ in range(600):
        assert budget.allow()
    assert not budget.allow()
    counter.record(ip="203.0.113.9")
    assert counter.count(ip="203.0.113.9") == 1


async def test_exhausted_budget_skips_failure_but_writes_success(maker) -> None:
    budget = LedgerBudget(limit=0)
    counter = FailureCounter()
    await record_auth_event(
        maker,
        kind="agent_auth",
        ok=False,
        ip="203.0.113.10",
        peer_ip="10.0.0.1",
        budget=budget,
        counter=counter,
    )
    await record_auth_event(
        maker,
        kind="agent_auth",
        ok=True,
        ip="203.0.113.10",
        peer_ip="10.0.0.1",
        budget=budget,
        counter=counter,
    )
    # agent_auth failures live in their own bucket, never the lockout bucket
    assert counter.count(ip="203.0.113.10") == 0
    assert counter.agent_failures(ip="203.0.113.10") == 1
    async with maker() as session:
        rows = (
            (await session.execute(select(AuthEvent).where(AuthEvent.ip == "203.0.113.10")))
            .scalars()
            .all()
        )
        assert len(rows) == 1 and rows[0].ok is True


async def test_detail_rejects_nested_structures(maker) -> None:
    with pytest.raises(ValueError):
        await record_audit(
            maker, actor_kind="agent", actor_id="a" * 12, actor_label="cu-test",
            action="put", item_name="aliyun", ok=True,
            detail={"reason": {"nested": "sk-leak"}},
        )
    with pytest.raises(ValueError):
        await record_audit(
            maker, actor_kind="agent", actor_id="a" * 12, actor_label="cu-test",
            action="put", item_name="aliyun", ok=True,
            detail={"evicted_ids": [{"nested": 1}]},
        )


def test_counter_scopes_independent() -> None:
    counter = FailureCounter()
    counter.record(ip="203.0.113.1", account=True)
    assert counter.count(ip="203.0.113.1") == 1
    assert counter.count(account=True) == 1
    assert counter.count(ip="203.0.113.2") == 0


def test_counter_bounded_buckets() -> None:
    counter = FailureCounter(max_keys=10)
    for i in range(100):
        counter.record(ip=f"203.0.113.{i}")
    assert counter.bucket_count() <= 10


async def test_setup_failure_not_counted_against_account(maker) -> None:
    budget = LedgerBudget(limit=0)
    counter = FailureCounter()
    await record_auth_event(
        maker, kind="setup", ok=False, ip="203.0.113.20", peer_ip="10.0.0.1",
        budget=budget, counter=counter,
    )
    assert counter.count(ip="203.0.113.20") == 1
    assert counter.count(account=True) == 0


async def test_audit_failure_rows_share_budget(maker) -> None:
    budget = LedgerBudget(limit=0)
    counter = FailureCounter()
    await record_audit(
        maker, actor_kind="anonymous", actor_id=None, actor_label="anonymous",
        action="auth.failure", item_name=None, ok=False, detail={"ip": "203.0.113.30"},
        budget=budget, counter=counter,
    )
    async with maker() as session:
        rows = (
            (await session.execute(select(AuditRow).where(AuditRow.action == "auth.failure")))
            .scalars()
            .all()
        )
        assert all(r.detail.get("ip") != "203.0.113.30" for r in rows)


def test_budget_exhaustion_logged_once(caplog) -> None:
    import logging

    budget = LedgerBudget(limit=0)
    with caplog.at_level(logging.WARNING, logger="custos.audit"):
        assert not budget.allow()
        assert not budget.allow()
    messages = [r for r in caplog.records if "budget" in r.getMessage()]
    assert len(messages) == 1


def test_account_bucket_never_evicted() -> None:
    counter = FailureCounter(max_keys=5)
    counter.record(account=True)
    for i in range(50):
        counter.record(ip=f"198.51.100.{i}")
    assert counter.count(account=True) == 1


async def test_budget_without_counter_rejected(maker) -> None:
    with pytest.raises(ValueError):
        await record_auth_event(
            maker, kind="agent_auth", ok=False, ip="203.0.113.40", peer_ip="10.0.0.1",
            budget=LedgerBudget(limit=0),
        )


def test_counter_bucket_memory_bounded() -> None:
    counter = FailureCounter()
    for _ in range(1000):
        counter.record(ip="203.0.113.50")
    # only the 10/30 thresholds are consulted; per-bucket memory is constant
    assert counter.count(ip="203.0.113.50") == 30


async def test_non_credential_audit_failure_not_counted(maker) -> None:
    budget = LedgerBudget(limit=0)
    counter = FailureCounter()
    await record_audit(
        maker, actor_kind="agent", actor_id="a" * 12, actor_label="cu-test",
        action="put", item_name="aliyun", ok=False, detail={"ip": "203.0.113.60"},
        budget=budget, counter=counter,
    )
    assert counter.count(ip="203.0.113.60") == 0


async def test_budget_counter_invariant_eager(maker) -> None:
    with pytest.raises(ValueError):
        await record_auth_event(
            maker, kind="agent_auth", ok=True, ip="203.0.113.70", peer_ip="10.0.0.1",
            budget=LedgerBudget(limit=600),
        )


async def test_agent_auth_fallback_uses_separate_bucket(maker) -> None:
    budget = LedgerBudget(limit=0)
    counter = FailureCounter()
    await record_auth_event(
        maker, kind="agent_auth", ok=False, ip="203.0.113.80", peer_ip="10.0.0.1",
        budget=budget, counter=counter,
    )
    assert counter.count(ip="203.0.113.80") == 0  # credential lockout untouched
    assert counter.agent_failures(ip="203.0.113.80") == 1


async def test_audit_only_failures_never_counted(maker) -> None:
    budget = LedgerBudget(limit=0)
    counter = FailureCounter()
    await record_audit(
        maker, actor_kind="anonymous", actor_id=None, actor_label="anonymous",
        action="auth.failure", item_name=None, ok=False,
        detail={"ip": "203.0.113.90", "reason": "turnstile"},
        budget=budget, counter=counter,
    )
    assert counter.count(ip="203.0.113.90") == 0


async def test_actor_id_encoding_validated(maker) -> None:
    with pytest.raises(ValueError):
        await record_audit(
            maker, actor_kind="anonymous", actor_id="not-null", actor_label="anonymous",
            action="auth.failure", item_name=None, ok=False, detail={},
        )
    with pytest.raises(ValueError):
        await record_audit(
            maker, actor_kind="agent", actor_id="zzz", actor_label="cu-test",
            action="get", item_name="aliyun", ok=True, detail={},
        )
    with pytest.raises(ValueError):
        await record_audit(
            maker, actor_kind="local_process", actor_id="other", actor_label="break-glass",
            action="account.unlock", item_name=None, ok=True, detail={},
        )


async def test_fallback_counts_once_per_credential_failure(maker) -> None:
    budget = LedgerBudget(limit=0)
    counter = FailureCounter()
    # one failed login = auth_event + audit row; counter must increment ONCE
    await record_auth_event(
        maker, kind="login_password", ok=False, ip="203.0.113.100", peer_ip="10.0.0.1",
        budget=budget, counter=counter,
    )
    await record_audit(
        maker, actor_kind="anonymous", actor_id=None, actor_label="anonymous",
        action="auth.failure", item_name=None, ok=False, detail={"ip": "203.0.113.100"},
        budget=budget, counter=counter,
    )
    assert counter.count(ip="203.0.113.100") == 1
    assert counter.count(account=True) == 1


async def test_reason_list_rejected(maker) -> None:
    with pytest.raises(ValueError):
        await record_audit(
            maker, actor_kind="anonymous", actor_id=None, actor_label="anonymous",
            action="auth.failure", item_name=None, ok=False,
            detail={"reason": ["turnstile"]},
        )


def test_actor_id_trailing_newline_rejected() -> None:
    from custos.audit import _validate_actor

    with pytest.raises(ValueError):
        _validate_actor("agent", "abcdef012345\n")


def test_agent_bucket_recency_refreshed() -> None:
    counter = FailureCounter(max_keys=3)
    counter.record_agent_failure(ip="192.0.2.1")
    for i in range(3):
        counter.record_agent_failure(ip=f"192.0.2.{10 + i}")
    counter.record_agent_failure(ip="192.0.2.1")  # refresh recency
    counter.record_agent_failure(ip="192.0.2.99")  # forces eviction
    assert counter.agent_failures(ip="192.0.2.1") >= 1


def test_account_window_is_30_minutes() -> None:
    counter = FailureCounter()
    # inject an event 20 minutes old: outside the IP window, inside account's
    import time as _time

    counter.record(account=True)
    counter._events["account"][0] = _time.monotonic() - 1200
    counter.record(ip="203.0.113.110")
    counter._events["ip:203.0.113.110"][0] = _time.monotonic() - 1200
    assert counter.count(account=True) == 1  # 30-min window keeps it
    assert counter.count(ip="203.0.113.110") == 0  # 15-min window drops it
