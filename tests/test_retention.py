"""Retention (plan 3 Task 9): recent-prior floor, dead-rows-only pruning,
ledger floor, session-only gate."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from custos.db.models import (
    AuditRow,
    AuthEvent,
    DeviceCode,
    Field,
    FieldHistory,
    Item,
    LockoutSuppression,
    OperatorSession,
    RecoveryCode,
    StepUpToken,
)
from custos.operator.sessions import create_session
from tests.admin_conftest import admin_stack, bearer

pytestmark = pytest.mark.usefixtures("pg_db")

__all__ = ["admin_stack"]

OLD = datetime.now(UTC) - timedelta(days=400)


async def _mk_item(maker, name="ret"):
    async with maker() as s:
        item = Item(name=name, notes="")
        s.add(item)
        await s.flush()
        fid = uuid.uuid4()
        s.add(Field(id=fid, item_id=item.id, name="KEY", secret=False, value="current"))
        await s.commit()
        return item.id, fid


async def _mk_history(maker, item_id, fid, n, ts):
    async with maker() as s:
        for i in range(n):
            s.add(FieldHistory(
                id=uuid.uuid4(), field_id=fid, item_id=item_id, name="KEY",
                secret=False, value=f"prior-{i}", superseded_by="local",
                actor_label="cu-test",
                superseded_at=ts + timedelta(seconds=i),
            ))
        await s.commit()


async def test_recent_prior_floor(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        item_id, fid = await _mk_item(maker)
        await _mk_history(maker, item_id, fid, 25, OLD)
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/retention",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 200, r.text
        assert r.json()["field_history"] == 5  # 25 - 20 floor
        async with maker() as s:
            remaining = (await s.execute(select(FieldHistory.value))).scalars().all()
            f = (await s.execute(select(Field))).scalars().first()
        # the 20 NEWEST survive; current value untouched
        assert sorted(remaining) == sorted(f"prior-{i}" for i in range(5, 25))
        assert f.value == "current"


async def test_prunes_dead_rows_only(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        async with maker() as s:
            # shared DB: earlier files leave device rows behind
            from sqlalchemy import delete

            await s.execute(delete(DeviceCode))
            await s.execute(delete(RecoveryCode))
            # expired session + live session
            dead_sess, _ = await create_session(s)
            dead_sess.revoked_at = datetime.now(UTC)
            live_sess, _ = await create_session(s)
            # consumed step-up + live run
            import hashlib
            s.add(StepUpToken(session_id=live_sess.id,
                              nonce_hash=hashlib.sha256(b"cu-test-a").digest(),
                              kind="single", consumed_at=datetime.now(UTC),
                              expires_at=datetime.now(UTC) + timedelta(minutes=5)))
            s.add(StepUpToken(session_id=live_sess.id,
                              nonce_hash=hashlib.sha256(b"cu-test-b").digest(),
                              kind="rekey_run",
                              expires_at=datetime.now(UTC) + timedelta(minutes=30)))
            # consumed device code + live one
            s.add(DeviceCode(code_hash=bytes(32), client_ip="203.0.113.1",
                             user_agent="cu-test",
                             expires_at=datetime.now(UTC) + timedelta(minutes=5),
                             consumed_at=datetime.now(UTC)))
            s.add(DeviceCode(code_hash=bytes([1]) + bytes(31), client_ip="203.0.113.1",
                             user_agent="cu-test",
                             expires_at=datetime.now(UTC) + timedelta(minutes=5)))
            # old + fresh audit rows; consumed recovery code
            s.add(AuditRow(actor_kind="local_process", actor_id="local",
                           actor_label="cu-test", action="retention", ok=True,
                           detail={}, ts=OLD))
            s.add(RecoveryCode(digest=bytes(32), consumed_at=datetime.now(UTC)))
            await s.commit()
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/retention",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 200, r.text
        counts = r.json()
        assert counts["operator_sessions"] >= 1
        assert counts["step_up_tokens"] >= 1
        assert counts["device_codes"] >= 1
        assert counts["audit"] >= 1
        async with maker() as s:
            # live session + live run + live device code + recovery codes survive
            assert (await s.execute(select(func.count()).select_from(OperatorSession)
                                    .where(OperatorSession.revoked_at.is_(None)))).scalar_one() >= 1
            kinds = (await s.execute(select(StepUpToken.kind))).scalars().all()
            assert "rekey_run" in kinds and "single" not in kinds
            assert (await s.execute(select(func.count()).select_from(
                DeviceCode))).scalar_one() == 1
            assert (await s.execute(select(func.count()).select_from(
                RecoveryCode))).scalar_one() == 1  # forensic retention


async def test_lockout_ledger_floor(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        async with maker() as s:
            s.add(AuthEvent(kind="login_password", ok=False, ip="203.0.113.9",
                            peer_ip="203.0.113.9", ts=OLD))
            s.add(AuthEvent(kind="login_password", ok=False, ip="203.0.113.9",
                            peer_ip="203.0.113.9"))  # fresh
            s.add(LockoutSuppression(scope="account", suppressed_until_events_ts=OLD))
            s.add(LockoutSuppression(scope="ip:*",
                                     suppressed_until_events_ts=datetime.now(UTC)))
            await s.commit()
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        # default retention 365d: OLD (400d) pruned, fresh kept
        r = await client.post("/api/admin/retention",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 200
        async with maker() as s:
            events = (await s.execute(select(AuthEvent.ts))).scalars().all()
            scopes = (await s.execute(select(LockoutSuppression.scope))).scalars().all()
        assert all(ts > OLD + timedelta(days=1) for ts in events)
        assert scopes == ["ip:*"]  # old marker pruned, fresh kept


async def test_retention_session_only(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        sens = await h["mint_co"](allow_sensitive=True)
        r = await client.post("/api/admin/retention", headers=bearer(sens))
        assert r.status_code == 403 and r.json()["code"] == "session_required"
        async with maker() as s:
            rows = (await s.execute(select(AuditRow).where(
                AuditRow.action == "auth.failure"))).scalars().all()
        assert any(r.detail.get("reason") == "session_required" for r in rows)
        csrf = await h["login"](client)
        r = await client.post("/api/admin/retention", headers={"x-csrf-token": csrf})
        assert r.status_code == 401
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/retention",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 200
        async with maker() as s:
            rows = (await s.execute(select(AuditRow).where(
                AuditRow.action == "retention"))).scalars().all()
        assert rows and "pruned" in rows[-1].detail


async def test_revoked_session_with_consumed_stepup_prunes(admin_stack) -> None:
    """Regression: consumed step-ups / live approved device codes bound to a
    revoked session must not FK-block the session prune."""
    async with admin_stack() as (client, maker, h):
        import hashlib

        async with maker() as s:
            sess, _ = await create_session(s)
            sess.revoked_at = datetime.now(UTC)
            s.add(StepUpToken(session_id=sess.id,
                              nonce_hash=hashlib.sha256(b"cu-test-fk").digest(),
                              kind="single", consumed_at=datetime.now(UTC),
                              expires_at=datetime.now(UTC) + timedelta(minutes=5)))
            s.add(DeviceCode(code_hash=bytes([2]) + bytes(31),
                             client_ip="203.0.113.1", user_agent="cu-test",
                             approved_by_session=sess.id,
                             approved_at=datetime.now(UTC),
                             expires_at=datetime.now(UTC) + timedelta(minutes=5)))
            await s.commit()
            sess_id = sess.id
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/retention",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 200, r.text
        async with maker() as s:
            assert (await s.execute(select(func.count()).select_from(OperatorSession)
                                    .where(OperatorSession.id == sess_id))).scalar_one() == 0


async def test_floor_ranks_over_all_ages(admin_stack) -> None:
    """20 old + 5 fresh snapshots: the floor is the 20 newest OVERALL, so
    15 old rows prune and 5 old + 5 fresh survive."""
    async with admin_stack() as (client, maker, h):
        item_id, fid = await _mk_item(maker, name="ret-mix")
        await _mk_history(maker, item_id, fid, 20, OLD)
        await _mk_history(maker, item_id, fid, 5, datetime.now(UTC) - timedelta(days=1))
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/retention",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 200
        # 25 total, floor keeps the 20 newest overall → 5 oldest prune
        assert r.json()["field_history"] == 5
        async with maker() as s:
            n = (await s.execute(select(func.count()).select_from(
                FieldHistory))).scalar_one()
        assert n == 20  # 15 old + 5 fresh survive


async def test_idle_expired_session_pruned(admin_stack) -> None:
    async with admin_stack() as (client, maker, h):
        async with maker() as s:
            sess, _ = await create_session(s, idle_ttl=3600)
            sess.last_seen_at = datetime.now(UTC) - timedelta(hours=2)
            await s.commit()
            sess_id = sess.id
        csrf = await h["login"](client)
        su = await h["step_up"](client, csrf)
        r = await client.post("/api/admin/retention",
                              headers={"x-csrf-token": csrf, "x-step-up-token": su})
        assert r.status_code == 200
        async with maker() as s:
            assert (await s.execute(select(func.count()).select_from(OperatorSession)
                                    .where(OperatorSession.id == sess_id))).scalar_one() == 0
