"""Retention engine (design §6, plan 3).

Operator-command pruning — the ONLY GC path (no workers, §2). Never
touches: live sessions/runs, items/fields, recovery_codes (forensic
value), or the 20 most recent snapshots per (item_id, name) regardless
of age. audit/auth_events pruning respects CUSTOS_RETENTION_DAYS
(minimum 7, startup-enforced) so lockout windows always have a ledger.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from custos.admin.auth import AdminPrincipal
from custos.audit import add_audit_row
from custos.db.models import (
    AuditRow,
    AuthEvent,
    DeviceCode,
    FieldHistory,
    LockoutSuppression,
    OperatorSession,
    StepUpToken,
    WebAuthnChallenge,
)
from custos.errors import AppError
from custos.items import HISTORY_BUDGET


async def run_retention(
    session: AsyncSession, p: AdminPrincipal, days: int
) -> dict[str, int]:
    if p.actor_kind != "operator_session":
        raise AppError("session_required", "retention is session-only")
    if days < 7:
        raise AppError("invalid", "retention window must be at least 7 days")
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=days)
    counts: dict[str, int] = {}

    # history: rank over ALL snapshots per (item_id, name); prune only rows
    # that are BOTH older than the cutoff AND outside the 20-newest floor
    ranked = (
        select(
            FieldHistory.id,
            FieldHistory.superseded_at,
            func.row_number()
            .over(
                partition_by=(FieldHistory.item_id, FieldHistory.name),
                order_by=(FieldHistory.superseded_at.desc(), FieldHistory.id.desc()),
            )
            .label("rn"),
        )
        .subquery()
    )
    prunable = (
        select(ranked.c.id)
        .where(ranked.c.rn > HISTORY_BUDGET, ranked.c.superseded_at < cutoff)
        .scalar_subquery()
    )
    res = await session.execute(
        delete(FieldHistory).where(FieldHistory.id.in_(prunable))
    )
    counts["field_history"] = int(res.rowcount)  # type: ignore[attr-defined]

    res = await session.execute(delete(AuditRow).where(AuditRow.ts < cutoff))
    counts["audit"] = int(res.rowcount)  # type: ignore[attr-defined]
    res = await session.execute(delete(AuthEvent).where(AuthEvent.ts < cutoff))
    counts["auth_events"] = int(res.rowcount)  # type: ignore[attr-defined]

    # sessions: lock the candidate rows FOR UPDATE and materialize the dead
    # id set ONCE — the lock blocks concurrent last_seen refreshes/revokes
    # until commit, so the dependent deletes and the session delete can
    # never disagree with the resolver's view. "Expired" mirrors
    # operator.sessions.resolve_session EXACTLY (idle rule: last_seen +
    # idle_ttl <= now; recovery_reset stores idle 0 → absolute check only).
    # KEEP IN LOCKSTEP with resolve_session if the idle rule ever changes.
    candidates = list(
        (
            await session.execute(
                select(OperatorSession)
                .where(
                    (OperatorSession.revoked_at.is_not(None))
                    | (OperatorSession.absolute_expires_at <= now)
                    | (
                        (OperatorSession.idle_ttl_seconds > 0)
                        & (
                            OperatorSession.last_seen_at
                            + func.make_interval(0, 0, 0, 0, 0, 0, OperatorSession.idle_ttl_seconds)
                            <= now
                        )
                    )
                )
                .with_for_update()
            )
        ).scalars()
    )
    dead_session_ids = [s.id for s in candidates]
    res = await session.execute(
        delete(StepUpToken).where(
            (StepUpToken.consumed_at.is_not(None))
            | (StepUpToken.expires_at <= now)
            | StepUpToken.session_id.in_(dead_session_ids)
        )
    )
    counts["step_up_tokens"] = int(res.rowcount)  # type: ignore[attr-defined]
    res = await session.execute(
        delete(DeviceCode).where(
            (DeviceCode.consumed_at.is_not(None))
            | (DeviceCode.expires_at <= now)
            | DeviceCode.approved_by_session.in_(dead_session_ids)
        )
    )
    counts["device_codes"] = int(res.rowcount)  # type: ignore[attr-defined]
    res = await session.execute(
        delete(WebAuthnChallenge).where(
            (WebAuthnChallenge.consumed_at.is_not(None))
            | (WebAuthnChallenge.expires_at <= now)
            | WebAuthnChallenge.session_id.in_(dead_session_ids)
        )
    )
    counts["webauthn_challenges"] = int(res.rowcount)  # type: ignore[attr-defined]
    res = await session.execute(
        delete(OperatorSession).where(OperatorSession.id.in_(dead_session_ids))
    )
    counts["operator_sessions"] = int(res.rowcount)  # type: ignore[attr-defined]
    res = await session.execute(
        delete(LockoutSuppression).where(
            LockoutSuppression.suppressed_until_events_ts < cutoff
        )
    )
    counts["lockout_suppressions"] = int(res.rowcount)  # type: ignore[attr-defined]

    # success audit commits WITH the pruning (§4 closed detail set: total only)
    add_audit_row(
        session,
        actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
        action="retention", item_name=None, ok=True,
        detail={"pruned": sum(counts.values())},
    )
    return counts
