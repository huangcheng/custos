"""Admin maintenance routes (design §4/§6, plan 3): rekey today; verify,
rekey audit, retention, and audit read land in Tasks 8-10. Rekey auth:
session consumes one single step-up on the first batch (minting a
rekey_run token), later batches present the run token; allow_sensitive
tokens need neither. One active run per vault; run expiry extends per
successful batch."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from custos.admin.auth import AdminPrincipal, require_admin, require_session_only
from custos.audit import ACTION_ENUM, add_audit_row
from custos.cursors import mint_cursor, read_cursor
from custos.db.models import AuditRow, OperatorSession, StepUpToken
from custos.errors import AppError
from custos.rekey import (
    extend_run,
    mint_run,
    mint_scan_cursor,
    read_scan_cursor,
    rekey_audit,
    rekey_batch,
    validate_run,
    verify_batch,
)
from custos.rekey import (
    hash_token as token_hash,
)
from custos.retention import run_retention
from custos.routes_agent import _json_body, _page_limit

router = APIRouter(prefix="/api/admin")


async def _resolve_run_auth(
    request: Request, p: AdminPrincipal
) -> tuple[Any, StepUpToken | None, bool]:
    """Returns (presenter row, run row or None, first_batch). A rekey_run
    token is deliberately accepted by BOTH sweep endpoints (§4: one run
    kind for rekey and verify; cursors are endpoint-tagged instead)."""
    maker = request.app.state.session_maker
    token = request.headers.get("x-step-up-token", "")
    async with maker() as session:
        if p.actor_kind == "operator_token":
            if not p.allow_sensitive:
                raise AppError("step_up_required", "step-up required")
            request.state.allow_sensitive = True
            return None, None, False
        presenter = await session.get(OperatorSession, p.row_id)
        if presenter is None or presenter.revoked_at is not None:
            raise AppError("step_up_required", "step-up required")
        if not token:
            raise AppError("step_up_required", "step-up required")
        # run token first (multi-use); a consumed single falls through to
        # mint_run which re-validates and 409s if a run is already live
        row = (
            await session.execute(
                select(StepUpToken).where(StepUpToken.nonce_hash == token_hash(token))
            )
        ).scalar_one_or_none()
        if row is not None and row.kind == "rekey_run":
            run = await validate_run(session, token, presenter)
            return presenter, run, False
        return presenter, None, True


async def _run_sweep(request: Request, p: AdminPrincipal, endpoint: str) -> dict[str, Any]:
    body = await _json_body(request)
    cursor_raw = body.get("cursor")
    if cursor_raw is not None and not isinstance(cursor_raw, str):
        raise AppError("invalid", "cursor must be a string")
    pepper = request.app.state.settings.pepper_raw
    cursor_payload = (
        read_scan_cursor(cursor_raw, pepper, endpoint, p.plane) if cursor_raw else {}
    )
    presenter, run, first_batch = await _resolve_run_auth(request, p)
    maker = request.app.state.session_maker
    vault = request.app.state.vault
    engine_fn = rekey_batch if endpoint == "rekey" else verify_batch
    new_run_token: str | None = None
    async with maker() as session:
        if first_batch and p.actor_kind == "operator_session":
            new_run_token = await mint_run(
                session, presenter, request.headers.get("x-step-up-token", "")
            )
        result = await engine_fn(session, vault, cursor_payload)
        if run is not None:
            run_row = await session.get(StepUpToken, run.id)
            if run_row is not None:
                if result["remaining"] == 0:
                    # completed sweep: release the run immediately — a fresh
                    # rekey after a rotation must not 409 for the TTL window
                    await session.delete(run_row)
                else:
                    extend_run(run_row)
        if new_run_token is not None and result["remaining"] == 0:
            # zero-row first batch: nothing to run — drop the row we just
            # minted so it never blocks the next run, and never advertise a
            # token whose row no longer exists
            row = (
                await session.execute(
                    select(StepUpToken).where(
                        StepUpToken.nonce_hash == token_hash(new_run_token)
                    )
                )
            ).scalar_one_or_none()
            if row is not None:
                await session.delete(row)
            new_run_token = None
        # run-start audit commits WITH the first batch (§4 invariant)
        if first_batch or (p.actor_kind == "operator_token" and not cursor_raw):
            detail: dict[str, object] = {}
            if getattr(request.state, "allow_sensitive", False):
                detail["allow_sensitive"] = True
            add_audit_row(
                session,
                actor_kind=p.actor_kind, actor_id=p.actor_id,
                actor_label=p.actor_label,
                action="rekey" if endpoint == "rekey" else "rekey_verify",
                item_name=None, ok=True, detail=detail,
            )
        await session.commit()
    payload = result.pop("_cursor_payload", None)
    out: dict[str, Any] = {k: v for k, v in result.items()}
    if payload is not None:
        out["cursor"] = mint_scan_cursor(payload, pepper, endpoint, p.plane)
    if new_run_token is not None:
        out["run_token"] = new_run_token
    return out


@router.post("/rekey")
async def post_rekey(
    request: Request, p: AdminPrincipal = Depends(require_admin)
) -> dict[str, Any]:
    return await _run_sweep(request, p, "rekey")


@router.post("/rekey/verify")
async def post_verify(
    request: Request, p: AdminPrincipal = Depends(require_admin)
) -> dict[str, Any]:
    return await _run_sweep(request, p, "rekey_verify")


@router.get("/rekey/audit")
async def get_rekey_audit(
    request: Request, p: AdminPrincipal = Depends(require_admin)
) -> dict[str, Any]:
    """Plain admin auth, metadata only, not audited (§4 enumeration read)."""
    async with request.app.state.session_maker() as session:
        return await rekey_audit(session, request.app.state.vault)


@router.post("/retention")
async def post_retention(
    request: Request, p: AdminPrincipal = Depends(require_session_only)
) -> dict[str, int]:
    async with request.app.state.session_maker() as session:
        counts = await run_retention(
            session, p, request.app.state.settings.retention_days
        )
        await session.commit()
    return counts


@router.get("/audit")
async def get_audit(
    request: Request,
    actor: str | None = None,
    action: str | None = None,
    item: str | None = None,
    cursor: str | None = None,
    limit: str | None = None,
    p: AdminPrincipal = Depends(require_admin),
) -> dict[str, Any]:
    """50/100 keyset pages (id ascending), AND-combined filters. Plain
    admin auth; enumeration read — not audited (§4)."""
    page = _page_limit(limit)
    pepper = request.app.state.settings.pepper_raw
    payload = read_cursor(cursor, pepper, "admin_audit", p.plane) if cursor else {}
    stmt = select(AuditRow).order_by(AuditRow.id)
    if "after" in payload:
        stmt = stmt.where(AuditRow.id > int(payload["after"]))
    if actor is not None:
        stmt = stmt.where(AuditRow.actor_id == actor)
    if action is not None:
        if action not in ACTION_ENUM:
            raise AppError("invalid", "unknown action filter")
        stmt = stmt.where(AuditRow.action == action)
    if item is not None:
        stmt = stmt.where(AuditRow.item_name == item)
    for param, col_op in (("from", "ge"), ("to", "le")):
        raw = request.query_params.get(param)
        if raw is not None:
            try:
                ts = datetime.fromisoformat(raw)
            except ValueError:
                raise AppError("invalid", f"{param} must be ISO 8601") from None
            if ts.tzinfo is None:
                raise AppError("invalid", f"{param} must carry a timezone")
            stmt = stmt.where(
                AuditRow.ts >= ts if col_op == "ge" else AuditRow.ts <= ts
            )
    async with request.app.state.session_maker() as session:
        rows = list((await session.execute(stmt.limit(page + 1))).scalars())
    has_more = len(rows) > page
    rows = rows[:page]
    next_cursor = None
    if has_more and rows:
        next_cursor = mint_cursor({"after": rows[-1].id}, pepper, "admin_audit", p.plane)
    return {
        "items": [
            {
                "id": r.id,
                "ts": r.ts.isoformat(),
                "actor_kind": r.actor_kind,
                "actor_id": r.actor_id,
                "actor_label": r.actor_label,
                "action": r.action,
                "item_name": r.item_name,
                "ok": r.ok,
                "detail": r.detail,
            }
            for r in rows
        ],
        "next_cursor": next_cursor,
    }
