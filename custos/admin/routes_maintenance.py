"""Admin maintenance routes (design §4/§6, plan 3): rekey today; verify,
rekey audit, retention, and audit read land in Tasks 8-10. Rekey auth:
session consumes one single step-up on the first batch (minting a
rekey_run token), later batches present the run token; allow_sensitive
tokens need neither. One active run per vault; run expiry extends per
successful batch."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from custos.admin.auth import AdminPrincipal, require_admin
from custos.audit import record_audit
from custos.db.models import OperatorSession, StepUpToken
from custos.errors import AppError
from custos.rekey import (
    extend_run,
    mint_run,
    mint_scan_cursor,
    read_scan_cursor,
    rekey_batch,
    validate_run,
    verify_batch,
)
from custos.routes_agent import _json_body

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
        from custos.rekey import _hash

        row = (
            await session.execute(
                select(StepUpToken).where(StepUpToken.nonce_hash == _hash(token))
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
            # re-fetch inside this transaction and extend on success
            run_row = await session.get(StepUpToken, run.id)
            if run_row is not None:
                extend_run(run_row)
        await session.commit()
    payload = result.pop("_cursor_payload", None)
    out: dict[str, Any] = {k: v for k, v in result.items()}
    if payload is not None:
        out["cursor"] = mint_scan_cursor(payload, pepper, endpoint, p.plane)
    if new_run_token is not None:
        out["run_token"] = new_run_token
    if first_batch or (p.actor_kind == "operator_token" and not cursor_raw):
        detail: dict[str, object] = {}
        if getattr(request.state, "allow_sensitive", False):
            detail["allow_sensitive"] = True
        await record_audit(
            maker,
            actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
            action="rekey" if endpoint == "rekey" else "rekey_verify",
            item_name=None, ok=True, detail=detail,
        )
    return out


@router.post("/rekey")
async def post_rekey(
    request: Request, p: AdminPrincipal = Depends(require_admin)
) -> dict[str, Any]:
    return await _run_sweep(request, p, "rekey")
