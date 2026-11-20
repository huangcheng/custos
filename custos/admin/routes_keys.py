"""Admin key/token management (design §6, plan 3).

Mint/revoke are session+step-up ONLY (require_session_only 403s any
token before state checks). Inventories are plain admin reads but
audited (key.list/token.list — reconnaissance leaves a trace, §4).
Token revocation cascade-deletes bound unconsumed step-up/run rows in
the same transaction (§5); success audits commit WITH the mutation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import delete, select

from custos.admin.auth import AdminPrincipal, require_admin, require_session_only
from custos.audit import record_audit
from custos.db.models import AgentKey, AuditRow, OperatorToken, StepUpToken
from custos.errors import AppError
from custos.keys import mint_agent_key
from custos.operator_tokens import mint_operator_token
from custos.routes_agent import _json_body

router = APIRouter(prefix="/api/admin")

_MODES = ("read", "read-write")


def _invalid(message: str) -> AppError:
    return AppError("invalid", message)


def _label(body: dict[str, Any]) -> str:
    label = body.get("label")
    if not isinstance(label, str) or not 1 <= len(label) <= 200:
        raise _invalid("label must be 1..200 characters")
    return label


def _parse_expiry(raw: Any) -> datetime | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise _invalid("expires_at must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        raise _invalid("expires_at must be an ISO 8601 string") from None
    if parsed.tzinfo is None:
        raise _invalid("expires_at must carry a timezone")
    return parsed


def _audit_in_txn(
    session: Any, p: AdminPrincipal, action: str, detail: dict[str, object]
) -> None:
    from custos.audit import ACTION_ENUM, ACTOR_KINDS, _validate_actor, _validate_detail

    if action not in ACTION_ENUM:
        raise ValueError(f"audit action {action!r} is not in the closed enum")
    if p.actor_kind not in ACTOR_KINDS:
        raise ValueError(f"actor kind {p.actor_kind!r} is not in the closed enum")
    _validate_actor(p.actor_kind, p.actor_id)
    _validate_detail(detail)
    session.add(
        AuditRow(
            actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
            action=action, item_name=None, ok=True, detail=detail,
        )
    )


@router.post("/keys", status_code=201)
async def mint_key(
    request: Request, p: AdminPrincipal = Depends(require_session_only)
) -> dict[str, Any]:
    body = await _json_body(request)
    label = _label(body)
    mode = body.get("mode")
    if mode not in _MODES:
        raise _invalid("mode must be read or read-write")
    scopes = body.get("scopes")
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        raise _invalid("scopes must be a list of strings")
    expires_at = _parse_expiry(body.get("expires_at"))
    if expires_at is not None and expires_at <= datetime.now(UTC):
        raise _invalid("expires_at must be in the future")
    token, draft = mint_agent_key(request.app.state.settings.pepper_raw)
    async with request.app.state.session_maker() as session:
        row = AgentKey(key_id=draft.key_id, digest=draft.digest, label=label,
                       mode=mode, scopes=scopes, expires_at=expires_at)
        session.add(row)
        await session.flush()
        _audit_in_txn(session, p, "key.mint", {"key_id": draft.key_id})
        await session.commit()
        created_at = row.created_at
    return {
        "token": token,  # shown exactly once
        "key_id": draft.key_id, "label": label, "mode": mode, "scopes": scopes,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "created_at": created_at.isoformat(),
    }


@router.get("/keys")
async def list_keys(
    request: Request, p: AdminPrincipal = Depends(require_admin)
) -> dict[str, Any]:
    async with request.app.state.session_maker() as session:
        rows = list((await session.execute(
            select(AgentKey).order_by(AgentKey.created_at))).scalars())
    keys = [
        {
            "key_id": r.key_id, "label": r.label, "mode": r.mode, "scopes": r.scopes,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
    await record_audit(
        request.app.state.session_maker,
        actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
        action="key.list", item_name=None, ok=True, detail={"count": len(keys)},
    )
    return {"keys": keys}


@router.delete("/keys/{key_id}", status_code=204)
async def revoke_key(
    key_id: str, request: Request,
    p: AdminPrincipal = Depends(require_session_only),
) -> Response:
    async with request.app.state.session_maker() as session:
        row = (await session.execute(
            select(AgentKey).where(AgentKey.key_id == key_id).with_for_update()
        )).scalar_one_or_none()
        if row is None:
            raise AppError("not_found", "not found")
        if row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)
        _audit_in_txn(session, p, "key.revoke", {"key_id": key_id})
        await session.commit()
    return Response(status_code=204)


@router.post("/tokens", status_code=201)
async def mint_token(
    request: Request, p: AdminPrincipal = Depends(require_session_only)
) -> dict[str, Any]:
    body = await _json_body(request)
    label = _label(body)
    allow_sensitive = body.get("allow_sensitive", False)
    if not isinstance(allow_sensitive, bool):
        raise _invalid("allow_sensitive must be a boolean")
    expires_at = _parse_expiry(body.get("expires_at"))
    # mint validates the mandatory expiry + caps itself (Task 1)
    token, draft = mint_operator_token(
        request.app.state.settings.pepper_raw,
        expires_at=expires_at, allow_sensitive=allow_sensitive,
    )
    async with request.app.state.session_maker() as session:
        row = OperatorToken(key_id=draft.key_id, digest=draft.digest, label=label,
                            allow_sensitive=allow_sensitive, expires_at=draft.expires_at)
        session.add(row)
        await session.flush()
        detail: dict[str, object] = {"key_id": draft.key_id}
        if allow_sensitive:
            detail["allow_sensitive"] = True
        _audit_in_txn(session, p, "token.mint", detail)
        await session.commit()
        created_at = row.created_at
    return {
        "token": token,  # shown exactly once
        "key_id": draft.key_id, "label": label, "allow_sensitive": allow_sensitive,
        "expires_at": draft.expires_at.isoformat(),
        "created_at": created_at.isoformat(),
    }


@router.get("/tokens")
async def list_tokens(
    request: Request, p: AdminPrincipal = Depends(require_admin)
) -> dict[str, Any]:
    async with request.app.state.session_maker() as session:
        rows = list((await session.execute(
            select(OperatorToken).order_by(OperatorToken.created_at))).scalars())
    tokens = [
        {
            "key_id": r.key_id, "label": r.label, "allow_sensitive": r.allow_sensitive,
            "expires_at": r.expires_at.isoformat(),
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
    await record_audit(
        request.app.state.session_maker,
        actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
        action="token.list", item_name=None, ok=True, detail={"count": len(tokens)},
    )
    return {"tokens": tokens}


@router.delete("/tokens/{key_id}", status_code=204)
async def revoke_token(
    key_id: str, request: Request,
    p: AdminPrincipal = Depends(require_session_only),
) -> Response:
    async with request.app.state.session_maker() as session:
        row = (await session.execute(
            select(OperatorToken).where(OperatorToken.key_id == key_id).with_for_update()
        )).scalar_one_or_none()
        if row is None:
            raise AppError("not_found", "not found")
        if row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)
        # §5: a revoked token never leaves a live bound step-up/run token
        await session.execute(
            delete(StepUpToken).where(
                StepUpToken.operator_token_id == row.id,
                StepUpToken.consumed_at.is_(None),
            )
        )
        _audit_in_txn(session, p, "token.revoke", {"key_id": key_id})
        await session.commit()
    return Response(status_code=204)
