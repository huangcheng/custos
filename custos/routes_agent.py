"""Agent-plane REST routes (design §6). Thin: parse → engine → shape → audit.

All access goes through the engine's check order (scope → mode → existence);
out-of-scope is byte-identical to missing. List/search are metadata-only,
exclude soft-deleted items, and paginate with opaque cursors (50/100).
"""

from __future__ import annotations

import json as _json
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, or_, select

from custos.audit import LedgerError, record_audit
from custos.auth_agent import agent_principal
from custos.cursors import mint_cursor, read_cursor
from custos.db.models import Field, Item
from custos.envexport import env_lines
from custos.errors import AppError
from custos.items import (
    Principal,
    create_item,
    get_item,
    patch_item,
    put_item,
    soft_delete,
)
from custos.keys import AgentPrincipal
from custos.limits import FieldView
from custos.scopes import scope_allows

router = APIRouter(prefix="/api")

_PAGE_SIZES = (50, 100)
_BODY_MAX = 2 * 1024 * 1024  # §4 request-body cap


async def _json_body(request: Request) -> dict[str, Any]:
    """Bounded body read: Content-Length gate + streamed cap (chunked too)."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError:
            raise AppError("invalid", "invalid content-length") from None
        if length > _BODY_MAX:
            raise AppError("payload_too_large", "request body exceeds 2 MiB")
    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > _BODY_MAX:
            raise AppError("payload_too_large", "request body exceeds 2 MiB")
    try:
        body = _json.loads(bytes(chunks))
    except (ValueError, UnicodeDecodeError):
        raise AppError("invalid", "malformed JSON body") from None
    if not isinstance(body, dict):
        raise AppError("invalid", "body must be an object")
    return body


def _page_limit(raw: str | None) -> int:
    if raw is None:
        return 50
    try:
        limit = int(raw)
    except ValueError:
        raise AppError("invalid", "invalid limit") from None
    if limit not in _PAGE_SIZES:
        raise AppError("invalid", "limit must be 50 or 100")
    return limit


async def _audit_denial(request: Request, key: AgentPrincipal, action: str, name: Any,
                        exc: AppError) -> None:
    # out-of-scope probes and mode denials are visible in the ledger (§5);
    # shares the global failure budget; called AFTER the handler session closes.
    from custos.limits import valid_item_name

    normalized = valid_item_name(name)
    try:
        await record_audit(
            request.app.state.session_maker,
            actor_kind="agent", actor_id=key.key_id, actor_label=key.actor_label,
            action=action, item_name=normalized, ok=False,
            detail={"reason": exc.code},  # wire-indistinguishable causes stay neutral
            budget=request.app.state.ledger_budget,
            counter=request.app.state.failure_counter,
        )
    except LedgerError:
        raise AppError("internal_error", "ledger unavailable") from None


def _etag(response: Response, revision: int) -> None:
    response.headers["ETag"] = f'"{revision}"'


def _list_row(
    item: Item, fields: list[tuple[str, bool]], include_deleted: bool = False
) -> dict[str, Any]:
    row = {
        "name": item.name,
        "notes": item.notes[:256],
        "revision": item.revision,
        "updated_at": item.updated_at.isoformat(),
        "fields": [{"name": n, "secret": s} for n, s in sorted(fields)],
    }
    if include_deleted:
        row["deleted"] = item.deleted_at is not None
    return row


async def list_via_engine(
    state: Any,
    key: Principal,
    endpoint: str,
    cursor: str | None = None,
    limit: int = 50,
    q: str | None = None,
    include_deleted: bool = False,
) -> dict[str, Any]:
    """Shared by REST list/search and the MCP tools — one implementation."""
    session_maker = state.session_maker
    binding = getattr(key, "plane", key.actor_id)
    pepper = state.settings.pepper_raw
    limit = _page_limit(str(limit))
    search = q
    cursor_payload: dict[str, Any] = {}
    if cursor is not None:
        cursor_payload = read_cursor(cursor, pepper, endpoint, binding)
    async with session_maker() as session:
        # scan narrow columns only: notes/blobs never loaded for scope checks
        stmt = select(Item.id, Item.name).order_by(Item.name)
        if not include_deleted:
            stmt = stmt.where(Item.deleted_at.is_(None))
        if "after" in cursor_payload:
            stmt = stmt.where(Item.name > cursor_payload["after"])
        if search is not None:
            escaped = search.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            plain_names = (
                select(Field.item_id)
                .where(Field.secret.is_(False), func.lower(Field.name).like(pattern, escape="\\"))
                .scalar_subquery()
            )
            stmt = stmt.where(
                or_(
                    func.lower(Item.name).like(pattern, escape="\\"),
                    func.lower(Item.notes).like(pattern, escape="\\"),
                    Item.id.in_(plain_names),
                )
            )
        # scope-filter BEFORE the page cut. The scan advances past the last
        # VISIBLE row only — out-of-scope rows are re-scanned next page, so a
        # short page never silently drops in-scope items behind them.
        visible: list[tuple[Any, str]] = []
        has_more = False
        scan_exhausted = False
        offset_name = cursor_payload.get("after")
        last_visible: str | None = None
        for _ in range(20):
            batch_stmt = stmt.limit(limit * 4)
            if offset_name is not None:
                batch_stmt = batch_stmt.where(Item.name > offset_name)
            batch = list((await session.execute(batch_stmt)).all())
            if not batch:
                scan_exhausted = True
                break
            for row_id, row_name in batch:
                if scope_allows(key.scopes, row_name):
                    if len(visible) == limit:
                        has_more = True
                        break
                    visible.append((row_id, row_name))
                    last_visible = row_name
            if has_more:
                break
            if len(batch) < limit * 4:
                scan_exhausted = True
                break
            offset_name = batch[-1][1]
        items_by_id: dict[Any, Item] = {}
        fields_by_item: dict[Any, list[tuple[str, bool]]] = {}
        if visible:
            ids = [i[0] for i in visible]
            for item in (
                await session.execute(
                    select(Item).where(Item.id.in_(ids))
                )
            ).scalars():
                if include_deleted or item.deleted_at is None:
                    items_by_id[item.id] = item
            # metadata columns only — never ciphertext/value blobs on list paths
            for item_id, fname, fsecret in (
                await session.execute(
                    select(Field.item_id, Field.name, Field.secret).where(
                        Field.item_id.in_(ids)
                    )
                )
            ).all():
                fields_by_item.setdefault(item_id, []).append((fname, fsecret))
    next_cursor = None
    if has_more and last_visible is not None:
        next_cursor = mint_cursor({"after": last_visible}, pepper, endpoint, binding)
    elif not scan_exhausted and offset_name is not None:
        # scan budget hit with nothing visible: resume from the scan edge so
        # the caller can always make progress through out-of-scope stretches
        next_cursor = mint_cursor({"after": offset_name}, pepper, endpoint, binding)
    result = {
        "items": [
            _list_row(items_by_id[i[0]], fields_by_item.get(i[0], []), include_deleted)
            for i in visible
            if i[0] in items_by_id  # soft-deleted between scan and hydrate
        ],
        "next_cursor": next_cursor,
    }
    # §4 defensive assertion: legal metadata pages are ~110 KB max
    if len(_json.dumps(result, ensure_ascii=True).encode()) > 1024 * 1024:
        raise AppError("payload_too_large", "page exceeds 1 MiB")
    return result


@router.get("/items")
async def list_items(
    request: Request, key: AgentPrincipal = Depends(agent_principal)
) -> dict[str, Any]:
    result = await list_via_engine(
        request.app.state, key, "list",
        cursor=request.query_params.get("cursor"),
        limit=_page_limit(request.query_params.get("limit")),
    )
    await record_audit(
        request.app.state.session_maker,
        actor_kind="agent", actor_id=key.key_id, actor_label=key.actor_label,
        action="list", item_name=None, ok=True,
        detail={"count": len(result["items"])},
    )
    return result


@router.get("/search")
async def search_items(
    request: Request, key: AgentPrincipal = Depends(agent_principal)
) -> dict[str, Any]:
    q = request.query_params.get("q", "")
    if not q:
        raise AppError("invalid", "q is required")
    if len(q) > 256:
        raise AppError("invalid", "q too long")
    result = await list_via_engine(
        request.app.state, key, "search",
        cursor=request.query_params.get("cursor"),
        limit=_page_limit(request.query_params.get("limit")),
        q=q,
    )
    # audit detail carries the result count only — never q (§6)
    await record_audit(
        request.app.state.session_maker,
        actor_kind="agent", actor_id=key.key_id, actor_label=key.actor_label,
        action="search", item_name=None, ok=True,
        detail={"count": len(result["items"])},
    )
    return result


@router.get("/items/{name}")
async def get_one(
    name: str, request: Request, response: Response,
    key: AgentPrincipal = Depends(agent_principal),
) -> dict[str, Any]:
    denial: AppError | None = None
    async with request.app.state.session_maker() as session:
        try:
            result = await get_item(
                session, request.app.state.session_maker, request.app.state.vault, key, name
            )
        except AppError as exc:
            if exc.code not in ("not_found", "read_only", "key_unavailable"):
                raise
            denial = exc
    if denial is not None:
        await _audit_denial(request, key, "get", name, denial)
        raise denial
    _etag(response, result["revision"])
    from custos.telemetry import annotate_span

    annotate_span(key.actor_id, "get", name)
    await record_audit(
        request.app.state.session_maker,
        actor_kind="agent", actor_id=key.key_id, actor_label=key.actor_label,
        action="get", item_name=name, ok=True, detail={},
    )
    return result


@router.get("/items/{name}/env")
async def get_env(
    name: str, request: Request, key: AgentPrincipal = Depends(agent_principal)
) -> Response:
    denial: AppError | None = None
    async with request.app.state.session_maker() as session:
        try:
            result = await get_item(
                session, request.app.state.session_maker, request.app.state.vault, key, name
            )
        except AppError as exc:
            if exc.code not in ("not_found", "read_only", "key_unavailable"):
                raise
            denial = exc
    if denial is not None:
        await _audit_denial(request, key, "env", name, denial)
        raise denial
    views = [FieldView(f["name"], f["secret"], f["value"]) for f in result["fields"]]
    output = env_lines(views)  # agent plane: unconditional refusal
    await record_audit(
        request.app.state.session_maker,
        actor_kind="agent", actor_id=key.key_id, actor_label=key.actor_label,
        action="env", item_name=name, ok=True, detail={},
    )
    return Response(content=output, media_type="text/plain; charset=utf-8")


@router.post("/items", status_code=201)
async def create_one(
    request: Request, response: Response, key: AgentPrincipal = Depends(agent_principal)
) -> dict[str, Any]:
    body = await _json_body(request)
    denial: AppError | None = None
    async with request.app.state.session_maker() as session:
        try:
            result = await create_item(
                session, request.app.state.session_maker, request.app.state.vault, key, body
            )
        except AppError as exc:
            if exc.code not in ("not_found", "read_only", "key_unavailable"):
                raise
            denial = exc
        else:
            await session.commit()
    if denial is not None:
        await _audit_denial(request, key, "create", body.get("name"), denial)
        raise denial
    _etag(response, result["revision"])
    return result


@router.put("/items/{name}")
async def put_one(
    name: str, request: Request, response: Response,
    key: AgentPrincipal = Depends(agent_principal),
) -> dict[str, Any]:
    body = await _json_body(request)
    upsert = request.query_params.get("upsert") == "1"
    if_match = request.headers.get("if-match")
    denial: AppError | None = None
    async with request.app.state.session_maker() as session:
        try:
            result = await put_item(
                session, request.app.state.session_maker, request.app.state.vault, key, name,
                body, if_match=if_match, upsert=upsert,
            )
        except AppError as exc:
            if exc.code not in ("not_found", "read_only", "key_unavailable"):
                raise
            denial = exc
        else:
            await session.commit()
    if denial is not None:
        await _audit_denial(request, key, "put", name, denial)
        raise denial
    response.status_code = 201 if result.get("created") else 200
    _etag(response, result["revision"])
    return result


@router.patch("/items/{name}")
async def patch_one(
    name: str, request: Request, response: Response,
    key: AgentPrincipal = Depends(agent_principal),
) -> dict[str, Any]:
    body = await _json_body(request)
    if_match = request.headers.get("if-match")
    denial: AppError | None = None
    async with request.app.state.session_maker() as session:
        try:
            result = await patch_item(
                session, request.app.state.session_maker, request.app.state.vault, key, name,
                body, if_match=if_match,
            )
        except AppError as exc:
            if exc.code not in ("not_found", "read_only", "key_unavailable"):
                raise
            denial = exc
        else:
            await session.commit()
    if denial is not None:
        await _audit_denial(request, key, "patch", name, denial)
        raise denial
    _etag(response, result["revision"])
    return result


@router.delete("/items/{name}", status_code=204)
async def delete_one(
    name: str, request: Request, key: AgentPrincipal = Depends(agent_principal)
) -> Response:
    denial: AppError | None = None
    async with request.app.state.session_maker() as session:
        try:
            await soft_delete(
                session, request.app.state.session_maker, request.app.state.vault, key, name
            )
        except AppError as exc:
            if exc.code not in ("not_found", "read_only", "key_unavailable"):
                raise
            denial = exc
        else:
            await session.commit()
    if denial is not None:
        await _audit_denial(request, key, "delete", name, denial)
        raise denial
    return Response(status_code=204)
