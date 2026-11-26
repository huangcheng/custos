"""Admin item routes (design §6, plan 3). All writes return the masked
shape; the downgrade pre-gate peeks (never burns) the step-up token and
the engine re-checks under the row lock. Error precedence §4: the auth
dependencies run before any handler body."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, Response

from custos.admin.auth import (
    AdminPrincipal,
    require_admin,
    require_sensitive,
    require_sensitive_step_up,
    require_session_only,
    require_step_up_for,
)
from custos.admin.items import (
    _sensitive_detail,
    admin_env,
    history_list,
    history_reveal,
    masked_get,
    purge,
    restore,
    reveal,
)
from custos.errors import AppError
from custos.items import create_item, force_drop, patch_item, put_item, soft_delete
from custos.routes_agent import _etag, _json_body, _page_limit, list_via_engine

router = APIRouter(prefix="/api/admin")


@router.get("/items")
async def list_items(
    request: Request,
    cursor: str | None = None,
    limit: str | None = None,
    p: AdminPrincipal = Depends(require_admin),
) -> dict[str, Any]:
    result = await list_via_engine(
        request.app.state, p, "admin_list", cursor=cursor,
        limit=_page_limit(limit), include_deleted=True,
    )
    # §4: admin enumeration reads are NOT audited individually
    return result


@router.get("/items/{name}")
async def get_masked(
    name: str, request: Request, response: Response,
    p: AdminPrincipal = Depends(require_admin),
) -> dict[str, Any]:
    async with request.app.state.session_maker() as session:
        result = await masked_get(session, request.app.state.vault, name)
    _etag(response, result["revision"])
    return result


@router.get("/items/{name}/reveal")
async def get_reveal(
    name: str, request: Request, response: Response,
    p: AdminPrincipal = Depends(require_sensitive),
) -> dict[str, Any]:
    async with request.app.state.session_maker() as session:
        result = await reveal(
            session, request.app.state.session_maker, request.app.state.vault, p, name,
            _sensitive_detail(request.state),
        )
    _etag(response, result["revision"])
    return result


@router.get("/items/{name}/env")
async def get_env(
    name: str, request: Request,
    allow_hazardous: str | None = None,
    p: AdminPrincipal = Depends(require_sensitive),
) -> Response:
    # rev 41 dropped the prompt for the plain read only. Emitting the hazardous
    # deny-set (PATH, LD_*, …) is an override, not a read: an allow_sensitive
    # token passes, an operator session must present a step-up. (Plain tokens
    # never reach here — require_sensitive already refused them with 403.)
    # Decide from the principal, not the audit marker on request.state.
    if allow_hazardous == "1" and not p.allow_sensitive:
        await require_step_up_for(request, p)
    async with request.app.state.session_maker() as session:
        output = await admin_env(
            session, request.app.state.session_maker, request.app.state.vault, p, name,
            allow_hazardous == "1", _sensitive_detail(request.state),
        )
    return Response(content=output, media_type="text/plain; charset=utf-8")


@router.get("/items/{name}/history")
async def get_history(
    name: str, request: Request,
    cursor: str | None = None,
    limit: str | None = None,
    p: AdminPrincipal = Depends(require_admin),
) -> dict[str, Any]:
    async with request.app.state.session_maker() as session:
        return await history_list(
            session, request.app.state.session_maker, p, name,
            request.app.state.settings.pepper_raw, cursor, _page_limit(limit),
        )


@router.get("/items/{name}/history/{snapshot_id}/reveal")
async def get_history_reveal(
    name: str, snapshot_id: uuid.UUID, request: Request,
    p: AdminPrincipal = Depends(require_sensitive),
) -> dict[str, Any]:
    async with request.app.state.session_maker() as session:
        return await history_reveal(
            session, request.app.state.session_maker, request.app.state.vault, p,
            name, snapshot_id, _sensitive_detail(request.state),
        )


@router.post("/items", status_code=201)
async def create_one(
    request: Request, response: Response,
    p: AdminPrincipal = Depends(require_admin),
) -> dict[str, Any]:
    body = await _json_body(request)
    async with request.app.state.session_maker() as session:
        result = await create_item(
            session, request.app.state.session_maker, request.app.state.vault, p,
            body, mask=True,
        )
        await session.commit()
    _etag(response, result["revision"])
    return result


async def _write_with_downgrade_gate(
    request: Request, p: AdminPrincipal, name: str, body: dict[str, Any],
    if_match: str | None, verb: str,
) -> dict[str, Any]:
    """PUT/PATCH share the pre-gate: plan against current views; a detected
    downgrade needs allow_sensitive or a VALID (peeked, unburned) step-up;
    the engine re-classifies under the row lock and consumes on success."""
    from sqlalchemy import select

    from custos.admin.auth import _header_step_up
    from custos.db.models import Item
    from custos.items import _decrypt_views, _load_fields
    from custos.limits import DowngradeError, plan_patch_ops, plan_put_ops

    engine_fn = put_item if verb == "put" else patch_item
    maker = request.app.state.session_maker
    vault = request.app.state.vault

    async def _run(allow_downgrade: bool) -> dict[str, Any]:
        async with maker() as session:
            result = await engine_fn(
                session, maker, vault, p, name, body, if_match=if_match,
                mask=True, allow_downgrade=allow_downgrade,
            )
            await session.commit()
        return result

    # pre-gate: read-only classification (no locks, no burns)
    async with maker() as session:
        item = (
            await session.execute(select(Item).where(Item.name == name))
        ).scalar_one_or_none()
        downgrade = False
        if item is not None and item.deleted_at is None:
            try:
                views = _decrypt_views(vault, await _load_fields(session, item.id))
            except AppError:
                views = None  # degraded: the engine call produces the 500
            if views is not None:
                try:
                    if verb == "put":
                        plan_put_ops(name, body, views)
                    else:
                        plan_patch_ops(body, views, path_name=name)
                except DowngradeError:
                    downgrade = True
                except AppError:
                    pass  # validation errors surface from the engine call
    if not downgrade:
        return await _run(False)
    if p.actor_kind == "operator_token":
        if not p.allow_sensitive:
            raise AppError("step_up_required", "step-up required")
        # the engine marks detail.allow_sensitive from p.allow_sensitive
        return await _run(True)
    # No downgrade applies without a valid gate: burn the single-use step-up
    # BEFORE the write so two concurrent requests cannot both apply it
    # (single-use is a hard §5 invariant; a post-consume write failure is the
    # same accepted cost as every other step-gated route).
    await _header_step_up(request, p, consume=True)
    return await _run(True)


@router.put("/items/{name}")
async def put_one(
    name: str, request: Request, response: Response,
    p: AdminPrincipal = Depends(require_admin),
) -> dict[str, Any]:
    body = await _json_body(request)
    result = await _write_with_downgrade_gate(
        request, p, name, body, request.headers.get("if-match"), "put"
    )
    _etag(response, result["revision"])
    return result


@router.patch("/items/{name}")
async def patch_one(
    name: str, request: Request, response: Response,
    p: AdminPrincipal = Depends(require_admin),
) -> dict[str, Any]:
    body = await _json_body(request)
    result = await _write_with_downgrade_gate(
        request, p, name, body, request.headers.get("if-match"), "patch"
    )
    _etag(response, result["revision"])
    return result


@router.delete("/items/{name}", status_code=204)
async def delete_one(
    name: str, request: Request,
    p: AdminPrincipal = Depends(require_admin),
) -> Response:
    async with request.app.state.session_maker() as session:
        await soft_delete(session, request.app.state.session_maker,
                          request.app.state.vault, p, name)
        await session.commit()
    return Response(status_code=204)


@router.post("/items/{name}/restore")
async def restore_one(
    name: str, request: Request, response: Response,
    p: AdminPrincipal = Depends(require_sensitive_step_up),
) -> dict[str, Any]:
    async with request.app.state.session_maker() as session:
        result = await restore(
            session, p, name, _sensitive_detail(request.state),
        )
        await session.commit()
    _etag(response, result["revision"])
    return result


@router.delete("/items/{name}/purge", status_code=204)
async def purge_one(
    name: str, request: Request,
    p: AdminPrincipal = Depends(require_session_only),
) -> Response:
    async with request.app.state.session_maker() as session:
        await purge(session, p, name)
        await session.commit()
    return Response(status_code=204)


@router.post("/items/{name}/force-drop")
async def force_drop_one(
    name: str, request: Request,
    p: AdminPrincipal = Depends(require_session_only),
) -> dict[str, int]:
    async with request.app.state.session_maker() as session:
        dropped = await force_drop(
            session, request.app.state.session_maker, request.app.state.vault,
            p, name, actor_kind="operator_session",
        )
        await session.commit()
    return {"dropped_unreadable": dropped}
