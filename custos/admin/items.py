"""Admin item engines (design §6, plan 3): masked reads, gated reveal/env,
history metadata + per-snapshot reveal. All value-producing paths run
AFTER the auth gates (error precedence §4); masked/list reads never fail
on unreadable blobs — they render `unavailable: true` (masked get only).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from custos.admin.auth import AdminPrincipal
from custos.audit import record_audit
from custos.crypto import UnreadableError, Vault
from custos.cursors import mint_cursor, read_cursor
from custos.db.models import Field, FieldHistory, Item
from custos.envexport import env_lines
from custos.errors import AppError
from custos.items import get_item
from custos.limits import FieldView


def _not_found() -> AppError:
    return AppError("not_found", "not found")


async def _get_any_item(session: AsyncSession, name: str) -> Item:
    item = (
        await session.execute(select(Item).where(Item.name == name))
    ).scalar_one_or_none()
    if item is None:
        raise _not_found()
    return item


async def masked_get(
    session: AsyncSession, vault: Vault, name: str
) -> dict[str, Any]:
    """Secrets masked; unreadable secrets render unavailable:true. Works on
    soft-deleted items. Enumeration read — not audited (§4 closed set)."""
    item = await _get_any_item(session, name)
    rows = list(
        (await session.execute(select(Field).where(Field.item_id == item.id))).scalars()
    )
    fields: list[dict[str, Any]] = []
    for f in sorted(rows, key=lambda r: r.name):
        if not f.secret:
            fields.append({"name": f.name, "secret": False, "value": f.value})
            continue
        entry: dict[str, Any] = {"name": f.name, "secret": True}
        if f.ciphertext is None or f.key_version is None:
            entry["unavailable"] = True
        else:
            try:
                vault.open("field", str(f.id), f.ciphertext, f.key_version)
            except UnreadableError:
                entry["unavailable"] = True
        fields.append(entry)
    return {
        "name": item.name,
        "notes": item.notes,
        "revision": item.revision,
        "deleted": item.deleted_at is not None,
        "fields": fields,
    }


def _sensitive_detail(request_state: Any) -> dict[str, object]:
    if getattr(request_state, "allow_sensitive", False):
        return {"allow_sensitive": True}
    return {}


async def _audit_read_failure(
    maker: async_sessionmaker[AsyncSession],
    p: AdminPrincipal,
    action: str,
    name: str,
    exc: AppError,
) -> None:
    """§4: degraded-mode value-read failures are audited (ok:false)."""
    await record_audit(
        maker,
        actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
        action=action, item_name=name, ok=False, detail={"reason": exc.code},
    )


async def reveal(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: AdminPrincipal,
    name: str,
    detail: dict[str, object],
) -> dict[str, Any]:
    try:
        result = await get_item(session, maker, vault, p, name, include_deleted=True)
    except AppError as exc:
        await _audit_read_failure(maker, p, "reveal", name, exc)
        raise
    await record_audit(
        maker,
        actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
        action="reveal", item_name=name, ok=True, detail=detail,
    )
    return result


async def admin_env(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: AdminPrincipal,
    name: str,
    allow_hazardous: bool,
    detail: dict[str, object],
) -> str:
    try:
        result = await get_item(session, maker, vault, p, name, include_deleted=True)
    except AppError as exc:
        await _audit_read_failure(maker, p, "env", name, exc)
        raise
    views = [FieldView(f["name"], f["secret"], f["value"]) for f in result["fields"]]
    output = env_lines(views, allow_hazardous=allow_hazardous)
    await record_audit(
        maker,
        actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
        action="env", item_name=name, ok=True, detail=detail,
    )
    return output


async def history_list(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    p: AdminPrincipal,
    name: str,
    pepper: bytes,
    cursor: str | None,
    limit: int,
) -> dict[str, Any]:
    item = await _get_any_item(session, name)
    endpoint = f"admin_history:{name}"
    payload = read_cursor(cursor, pepper, endpoint, p.plane) if cursor else {}
    stmt = (
        select(
            FieldHistory.id, FieldHistory.name, FieldHistory.secret,
            FieldHistory.superseded_at, FieldHistory.superseded_by,
            FieldHistory.actor_label,
        )
        .where(FieldHistory.item_id == item.id)
        .order_by(FieldHistory.superseded_at.desc(), FieldHistory.id.desc())
    )
    if "ts" in payload and "id" in payload:
        from datetime import datetime

        stmt = stmt.where(
            tuple_(FieldHistory.superseded_at, FieldHistory.id)
            < (datetime.fromisoformat(payload["ts"]), uuid.UUID(payload["id"]))
        )
    rows = list((await session.execute(stmt.limit(limit + 1))).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more and rows:
        next_cursor = mint_cursor(
            {"ts": rows[-1].superseded_at.isoformat(), "id": str(rows[-1].id)},
            pepper, endpoint, p.plane,
        )
    result = {
        "items": [
            {
                "id": str(r.id),
                "name": r.name,
                "secret": r.secret,
                "superseded_at": r.superseded_at.isoformat(),
                "superseded_by": r.superseded_by,
                "actor_label": r.actor_label,
            }
            for r in rows
        ],
        "next_cursor": next_cursor,
    }
    await record_audit(
        maker,
        actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
        action="history", item_name=name, ok=True, detail={"count": len(rows)},
    )
    return result


def _open_snapshot(vault: Vault, snap: FieldHistory) -> str:
    if snap.secret:
        if snap.ciphertext is None or snap.key_version is None:
            raise AppError("key_unavailable", "field value unavailable")
        try:
            return vault.open(
                "fieldh", str(snap.id), snap.ciphertext, snap.key_version
            ).decode()
        except (UnreadableError, UnicodeDecodeError) as exc:
            raise AppError("key_unavailable", "field value unavailable") from exc
    if snap.value is None:
        raise AppError("key_unavailable", "field value unavailable")
    return snap.value


async def history_reveal(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: AdminPrincipal,
    name: str,
    snapshot_id: uuid.UUID,
    detail: dict[str, object],
) -> dict[str, Any]:
    item = await _get_any_item(session, name)
    snap = await session.get(FieldHistory, snapshot_id)
    if snap is None or snap.item_id != item.id:
        raise _not_found()  # snapshot must belong to the named item (§6)
    try:
        value = _open_snapshot(vault, snap)
    except AppError as exc:
        await _audit_read_failure(maker, p, "reveal", item.name, exc)
        raise
    await record_audit(
        maker,
        actor_kind=p.actor_kind, actor_id=p.actor_id, actor_label=p.actor_label,
        action="reveal", item_name=item.name, ok=True, detail={**detail, "count": 1},
    )
    return {
        "id": str(snap.id),
        "name": snap.name,
        "secret": snap.secret,
        "value": value,
        "superseded_at": snap.superseded_at.isoformat(),
    }


async def restore(
    session: AsyncSession,
    p: AdminPrincipal,
    name: str,
    detail: dict[str, object],
) -> dict[str, Any]:
    """Metadata-only (§4): clears deleted_at, bumps revision. Works on
    unreadable items — no decryption, no cap measurement."""
    item = (
        await session.execute(
            select(Item).where(Item.name == name).with_for_update()
        )
    ).scalar_one_or_none()
    if item is None:
        raise _not_found()
    if item.deleted_at is None:
        raise AppError("conflict", "item is not deleted")
    pre_revision = item.revision
    item.deleted_at = None
    item.revision += 1
    await session.flush()
    from custos.items import _audit_write

    await _audit_write(session, p, "restore", item, pre_revision, [], dict(detail))
    rows = list(
        (await session.execute(select(Field).where(Field.item_id == item.id))).scalars()
    )
    return {
        "name": item.name,
        "notes": item.notes,
        "revision": item.revision,
        "deleted": False,
        "fields": [
            {"name": f.name, "secret": True} if f.secret
            else {"name": f.name, "secret": False, "value": f.value}
            for f in sorted(rows, key=lambda r: r.name)
        ],
    }


async def purge(
    session: AsyncSession,
    p: AdminPrincipal,
    name: str,
) -> None:
    """Hard-delete in one transaction, order pinned by §4: history rows
    first, then fields, then the item row (no FK cascade reliance). The
    success audit commits WITH the deletion — a rolled-back purge leaves
    no ok:true row."""
    from custos.audit import _validate_actor, _validate_detail
    from custos.db.models import AuditRow

    # engine-level operator guard (mirrors force_drop): purge is session-only
    if p.actor_kind != "operator_session":
        raise AppError("session_required", "purge is session-only")
    _validate_actor(p.actor_kind, p.actor_id)
    item = (
        await session.execute(
            select(Item).where(Item.name == name).with_for_update()
        )
    ).scalar_one_or_none()
    if item is None:
        raise _not_found()
    hist = await session.execute(
        delete(FieldHistory).where(FieldHistory.item_id == item.id)
    )
    flds = await session.execute(delete(Field).where(Field.item_id == item.id))
    await session.delete(item)
    await session.flush()
    total = int(hist.rowcount) + int(flds.rowcount) + 1  # type: ignore[attr-defined]
    detail: dict[str, object] = {"count": total}
    _validate_detail(detail)
    session.add(
        AuditRow(
            actor_kind=p.actor_kind,
            actor_id=p.actor_id,
            actor_label=p.actor_label,
            action="purge",
            item_name=name,
            ok=True,
            detail=detail,
        )
    )
