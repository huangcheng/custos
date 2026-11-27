"""Item write engine (design §4/§6).

Every write is one transaction under ``SELECT … FOR UPDATE`` on the item
row: history append, budget eviction, and revision bump serialize per item.
Check order on the agent plane: scope → mode → existence/uniqueness.
History snapshots only actual changes/removals, re-sealed under the history
AAD at the newest keyring version; 20 snapshots per (item_id, name), global
100 000-row ceiling. Audit detail carries counts and evicted ids — never
values.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from custos.audit import add_audit_row
from custos.crypto import UnreadableError, Vault
from custos.db.models import Field, FieldHistory, Item
from custos.errors import AppError
from custos.limits import (
    DowngradeError,
    FieldView,
    Op,
    check_caps,
    plan_patch_ops,
    plan_put_ops,
    valid_field_name,
    valid_item_name,
    validate_post_body,
)

HISTORY_BUDGET = 20
HISTORY_CEILING = 100_000
_ETAG_RE = re.compile(r'^"([0-9]{1,10}|\*)"\Z')


class _Ceiling:
    """Global history ceiling guard: one advisory-locked count per write,
    incremented locally afterwards (hard cap across concurrent items)."""

    def __init__(self) -> None:
        self._total: int | None = None

    async def reserve(self, session: AsyncSession, net_new: int) -> None:
        if self._total is None:
            # xact-scoped advisory lock serializes ceiling checks globally
            await session.execute(text("SELECT pg_advisory_xact_lock(8147)"))
            self._total = (
                await session.execute(select(func.count()).select_from(FieldHistory))
            ).scalar_one()
        if self._total + net_new > HISTORY_CEILING:
            raise AppError("history_budget_exceeded", "global history ceiling reached")
        self._total += net_new


class Principal(Protocol):
    @property
    def actor_id(self) -> str: ...
    @property
    def actor_label(self) -> str: ...
    @property
    def actor_kind(self) -> str: ...
    # "agent" | "operator_session" | "operator_token" | "local_process"


def _not_found() -> AppError:
    return AppError("not_found", "not found")


async def _lock_item(session: AsyncSession, name: str) -> Item | None:
    return (
        await session.execute(select(Item).where(Item.name == name).with_for_update())
    ).scalar_one_or_none()


async def _load_fields(session: AsyncSession, item_id: Any) -> list[Field]:
    return list(
        (await session.execute(select(Field).where(Field.item_id == item_id))).scalars()
    )


def _decrypt_views(vault: Vault, fields: list[Field]) -> dict[str, FieldView]:
    views: dict[str, FieldView] = {}
    for f in fields:
        if f.secret:
            if f.ciphertext is None or f.key_version is None:
                raise AppError("key_unavailable", "field value unavailable")
            try:
                value = vault.open("field", str(f.id), f.ciphertext, f.key_version).decode()
            except (UnreadableError, UnicodeDecodeError) as exc:
                raise AppError("key_unavailable", "field value unavailable") from exc
        else:
            if f.value is None:
                raise AppError("key_unavailable", "field value unavailable")
            value = f.value
        views[f.name] = FieldView(name=f.name, secret=f.secret, value=value)
    return views


def _check_if_match(item: Item, if_match: str | None) -> None:
    if if_match is None:
        return
    match = _ETAG_RE.match(if_match)
    if match is None:
        raise AppError("invalid", "malformed If-Match entity-tag")
    if match.group(1) == "*":
        return  # require-exists: the row is locked, so it exists
    if int(match.group(1)) != item.revision:
        raise AppError("conflict", f"revision mismatch (current {item.revision})")


async def _append_history(
    session: AsyncSession,
    vault: Vault,
    p: Principal,
    item: Item,
    field: Field,
    view: FieldView,
    evicted_ids: list[str],
    ceiling: _Ceiling,
) -> None:
    name_count = (
        await session.execute(
            select(func.count())
            .select_from(FieldHistory)
            .where(FieldHistory.item_id == item.id, FieldHistory.name == field.name)
        )
    ).scalar_one()
    # this append evicts one row when the name budget is full — net-neutral
    net_new = 0 if name_count >= HISTORY_BUDGET else 1
    await ceiling.reserve(session, net_new)
    if view.secret:
        # history AAD binds the history row id — seal after the id exists
        hist = FieldHistory(
            id=uuid.uuid4(),
            field_id=field.id,
            item_id=item.id,
            name=field.name,
            secret=True,
            superseded_by=p.actor_id,
            actor_label=p.actor_label,
        )
        blob, version = vault.seal("fieldh", str(hist.id), view.value.encode())
        hist.ciphertext, hist.key_version = blob, version
    else:
        hist = FieldHistory(
            id=uuid.uuid4(),
            field_id=field.id,
            item_id=item.id,
            name=field.name,
            secret=False,
            value=view.value,
            superseded_by=p.actor_id,
            actor_label=p.actor_label,
        )
    session.add(hist)
    await session.flush()
    # budget eviction keyed by (item_id, name) across field-row ids
    rows = list(
        (
            await session.execute(
                select(FieldHistory)
                .where(FieldHistory.item_id == item.id, FieldHistory.name == field.name)
                .order_by(FieldHistory.superseded_at.desc(), FieldHistory.id.desc())
            )
        ).scalars()
    )
    for stale in rows[HISTORY_BUDGET:]:
        evicted_ids.append(str(stale.id))
        await session.delete(stale)


async def _apply_ops(
    session: AsyncSession,
    vault: Vault,
    p: Principal,
    item: Item,
    ops: list[Op],
    existing_rows: list[Field],
    existing_views: dict[str, FieldView],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Apply ops in array order; returns (response field entries, evicted ids)."""
    ceiling = _Ceiling()
    rows_by_name = {f.name: f for f in existing_rows}
    evicted_ids: list[str] = []
    supplied: dict[str, dict[str, Any]] = {}
    for op in ops:
        row = rows_by_name.get(op.name)
        if op.kind == "remove":
            if row is not None:
                await _append_history(
                    session, vault, p, item, row, existing_views[op.name], evicted_ids, ceiling
                )
                await session.delete(row)
                await session.flush()  # delete-flush-insert: unique never collides
                del rows_by_name[op.name]
        elif op.kind == "set":
            if op.value is None:
                raise RuntimeError("set op without value")
            before = existing_views.get(op.name)
            changed = before is None or before.value != op.value or before.secret != op.secret
            if row is not None and changed and op.name in existing_views:
                await _append_history(
                    session, vault, p, item, row, existing_views[op.name], evicted_ids, ceiling
                )
            if row is None:
                row = Field(id=uuid.uuid4(), item_id=item.id, name=op.name, secret=op.secret)
                if op.secret:
                    blob, version = vault.seal("field", str(row.id), op.value.encode())
                    row.ciphertext, row.key_version = blob, version
                else:
                    row.value = op.value
                session.add(row)
                await session.flush()
                rows_by_name[op.name] = row
            else:
                row.secret = op.secret
                if op.secret:
                    blob, version = vault.seal("field", str(row.id), op.value.encode())
                    row.ciphertext, row.key_version, row.value = blob, version, None
                else:
                    row.value, row.ciphertext, row.key_version = op.value, None, None
            supplied[op.name] = {"name": op.name, "secret": op.secret, "value": op.value}
            existing_views[op.name] = FieldView(op.name, op.secret, op.value)
        elif op.kind == "keep" and op.name not in supplied:
            view = existing_views.get(op.name)
            if view is not None and view.secret:
                supplied[op.name] = {"name": op.name, "secret": True, "kept": True}
            elif view is not None:
                supplied[op.name] = {"name": op.name, "secret": False, "value": view.value}
    return supplied, evicted_ids


def _materialize_post(
    existing_views: dict[str, FieldView], ops: list[Op]
) -> dict[str, FieldView]:
    state = dict(existing_views)
    for op in ops:
        if op.kind == "remove":
            state.pop(op.name, None)
        elif op.kind == "set":
            if op.value is None:
                raise RuntimeError("set op without value")
            state[op.name] = FieldView(op.name, op.secret, op.value)
    return state


async def _audit_write(
    session: AsyncSession,
    p: Principal,
    action: str,
    item: Item,
    pre_revision: int,
    evicted_ids: list[str],
    extra_detail: dict[str, Any] | None = None,
) -> None:
    """Success audits commit WITH the write (a rolled-back write leaves no
    ok:true row). Failure audits stay independent per §4."""
    from custos.audit import ACTION_ENUM, ACTOR_KINDS, _validate_actor, _validate_detail
    from custos.db.models import AuditRow

    detail: dict[str, Any] = {
        "pre_revision": pre_revision,
        "revision": item.revision,
        "evicted": len(evicted_ids),
    }
    if evicted_ids:
        detail["evicted_ids"] = evicted_ids[:64]
    if extra_detail:
        reserved = {"pre_revision", "revision", "evicted", "evicted_ids"}
        if reserved & extra_detail.keys():
            raise ValueError("extra_detail must not overwrite reserved audit keys")
        detail.update(extra_detail)
    if action not in ACTION_ENUM:
        raise ValueError(f"audit action {action!r} is not in the closed enum")
    actor_kind = getattr(p, "actor_kind", "agent")
    if actor_kind not in ACTOR_KINDS:
        raise ValueError(f"actor kind {actor_kind!r} is not in the closed enum")
    _validate_actor(actor_kind, p.actor_id)
    _validate_detail(detail)
    session.add(
        AuditRow(
            actor_kind=actor_kind,
            actor_id=p.actor_id,
            actor_label=p.actor_label,
            action=action,
            item_name=item.name,
            ok=True,
            detail=detail,
        )
    )


def _response(
    item: Item, supplied: dict[str, dict[str, Any]], notes: str, mask: bool = False
) -> dict[str, Any]:
    fields = sorted(supplied.values(), key=lambda f: f["name"])
    if mask:
        # §6/§11: admin write responses never carry secret values or kept echoes
        fields = [
            {"name": f["name"], "secret": True} if f["secret"] else f for f in fields
        ]
    return {
        "name": item.name,
        "notes": notes,
        "revision": item.revision,
        "fields": fields,
        "created": False,
    }


async def create_item(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: Principal,
    body: dict[str, Any],
    mask: bool = False,
) -> dict[str, Any]:
    name, notes, views = validate_post_body(body)
    existing = await _lock_item(session, name)
    if existing is not None:
        raise AppError("conflict", "name exists")
    item = Item(name=name, notes=notes)
    session.add(item)
    try:
        await session.flush()
    except IntegrityError:
        # concurrent create of the same name: unique index arbitrated
        raise AppError("conflict", "name exists") from None
    supplied: dict[str, dict[str, Any]] = {}
    for view in views:
        row = Field(id=uuid.uuid4(), item_id=item.id, name=view.name, secret=view.secret)
        if view.secret:
            blob, version = vault.seal("field", str(row.id), view.value.encode())
            row.ciphertext, row.key_version = blob, version
        else:
            row.value = view.value
        session.add(row)  # complete row: the XOR CHECK never sees a partial insert
        supplied[view.name] = {"name": view.name, "secret": view.secret, "value": view.value}
    await session.flush()
    await _audit_write(session, p, "create", item, 0, [])
    resp = _response(item, supplied, notes, mask=mask)
    resp["created"] = True
    return resp


async def get_item(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: Principal,
    name: str,
    include_deleted: bool = False,
) -> dict[str, Any]:
    item = (
        await session.execute(select(Item).where(Item.name == name))
    ).scalar_one_or_none()
    if item is None or (item.deleted_at is not None and not include_deleted):
        raise _not_found()
    fields = await _load_fields(session, item.id)
    views = _decrypt_views(vault, fields)
    return {
        "name": item.name,
        "notes": item.notes,
        "revision": item.revision,
        "fields": [
            {"name": v.name, "secret": v.secret, "value": v.value}
            for v in sorted(views.values(), key=lambda v: v.name)
        ],
    }


async def put_item(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: Principal,
    name: str,
    body: dict[str, Any],
    if_match: str | None = None,
    upsert: bool = False,
    mask: bool = False,
    allow_downgrade: bool = False,
) -> dict[str, Any]:
    item = await _lock_item(session, name)
    if item is None:
        if not upsert:
            raise _not_found()
        if if_match is not None:
            raise AppError("conflict", "If-Match on a missing name")
        # validate the PUT-shaped body before the create branch runs
        plan_put_ops(name, body, {})
        return await create_item(session, maker, vault, p, {**body, "name": name}, mask=mask)
    if item.deleted_at is not None:
        raise AppError("conflict", "name is soft-deleted") if upsert else _not_found()
    _check_if_match(item, if_match)
    fields = await _load_fields(session, item.id)
    views = _decrypt_views(vault, fields)  # degraded mode: any unreadable field fails
    try:
        ops = plan_put_ops(name, body, views)
    except DowngradeError:
        if not allow_downgrade:
            raise AppError("secret_downgrade_denied", "secret downgrade refused") from None
        ops = plan_put_ops(name, body, views, allow_downgrade=True)
    notes = body["notes"]
    post = _materialize_post(views, ops)
    check_caps(name, notes, list(post.values()))
    pre_revision = item.revision
    supplied, evicted = await _apply_ops(session, vault, p, item, ops, fields, views)
    item.notes = notes
    item.revision += 1
    await session.flush()
    await _audit_write(
        session, p, "put", item, pre_revision, evicted,
        {"allow_sensitive": True}
        if allow_downgrade and getattr(p, "allow_sensitive", False)
        else None,
    )
    return _response(item, supplied, notes, mask=mask)


async def patch_item(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: Principal,
    name: str,
    body: dict[str, Any],
    if_match: str | None = None,
    mask: bool = False,
    allow_downgrade: bool = False,
) -> dict[str, Any]:
    item = await _lock_item(session, name)
    if item is None or item.deleted_at is not None:
        raise _not_found()
    _check_if_match(item, if_match)
    fields = await _load_fields(session, item.id)
    views = _decrypt_views(vault, fields)
    try:
        ops = plan_patch_ops(body, views, path_name=name)
    except DowngradeError:
        if not allow_downgrade:
            raise AppError("secret_downgrade_denied", "secret downgrade refused") from None
        ops = plan_patch_ops(body, views, path_name=name, allow_downgrade=True)
    new_notes = item.notes if "notes" not in body else (body["notes"] or "")
    post = _materialize_post(views, ops)
    check_caps(name, new_notes, list(post.values()))
    pre_revision = item.revision
    supplied, evicted = await _apply_ops(session, vault, p, item, ops, fields, views)
    # kept fields not explicitly mentioned stay as-is; include kept secrets
    for f in fields:
        if f.name in post and f.name not in supplied and post[f.name].secret:
            supplied[f.name] = {"name": f.name, "secret": True, "kept": True}
        elif f.name in post and f.name not in supplied:
            supplied[f.name] = {
                "name": f.name, "secret": False, "value": post[f.name].value,
            }
    item.notes = new_notes
    item.revision += 1
    await session.flush()
    await _audit_write(
        session, p, "patch", item, pre_revision, evicted,
        {"allow_sensitive": True}
        if allow_downgrade and getattr(p, "allow_sensitive", False)
        else None,
    )
    return _response(item, supplied, new_notes, mask=mask)


async def rename_item(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: Principal,
    name: str,
    new_name: str,
) -> dict[str, Any]:
    """Rename a live item (§5, rev 43). Only the name changes: fields,
    history and revision count stay with the row. The collision check covers
    soft-deleted names too — the name stays reserved until restore or purge."""
    if valid_item_name(new_name) is None:
        raise AppError("invalid", "invalid item name")
    item = await _lock_item(session, name)
    if item is None or item.deleted_at is not None:
        raise _not_found()
    if new_name == name:
        return {"name": name, "revision": item.revision}
    clash = (
        await session.execute(select(Item.id).where(Item.name == new_name))
    ).first()
    if clash is not None:
        raise AppError(
            "conflict",
            "an item with that name already exists (restore or purge it first)",
        )
    pre_revision = item.revision
    item.name = new_name
    item.revision += 1
    try:
        await session.flush()
    except IntegrityError:
        # a concurrent create/rename claimed new_name after the check above
        raise AppError(
            "conflict",
            "an item with that name already exists (restore or purge it first)",
        ) from None
    await _audit_write(session, p, "rename", item, pre_revision, [],
                       extra_detail={"from": name})
    return {"name": new_name, "revision": item.revision}


async def rename_field(
    session: AsyncSession,
    p: Principal,
    name: str,
    field_name: str,
    new_name: str,
) -> dict[str, Any]:
    """Rename one field of a live item (§5, rev 46). Only the field's name
    moves: the row and its sealed value stay (the ciphertext AAD binds the
    field id, not the name, so nothing is re-encrypted), history rows follow
    (they carry the name as a listing/budget label), and the item's revision
    bumps so an edit drawer holding the old name fails its If-Match."""
    if valid_field_name(new_name) is None:
        raise AppError("invalid", "invalid field name")
    item = await _lock_item(session, name)
    if item is None or item.deleted_at is not None:
        raise _not_found()
    row = (
        await session.execute(
            select(Field).where(Field.item_id == item.id, Field.name == field_name)
        )
    ).scalars().first()
    if row is None:
        raise _not_found()
    result = {"name": item.name, "revision": item.revision,
              "field": {"name": field_name, "secret": row.secret}}
    if new_name == field_name:
        return result
    clash = (
        await session.execute(
            select(Field.id).where(Field.item_id == item.id, Field.name == new_name)
        )
    ).first()
    if clash is not None:
        raise AppError("conflict", "a field with that name already exists on this item")
    pre_revision = item.revision
    row.name = new_name
    item.revision += 1
    try:
        await session.flush()
    except IntegrityError:
        # a concurrent write claimed new_name between the check and the flush
        raise AppError(
            "conflict", "a field with that name already exists on this item"
        ) from None
    await session.execute(
        update(FieldHistory).where(FieldHistory.field_id == row.id).values(name=new_name)
    )
    await _audit_write(session, p, "field.rename", item, pre_revision, [],
                       extra_detail={"field": new_name, "from": field_name})
    return {"name": item.name, "revision": item.revision,
            "field": {"name": new_name, "secret": row.secret}}


async def soft_delete(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: Principal,
    name: str,
) -> None:
    item = await _lock_item(session, name)
    if item is None or item.deleted_at is not None:
        raise _not_found()
    pre_revision = item.revision
    item.deleted_at = datetime.now(UTC)
    item.revision += 1
    await session.flush()
    await _audit_write(session, p, "delete", item, pre_revision, [])


async def force_drop(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    vault: Vault,
    p: Principal,
    name: str,
    actor_kind: str,
) -> int:
    """Operator escape (§4): delete unreadable field/history rows of ONE item
    (trial decryption bounded to this item's own rows). Keeps readable rows
    and the item row with its deleted_at state. Returns the dropped count.
    Operator plane only (§5/§6): the caller must pass an operator actor kind.
    `maker` is retained for signature uniformity with the other item ops; the
    success audit now commits in the caller's transaction (no own session)."""
    if actor_kind not in ("operator_session", "local_process"):
        raise AppError("session_required", "force-drop is operator-only")
    item = await _lock_item(session, name)
    if item is None:
        raise _not_found()
    dropped = 0
    for row in await _load_fields(session, item.id):
        if not row.secret:
            continue
        if row.ciphertext is None or row.key_version is None:
            continue
        try:
            vault.open("field", str(row.id), row.ciphertext, row.key_version)
        except UnreadableError:
            await session.delete(row)
            dropped += 1
    hist_rows = list(
        (
            await session.execute(
                select(FieldHistory).where(
                    FieldHistory.item_id == item.id, FieldHistory.secret.is_(True)
                )
            )
        ).scalars()
    )
    for hist in hist_rows:
        if hist.ciphertext is None or hist.key_version is None:
            continue
        try:
            vault.open("fieldh", str(hist.id), hist.ciphertext, hist.key_version)
        except UnreadableError:
            await session.delete(hist)
            dropped += 1
    if dropped:
        item.revision += 1
    await session.flush()
    # success audit commits WITH the drop (§4): a failed outer commit must
    # leave no ok:true force_drop row for rows that were never deleted
    add_audit_row(
        session,
        actor_kind=actor_kind,
        actor_id="local" if actor_kind == "local_process" else p.actor_id,
        actor_label=p.actor_label,
        action="force_drop",
        item_name=item.name,
        ok=True,
        detail={"dropped_unreadable": dropped},
    )
    return dropped
