"""Pure caps + write-body planning (design §4 limits, §6 write body).

No DB access here: the planner turns a request body plus the pre-request
field state into an ordered op list, enforcing the single precedence rule,
the sanctioned remove+add pair, and the pre/post downgrade classification
table. The engine (items.py) applies ops under the item row lock.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from custos.errors import AppError
from custos.names import ITEM_NAME_BODY, USERNAME_BODY

FIELD_VALUE_MAX = 16 * 1024  # raw UTF-8 bytes
NOTES_MAX = 4 * 1024  # raw UTF-8 bytes
FIELDS_MAX = 32
ITEM_MAX = 256 * 1024  # canonical escaped JSON bytes

_ITEM_NAME_RE = re.compile("^" + ITEM_NAME_BODY + r"\Z")
_USERNAME_RE = re.compile("^" + USERNAME_BODY + r"\Z")
_FIELD_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}\Z")


class DowngradeError(Exception):
    """secret→plain on the agent plane; the whole request fails atomically."""


@dataclass(frozen=True)
class FieldView:
    name: str
    secret: bool
    value: str  # plaintext (decrypted for measurement); never logged


@dataclass(frozen=True)
class Op:
    kind: str  # "set" | "remove" | "keep"
    name: str
    secret: bool = False
    value: str | None = None


def valid_item_name(name: object) -> str | None:
    """Canonical item-name check for audit attribution (one source of truth).
    Han ideographs are valid (rev 45); usernames stay ASCII-only."""
    if isinstance(name, str) and _ITEM_NAME_RE.match(name):
        return name
    return None


def valid_username(name: object) -> str | None:
    """Operator username grammar: ASCII-only, even though item names now
    accept CJK (rev 45)."""
    if isinstance(name, str) and _USERNAME_RE.match(name):
        return name
    return None


def _invalid(message: str) -> AppError:
    return AppError("invalid", message)


def canonical_item_bytes(name: str, notes: str, fields: list[FieldView]) -> bytes:
    obj = {
        "name": name,
        "notes": notes,
        "fields": [
            {"name": f.name, "secret": f.secret, "value": f.value}
            for f in sorted(fields, key=lambda f: f.name)
        ],
    }
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


def check_caps(name: str, notes: str, fields: list[FieldView]) -> None:
    if len(notes.encode()) > NOTES_MAX:
        raise AppError("payload_too_large", "notes exceed 4 KiB")
    if len(fields) > FIELDS_MAX:
        raise AppError("payload_too_large", "item exceeds 32 fields")
    for f in fields:
        if len(f.value.encode()) > FIELD_VALUE_MAX:
            raise AppError("payload_too_large", "field value exceeds 16 KiB")
    if len(canonical_item_bytes(name, notes, fields)) > ITEM_MAX:
        raise AppError("payload_too_large", "item exceeds 256 KiB canonical JSON")


def _check_text(value: str, label: str) -> None:
    if "\x00" in value:
        raise _invalid(f"{label} must not contain NUL")
    try:
        value.encode()
    except UnicodeEncodeError:
        raise _invalid(f"{label} must be valid UTF-8 (no lone surrogates)") from None


def _check_names(name: str | None, fields: list[dict[str, Any]]) -> None:
    if name is not None and not _ITEM_NAME_RE.match(name):
        raise _invalid("invalid item name")
    for entry in fields:
        fname = entry.get("name")
        if not isinstance(fname, str) or not _FIELD_NAME_RE.match(fname):
            raise _invalid("invalid field name")
        value = entry.get("value")
        if isinstance(value, str):
            _check_text(value, "field values")
        secret = entry.get("secret")
        if secret is not None and not isinstance(secret, bool):
            raise _invalid("secret must be a boolean")


def _body_fields(body: dict[str, Any]) -> list[dict[str, Any]]:
    fields = body.get("fields")
    if not isinstance(fields, list) or any(not isinstance(f, dict) for f in fields):
        raise _invalid("fields must be an array of objects")
    return fields


def validate_post_body(body: dict[str, Any]) -> tuple[str, str, list[FieldView]]:
    name = body.get("name")
    if not isinstance(name, str):
        raise _invalid("name is required")
    notes = body.get("notes", "")
    if not isinstance(notes, str):
        raise _invalid("notes must be a string")
    _check_text(notes, "notes")
    entries = _body_fields(body)
    _check_names(name, entries)
    seen: set[str] = set()
    views: list[FieldView] = []
    for entry in entries:
        fname = entry["name"]
        if fname in seen:
            raise _invalid("duplicate field names")
        seen.add(fname)
        secret = entry.get("secret")
        value = entry.get("value")
        if not isinstance(secret, bool) or not isinstance(value, str):
            raise _invalid("create entries require explicit secret and non-null value")
        views.append(FieldView(name=fname, secret=secret, value=value))
    check_caps(name, notes, views)
    return name, notes, views


def _classify_downgrades(
    pre: dict[str, FieldView], post: dict[str, FieldView]
) -> None:
    """Pre/post classification table (§6): any name secret at request start
    and plain afterwards is a downgrade, regardless of the op path."""
    for fname, before in pre.items():
        after = post.get(fname)
        if before.secret and after is not None and not after.secret:
            raise DowngradeError()


def plan_put_ops(
    path_name: str,
    body: dict[str, Any],
    existing: dict[str, FieldView],
    allow_downgrade: bool = False,
) -> list[Op]:
    body_name = body.get("name")
    if body_name is not None and body_name != path_name:
        raise _invalid("body name must match the path")
    if "notes" not in body or not isinstance(body["notes"], str):
        raise _invalid("notes is required on PUT (empty string clears)")
    _check_text(body["notes"], "notes")
    entries = _body_fields(body)
    _check_names(None, entries)
    seen: set[str] = set()
    ops: list[Op] = []
    post: dict[str, FieldView] = {}
    for entry in entries:
        fname = entry["name"]
        if fname in seen:
            raise _invalid("duplicate field names")
        seen.add(fname)
        before = existing.get(fname)
        secret = entry.get("secret")
        has_value = "value" in entry
        value = entry.get("value")
        if has_value and value is None:
            raise _invalid("value: null is a PATCH remove, not valid on PUT")
        if has_value:
            if not isinstance(secret, bool) or not isinstance(value, str):
                raise _invalid("entries with a value require explicit secret")
            if before is not None and before.secret != secret:
                # flag change on PUT = remove+add with the pre/post rule
                ops.append(Op(kind="remove", name=fname))
            ops.append(Op(kind="set", name=fname, secret=secret, value=value))
            post[fname] = FieldView(fname, secret, value)
        else:
            # omission: keep only an existing secret field with no flag change
            if before is None or not before.secret or (secret is not None and secret is not True):
                raise _invalid("omitted value is only valid for an existing secret field")
            ops.append(Op(kind="keep", name=fname, secret=True))
            post[fname] = before
    for fname in existing:
        if fname not in seen:
            ops.append(Op(kind="remove", name=fname))
    if not allow_downgrade:
        _classify_downgrades(existing, post)
    return ops


def plan_patch_ops(
    body: dict[str, Any],
    existing: dict[str, FieldView],
    path_name: str | None = None,
    allow_downgrade: bool = False,
) -> list[Op]:
    body_name = body.get("name")
    if body_name is not None and path_name is not None and body_name != path_name:
        raise _invalid("body name must match the path")
    entries = body.get("fields", [])
    if not isinstance(entries, list) or any(not isinstance(f, dict) for f in entries):
        raise _invalid("fields must be an array of objects")
    if "notes" in body and body["notes"] is not None and not isinstance(body["notes"], str):
        raise _invalid("notes must be a string or null")
    if isinstance(body.get("notes"), str):
        _check_text(body["notes"], "notes")
    _check_names(None, entries)

    # duplicate names allowed only as remove-then-add pair (single pass)
    positions: dict[str, list[int]] = {}
    for idx, entry in enumerate(entries):
        positions.setdefault(entry["name"], []).append(idx)
    for idxs in positions.values():
        if len(idxs) > 2:
            raise _invalid("duplicate field names")
        if len(idxs) == 2:
            first, second = entries[idxs[0]], entries[idxs[1]]
            if "value" not in first or first["value"] is not None:
                raise _invalid("duplicates allowed only as remove-then-add pair")
            if not isinstance(second.get("value"), str):
                raise _invalid("the second entry of a pair must be an add with a value")

    ops: list[Op] = []
    # intermediate state for keep/omission semantics; pre state for downgrades
    state: dict[str, FieldView | None] = dict(existing)
    removed_in_request: set[str] = set()
    for entry in entries:
        fname = entry["name"]
        current = state.get(fname)
        has_value = "value" in entry
        value = entry.get("value")
        secret = entry.get("secret")
        if has_value and value is None:
            if secret is not None:
                raise _invalid("remove entries carry only value: null")
            ops.append(Op(kind="remove", name=fname))
            state[fname] = None
            removed_in_request.add(fname)
            continue
        if fname in removed_in_request:
            # add entry after a remove: explicit secret + non-null value required
            if not isinstance(secret, bool) or not isinstance(value, str):
                raise _invalid("re-add after remove requires explicit secret and value")
            ops.append(Op(kind="set", name=fname, secret=secret, value=value))
            state[fname] = FieldView(fname, secret, value)
            continue
        if has_value:
            if not isinstance(value, str):
                raise _invalid("value must be a string or null")
            if current is None:
                if not isinstance(secret, bool):
                    raise _invalid("new fields require explicit secret")
                target_secret = secret
            else:
                target_secret = current.secret if secret is None else secret
                if secret is not None and secret != current.secret:
                    raise _invalid("in-place flag change requires the remove+add pair")
            ops.append(Op(kind="set", name=fname, secret=target_secret, value=value))
            state[fname] = FieldView(fname, target_secret, value)
        else:
            if current is None:
                raise _invalid("omitted value is only valid for an existing field")
            if secret is None:
                ops.append(Op(kind="keep", name=fname, secret=current.secret))
            elif secret is True and current.secret:
                ops.append(Op(kind="keep", name=fname, secret=True))
            else:
                raise _invalid("omitted value is only valid for an existing secret field")
    post = {k: v for k, v in state.items() if v is not None}
    if not allow_downgrade:
        _classify_downgrades(existing, post)
    return ops
