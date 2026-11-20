"""Rekey + verify engine (design §4, plan 3).

Batched re-seal under the newest keyring version. Selection is indexed
metadata (key_version != newest), never a decrypt scan; trial decryption
happens only on the selected ≤200 rows. Termination is cursor exhaustion
— unreadable rows are skipped, never reselected. Each re-seal is a
guarded UPDATE (id + old version + old bytes): a concurrent write makes
it a no-op. Run tokens are multi-use `rekey_run` step_up_tokens rows,
TTL 30 min extended per successful batch; one active run per vault.
Scan cursors: base64url JSON + HMAC(pepper) tag, NO TTL, bound to
endpoint + plane (session plane survives session rotation).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from custos.crypto import UnreadableError, Vault
from custos.db.models import (
    Field,
    FieldHistory,
    OperatorAccount,
    OperatorSession,
    OperatorToken,
    StepUpToken,
)
from custos.errors import AppError

_BATCH = 200
_RUN_TTL = timedelta(minutes=30)
_TABLES = ("fields", "field_history", "operator_account")
_RUN_LOCK_KEY = 8148  # xact advisory lock: one active rekey run per vault


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint_scan_cursor(payload: dict[str, Any], pepper: bytes, endpoint: str, plane: str) -> str:
    body = {**payload, "endpoint": endpoint, "plane": plane}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    tag = hmac.new(pepper, raw, hashlib.sha256).digest()
    return _b64url(raw) + "." + _b64url(tag)


def read_scan_cursor(token: str, pepper: bytes, endpoint: str, plane: str) -> dict[str, Any]:
    def _deny() -> AppError:
        return AppError("unauthorized", "invalid cursor")

    if len(token) > 2048:
        raise _deny()
    try:
        raw_b64, tag_b64 = token.split(".", 1)
        raw = _b64url_decode(raw_b64)
        tag = _b64url_decode(tag_b64)
    except (ValueError, AttributeError):
        raise _deny() from None
    if not hmac.compare_digest(tag, hmac.new(pepper, raw, hashlib.sha256).digest()):
        raise _deny()
    try:
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise ValueError
    except ValueError:
        raise _deny() from None
    if body.get("endpoint") != endpoint or body.get("plane") != plane:
        raise _deny()
    return body


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


async def mint_run(
    session: AsyncSession, presenter: OperatorSession, single_token: str
) -> str:
    """Consume the single step-up and insert the run row in ONE transaction
    (§4). An unexpired rekey_run row anywhere in the vault → 409."""
    from custos.operator.stepup import consume_step_up

    now = datetime.now(UTC)
    # serialize the check-then-insert: two concurrent first batches must not
    # both mint a run (READ COMMITTED alone does not prevent it)
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _RUN_LOCK_KEY})
    live = (
        await session.execute(
            select(StepUpToken.id).where(
                StepUpToken.kind == "rekey_run", StepUpToken.expires_at > now
            )
        )
    ).first()
    if live is not None:
        raise AppError("conflict", "a rekey run is already active")
    await consume_step_up(session, single_token, presenter)
    raw = _b64url(secrets.token_bytes(32))
    session.add(
        StepUpToken(
            session_id=presenter.id,
            nonce_hash=_hash(raw),
            kind="rekey_run",
            expires_at=now + _RUN_TTL,
        )
    )
    await session.flush()
    return raw


async def validate_run(
    session: AsyncSession, token: str, presenter: OperatorSession | OperatorToken
) -> StepUpToken:
    """Multi-use: validate binding + liveness, never consume. The caller
    extends expiry after a successful batch and commits."""
    row = (
        await session.execute(
            select(StepUpToken).where(StepUpToken.nonce_hash == _hash(token))
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if isinstance(presenter, OperatorToken):
        bound = row is not None and row.operator_token_id == presenter.id
        live = presenter.revoked_at is None and presenter.expires_at > now
    else:
        bound = row is not None and row.session_id == presenter.id
        live = presenter.revoked_at is None
    if (
        row is None
        or row.kind != "rekey_run"
        or row.expires_at <= now
        or not bound
        or not live
    ):
        raise AppError("step_up_required", "step-up required")
    return row


def extend_run(run: StepUpToken) -> None:
    run.expires_at = datetime.now(UTC) + _RUN_TTL


def _table_index(table: str) -> int:
    return _TABLES.index(table)


async def _select_rows(
    session: AsyncSession,
    vault: Vault,
    cursor_payload: dict[str, Any],
    *,
    all_rows: bool,
) -> list[tuple[str, Any]]:
    """Fixed table order, id ascending, resume after (table, last_id).
    rekey: key_version != newest; verify: every ciphertext row."""
    start_table = cursor_payload.get("table")
    last_id = cursor_payload.get("last_id")
    start_idx = _table_index(start_table) if start_table else 0
    selected: list[tuple[str, Any]] = []
    newest = vault.current_version
    for idx in range(start_idx, len(_TABLES)):
        table = _TABLES[idx]
        model: Any = {"fields": Field, "field_history": FieldHistory,
                      "operator_account": OperatorAccount}[table]
        version_col = (
            OperatorAccount.totp_key_version if table == "operator_account"
            else model.key_version
        )
        stmt = select(model)
        if all_rows:
            stmt = stmt.where(version_col.is_not(None))
        else:
            stmt = stmt.where(version_col.is_not(None), version_col != newest)
        if table == start_table and last_id:
            stmt = stmt.where(model.id > _coerce_id(table, last_id))
        stmt = stmt.order_by(model.id).limit(_BATCH - len(selected))
        rows = list((await session.execute(stmt)).scalars())
        selected.extend((table, r) for r in rows)
        if len(selected) >= _BATCH:
            break
    return selected


def _coerce_id(table: str, raw: str) -> Any:
    return int(raw) if table == "operator_account" else uuid.UUID(raw)


def _row_blob(table: str, row: Any) -> tuple[bytes | None, int | None, str, str]:
    """(ciphertext, version, crypto domain, row_id text)."""
    if table == "operator_account":
        return row.totp_secret, row.totp_key_version, "operator:totp", ""
    domain = "field" if table == "fields" else "fieldh"
    return row.ciphertext, row.key_version, domain, str(row.id)


async def _count_ahead(
    session: AsyncSession, vault: Vault, table: str, last_id: Any, *, all_rows: bool
) -> int:
    """remaining: rows strictly ahead of the cursor (SQL only, no decrypt)."""
    newest = vault.current_version
    total = 0
    start_idx = _table_index(table)
    for idx in range(start_idx, len(_TABLES)):
        t = _TABLES[idx]
        model: Any = {"fields": Field, "field_history": FieldHistory,
                      "operator_account": OperatorAccount}[t]
        version_col = (
            OperatorAccount.totp_key_version if t == "operator_account"
            else model.key_version
        )
        stmt = select(func.count()).select_from(model)
        if all_rows:
            stmt = stmt.where(version_col.is_not(None))
        else:
            stmt = stmt.where(version_col.is_not(None), version_col != newest)
        if t == table:
            stmt = stmt.where(model.id > last_id)
        total += int((await session.execute(stmt)).scalar_one())
    return total


async def _sweep_batch(
    session: AsyncSession,
    vault: Vault,
    cursor_payload: dict[str, Any],
    *,
    reseal: bool,
) -> dict[str, Any]:
    """One batch: select ≤200 rows, trial-open each; rekey re-seals readable
    rows via guarded UPDATE, verify only counts. Returns counts + cursor."""
    selected = await _select_rows(session, vault, cursor_payload, all_rows=not reseal)
    skipped = 0
    unreadable = {"fields": 0, "field_history": 0, "operator_account": 0}
    last_table: str | None = cursor_payload.get("table")
    last_id: Any = cursor_payload.get("last_id")
    newest = vault.current_version
    for table, row in selected:
        blob, version, domain, row_id = _row_blob(table, row)
        last_table, last_id = table, row.id
        if blob is None or version is None:
            skipped += 1
            unreadable[table] += 1
            continue
        try:
            plaintext = vault.open(domain, row_id, blob, version)
        except UnreadableError:
            skipped += 1
            unreadable[table] += 1
            continue
        if not reseal or version == newest:
            continue
        new_blob, new_version = vault.seal(domain, row_id, plaintext)
        if table == "operator_account":
            result = await session.execute(
                update(OperatorAccount)
                .where(
                    OperatorAccount.id == row.id,
                    OperatorAccount.totp_key_version == version,
                    OperatorAccount.totp_secret == blob,
                )
                .values(totp_secret=new_blob, totp_key_version=new_version)
            )
        else:
            model = Field if table == "fields" else FieldHistory
            result = await session.execute(
                update(model)
                .where(model.id == row.id, model.key_version == version,
                       model.ciphertext == blob)
                .values(ciphertext=new_blob, key_version=new_version)
            )
        # rowcount 0 → concurrent write already handled the row; neither
        # skipped nor remaining-blocking (§4)
        _ = result.rowcount  # type: ignore[attr-defined]
    if not selected:
        # nothing selected: cursor exhausted (coerce any replayed position
        # so the count compares typed ids, never raw JSON strings)
        if cursor_payload.get("table") and cursor_payload.get("last_id"):
            remaining = await _count_ahead(
                session, vault, cursor_payload["table"],
                _coerce_id(cursor_payload["table"], cursor_payload["last_id"]),
                all_rows=not reseal,
            )
        else:
            remaining = 0
        cursor = None
    else:
        # selected is non-empty → the loop set both position vars
        if last_table is None:  # pragma: no cover — invariant guard
            raise RuntimeError("selection without position")
        remaining = await _count_ahead(session, vault, last_table, last_id,
                                       all_rows=not reseal)
        cursor = {"table": last_table, "last_id": str(last_id)}
    out: dict[str, Any] = {"remaining": remaining, "skipped": skipped}
    if not reseal:
        out["unreadable"] = {
            "fields": unreadable["fields"],
            "history": unreadable["field_history"],
            "operator": unreadable["operator_account"],
        }
    if cursor is not None and remaining > 0:
        out["_cursor_payload"] = cursor
    return out


async def rekey_batch(
    session: AsyncSession, vault: Vault, cursor_payload: dict[str, Any]
) -> dict[str, Any]:
    return await _sweep_batch(session, vault, cursor_payload, reseal=True)


async def verify_batch(
    session: AsyncSession, vault: Vault, cursor_payload: dict[str, Any]
) -> dict[str, Any]:
    return await _sweep_batch(session, vault, cursor_payload, reseal=False)
