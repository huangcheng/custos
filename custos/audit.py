"""Independent-commit audit and auth-event ledger (design §4, §5).

Every row commits in its own transaction before the caller's error response —
never rolled back with the failing request. Closed action/detail sets and a
length cap defend against accidental value leakage; this module has no
parameter that could carry a secret value at all. Under a distributed flood
the global failure-row budget skips ledger writes and falls back to an
in-process sliding counter so lockout still trips (§5 rate limits).
"""

from __future__ import annotations

import logging
import re
import time
from collections import OrderedDict, deque

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from custos.db.models import AuditRow, AuthEvent

ACTION_ENUM: frozenset[str] = frozenset(
    {
        "list", "search", "get", "env", "create", "put", "patch", "delete", "restore",
        "purge", "force_drop", "history", "reveal", "device.login", "key.mint",
        "key.revoke", "key.list", "token.mint", "token.revoke", "token.list",
        "operator.login", "operator.logout", "operator.step_up",
        "operator.password_change", "operator.totp_change", "operator.passkey_change",
        "operator.recovery_regen", "operator.setup", "account.unlock", "rekey",
        "rekey_verify", "retention", "auth.failure",
    }
)

ACTOR_KINDS: frozenset[str] = frozenset(
    {"agent", "operator_session", "operator_token", "anonymous", "local_process"}
)

AUTH_EVENT_KINDS: frozenset[str] = frozenset(
    {
        "login_password", "login_totp", "login_passkey", "login_recovery",
        "step_up", "agent_auth", "setup",
    }
)

DETAIL_KEYS: frozenset[str] = frozenset(
    {
        "pre_revision", "revision", "evicted", "evicted_ids", "dropped_unreadable",
        "codes_consumed", "count", "remaining", "skipped", "key_id", "break_glass",
        "allow_sensitive", "ip", "stage", "reason", "created",
    }
)

_DETAIL_VALUE_MAX = 256
_KEY_ID_RE = re.compile(r"^[0-9a-f]{12}\Z")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
# kinds that feed the per-account window (setup is per-IP only, §5)
_ACCOUNT_LOCKOUT_KINDS = frozenset(
    {"login_password", "login_totp", "login_passkey", "login_recovery", "step_up"}
)

logger = logging.getLogger("custos.audit")


def _validate_actor(actor_kind: str, actor_id: str | None) -> None:
    if actor_kind == "anonymous":
        if actor_id is not None:
            raise ValueError("anonymous audit rows must have actor_id=None")
    elif actor_kind == "local_process":
        if actor_id != "local":
            raise ValueError("local_process audit rows must have actor_id='local'")
    elif actor_kind in ("agent", "operator_token"):
        if actor_id is None or not _KEY_ID_RE.match(actor_id):
            raise ValueError("agent/operator_token actor_id must be a 12-hex key_id")
    elif actor_kind == "operator_session" and (actor_id is None or not _UUID_RE.match(actor_id)):
        raise ValueError("operator_session actor_id must be a lowercase uuid")


class LedgerError(Exception):
    """Ledger write failed; the caller must fail the request closed (503)."""


class LedgerBudget:
    """Global failure-row budget: at most ``limit`` ledgered failures per minute."""

    def __init__(self, limit: int = 600) -> None:
        self._limit = limit
        self._window_start = time.monotonic()
        self._used = 0
        self._logged_exhaustion = False

    def allow(self) -> bool:
        now = time.monotonic()
        if now - self._window_start >= 60:
            self._window_start = now
            self._used = 0
            self._logged_exhaustion = False
        if self._used >= self._limit:
            if not self._logged_exhaustion:
                logger.warning(
                    "ledger failure-row budget exhausted; falling back to in-process counter"
                )
                self._logged_exhaustion = True
            return False
        self._used += 1
        return True


class FailureCounter:
    """In-process sliding 15-min failure counter (lockout fallback when the
    ledger budget is exhausted). Keys are ip:<addr> / account."""

    def __init__(self, window_seconds: int = 900, max_keys: int = 10_000) -> None:
        self._window = window_seconds  # per-IP: 15 min
        self._account_window = window_seconds * 2  # per-account: 30 min (§5)
        self._max_keys = max_keys
        # insertion-ordered: eviction pops from the front (amortized O(1));
        # the shared "account" bucket is exempt — it must never fail open.
        self._events: OrderedDict[str, deque[float]] = OrderedDict()

    def bucket_count(self) -> int:
        return len(self._events)

    def _evict_overflow(self) -> None:
        while len(self._events) > self._max_keys:
            for key in self._events:
                if key != "account":
                    del self._events[key]
                    break
            else:
                return

    def _window_for(self, key: str) -> int:
        return self._account_window if key == "account" else self._window

    def record(self, *, ip: str | None = None, account: bool = False) -> None:
        now = time.monotonic()
        keys = ([f"ip:{ip}"] if ip is not None else []) + (["account"] if account else [])
        for key in keys:
            events = self._events.get(key)
            if events is None:
                # maxlen = largest lockout threshold (30): counts saturate there,
                # per-bucket memory is constant under sustained floods.
                events = self._events[key] = deque(maxlen=30)
            else:
                # refresh recency for eviction order
                self._events.move_to_end(key)
            while events and now - events[0] > self._window_for(key):
                events.popleft()
            events.append(now)
        self._evict_overflow()

    def agent_failures(self, *, ip: str) -> int:
        """Failed agent auth in the last minute (30/min/IP request limiter —
        deliberately separate from the credential-lockout bucket)."""
        events = self._events.get(f"agent:{ip}")
        if events is None:
            return 0
        now = time.monotonic()
        return sum(1 for ts in events if now - ts <= 60)

    def record_agent_failure(self, *, ip: str) -> None:
        now = time.monotonic()
        key = f"agent:{ip}"
        events = self._events.get(key)
        if events is None:
            events = self._events[key] = deque(maxlen=30)
        else:
            self._events.move_to_end(key)  # refresh recency for eviction order
        events.append(now)
        self._evict_overflow()

    def count(self, *, ip: str | None = None, account: bool = False) -> int:
        if account:
            key = "account"
        elif ip is not None:
            key = f"ip:{ip}"
        else:
            raise ValueError("count requires ip= or account=True")
        now = time.monotonic()
        events = self._events.get(key)
        if events is None:
            return 0
        while events and now - events[0] > self._window_for(key):
            events.popleft()
        return len(events)


def _validate_detail(detail: dict[str, object]) -> None:
    def _check_scalar(value: object) -> None:
        if value is None or isinstance(value, (bool, int, float)):
            return
        if isinstance(value, str):
            if len(value) > _DETAIL_VALUE_MAX:
                raise ValueError("audit detail string values are capped at 256 chars")
            return
        raise ValueError("audit detail values must be scalars or lists of scalars")

    for key, value in detail.items():
        if key not in DETAIL_KEYS:
            raise ValueError(f"audit detail key {key!r} is not in the closed set")
        if key == "reason" and not isinstance(value, str):
            raise ValueError("audit detail reason must be a string")
        if isinstance(value, (list, tuple)):
            if len(value) > 64:
                raise ValueError("audit detail lists are capped at 64 entries")
            for item in value:
                _check_scalar(item)
        else:
            _check_scalar(value)


async def record_audit(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    actor_kind: str,
    actor_id: str | None,
    actor_label: str,
    action: str,
    item_name: str | None,
    ok: bool,
    detail: dict[str, object],
    budget: LedgerBudget | None = None,
    counter: FailureCounter | None = None,
) -> None:
    if action not in ACTION_ENUM:
        raise ValueError(f"audit action {action!r} is not in the closed enum")
    if actor_kind not in ACTOR_KINDS:
        raise ValueError(f"actor kind {actor_kind!r} is not in the closed enum")
    _validate_actor(actor_kind, actor_id)
    if budget is not None and counter is None:
        raise ValueError("budget requires a counter (lockout fallback must stay alive)")
    _validate_detail(detail)
    if not ok and budget is not None and not budget.allow():
        # Shared budget: the row is skipped. Counting happens ONLY in
        # record_auth_event — a credential failure writes both rows but must
        # increment the fallback counter exactly once.
        return
    try:
        async with session_maker() as session, session.begin():
            session.add(
                AuditRow(
                    actor_kind=actor_kind,
                    actor_id=actor_id,
                    actor_label=actor_label,
                    action=action,
                    item_name=item_name,
                    ok=ok,
                    detail=detail,
                )
            )
    except (SQLAlchemyError, OSError) as exc:
        raise LedgerError("audit write failed") from exc


async def record_auth_event(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    kind: str,
    ok: bool,
    ip: str,
    peer_ip: str,
    budget: LedgerBudget | None = None,
    counter: FailureCounter | None = None,
) -> None:
    if kind not in AUTH_EVENT_KINDS:
        raise ValueError(f"auth event kind {kind!r} is not in the closed enum")
    if budget is not None and counter is None:
        raise ValueError("budget requires a counter (lockout fallback must stay alive)")
    if not ok and budget is not None and not budget.allow():
        # Flood: skip the ledger write, keep lockout alive via the counter.
        if kind == "agent_auth":
            counter.record_agent_failure(ip=ip)  # type: ignore[union-attr]
        else:
            counter.record(  # type: ignore[union-attr]
                ip=ip, account=kind in _ACCOUNT_LOCKOUT_KINDS
            )
        return
    try:
        async with session_maker() as session, session.begin():
            session.add(AuthEvent(kind=kind, ok=ok, ip=ip, peer_ip=peer_ip))
    except (SQLAlchemyError, OSError) as exc:
        raise LedgerError("auth event write failed") from exc
