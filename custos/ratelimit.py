"""In-process rate limiting (design §5). Single-worker contract (§3).

Agent plane: 120 req/min/key + 8 concurrent; failed agent auth:
30 failures/min/IP. Admin/unauthenticated buckets arrive with plan 2.
"""

from __future__ import annotations

import time
from collections import deque

from custos.errors import AppError

_WINDOW = 60.0


class RateLimiter:
    def __init__(
        self,
        agent_requests_per_min: int = 120,
        agent_concurrent: int = 8,
        failed_auth_per_min: int = 30,
        admin_requests_per_min: int = 300,
    ) -> None:
        self._req_limit = agent_requests_per_min
        self._conc_limit = agent_concurrent
        self._fail_limit = failed_auth_per_min
        self._admin_limit = admin_requests_per_min
        self._requests: dict[str, deque[float]] = {}
        self._failures: dict[str, deque[float]] = {}
        self._inflight: dict[str, int] = {}
        self._unauth: dict[str, deque[float]] = {}
        self._setup_global: deque[float] = deque()

    def check_unauth(self, ip: str, *, setup: bool = False) -> None:
        """Unauthenticated credential endpoints: 10/min/IP (setup 3/min/IP +
        global 10/min). Runs AFTER lockout, BEFORE credential verification."""
        now = time.monotonic()
        limit = 3 if setup else 10
        # per-IP gate FIRST: a rejected attempt must not burn the global quota
        self._bucket(self._unauth, f"{ip}:{'setup' if setup else 'auth'}", limit)
        if setup:
            while self._setup_global and now - self._setup_global[0] > _WINDOW:
                self._setup_global.popleft()
            if len(self._setup_global) >= 10:
                raise AppError("rate_limited", headers={"Retry-After": "60"})
            self._setup_global.append(now)
        if len(self._unauth) > 4096:
            self._sweep(self._unauth, now)
        while len(self._unauth) > 4096:
            self._unauth.pop(next(iter(self._unauth)))

    def _bucket(self, table: dict[str, deque[float]], key: str, limit: int) -> None:
        now = time.monotonic()
        events = table.get(key)
        if events is None:
            events = table[key] = deque()
        while events and now - events[0] > _WINDOW:
            events.popleft()
        if len(events) >= limit:
            retry = max(1, int(_WINDOW - (now - events[0])) + 1)
            raise AppError("rate_limited", headers={"Retry-After": str(retry)})
        events.append(now)
        self._sweep(table, now)

    def _sweep(self, table: dict[str, deque[float]], now: float) -> None:
        # drop drained keys so attacker-chosen IPs cannot grow the dict forever
        if len(table) > 1024:
            stale = [k for k, ev in table.items() if not ev or now - ev[-1] > _WINDOW]
            for key in stale:
                del table[key]

    def check_agent_request(self, key_id: str) -> None:
        self._bucket(self._requests, key_id, self._req_limit)

    def check_admin_request(self, key: str) -> None:
        """Admin plane: 300 req/min per session-or-token (§5)."""
        self._bucket(self._requests, key, self._admin_limit)

    def record_failed_auth(self, ip: str) -> None:
        """Record a verified failure without raising; the gate 429s the next try."""
        now = time.monotonic()
        events = self._failures.setdefault(ip, deque())
        while events and now - events[0] > _WINDOW:
            events.popleft()
        events.append(now)
        # attacker-driven table: sweep drained keys and hard-cap the count
        if len(self._failures) > 4096:
            self._sweep(self._failures, now)
        while len(self._failures) > 4096:
            self._failures.pop(next(iter(self._failures)))

    def check_failed_auth_gate(self, ip: str) -> None:
        """Pre-verification gate: full bucket → 429 without verifying/ledgering."""
        now = time.monotonic()
        events = self._failures.get(ip)
        if events is None:
            return
        while events and now - events[0] > _WINDOW:
            events.popleft()
        if not events:
            del self._failures[ip]
            return
        if len(events) >= self._fail_limit:
            retry = max(1, int(_WINDOW - (now - events[0])) + 1)
            raise AppError("rate_limited", headers={"Retry-After": str(retry)})

    def acquire_agent_slot(self, key_id: str) -> None:
        current = self._inflight.get(key_id, 0)
        if current >= self._conc_limit:
            raise AppError("rate_limited", headers={"Retry-After": "1"})
        self._inflight[key_id] = current + 1

    def release_agent_slot(self, key_id: str) -> None:
        current = self._inflight.get(key_id, 0)
        if current <= 1:
            self._inflight.pop(key_id, None)
        else:
            self._inflight[key_id] = current - 1
