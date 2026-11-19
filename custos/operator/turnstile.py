"""Cloudflare Turnstile (design §5): fail-closed siteverify.

POST secret/response/remoteip with a fixed 5s timeout; success:false, any
error-code (incl. already-spent), timeout, transport error, or a missing/
mismatched hostname all reject with 422 turnstile_failed. Verification
runs after lockout+limiter, before credentials. Audit-only (no auth_events
row → never counted by credential lockout).
"""

from __future__ import annotations

import httpx

from custos.config import Settings
from custos.errors import AppError

_SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
_TIMEOUT = 5.0


async def verify_turnstile(
    settings: Settings,
    token: str | None,
    ip: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> None:
    if not settings.turnstile_secret:
        return  # Turnstile not configured
    if not token:
        raise AppError("turnstile_failed", "turnstile token required")
    data = {"secret": settings.turnstile_secret, "response": token, "remoteip": ip}
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        resp = await client.post(_SITEVERIFY, data=data, timeout=_TIMEOUT)
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError("non-object siteverify payload")
    except (httpx.HTTPError, ValueError):
        raise AppError("turnstile_failed", "turnstile verification failed") from None
    finally:
        if owns_client:
            await client.aclose()
    if not payload.get("success"):
        raise AppError("turnstile_failed", "turnstile verification failed")
    hostname = payload.get("hostname")
    if not hostname or hostname not in (settings.turnstile_hostnames or ()):
        raise AppError("turnstile_failed", "turnstile verification failed")
