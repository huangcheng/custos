"""Console static serving (design §3, plan 4).

The build lives in ``console/dist`` (container: ``/app/console/dist``).
Three path classes, each with its own cache policy:

- hashed assets under ``assets/`` → ``public, max-age=31536000, immutable``
- the SPA shell and every client-side route → ``no-store`` + the §3 CSP
- ``/api/*`` and ``/mcp`` → never touched here (the API routers and the
  MCP mount own them); an unmatched API path stays a JSON 404.

The shell is read once at mount time: it cannot change until the next
deploy, and re-reading it per request would put blocking disk I/O on the
event loop for every client-side navigation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.staticfiles import StaticFiles

logger = logging.getLogger("custos.console")

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'"
)
CSP_TURNSTILE = (
    "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; "
    "style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; "
    "connect-src 'self' https://challenges.cloudflare.com; "
    "frame-src https://challenges.cloudflare.com; frame-ancestors 'none'"
)
_ASSET_CACHE = "public, max-age=31536000, immutable"
_NOT_FOUND = {"code": "not_found", "message": "not found"}


def _settings_dist(settings: object) -> Path | None:
    """The dist directory, or None when this deployment has no console.

    A dist without ``index.html`` is treated as absent (partial build,
    wrong ``CUSTOS_CONSOLE_DIST``): serving a 500 on every route is worse
    than a clean JSON 404.
    """
    raw = getattr(settings, "console_dist", "") or ""
    candidate = Path(raw).expanduser() if raw else (
        Path(__file__).resolve().parent.parent / "console" / "dist"
    )
    try:
        candidate = candidate.resolve()
    except (OSError, ValueError):
        return None
    if not candidate.is_dir():
        return None
    if not (candidate / "index.html").is_file():
        logger.warning("console dist has no index.html; console disabled: %s", candidate)
        return None
    return candidate


def _resolve_asset(dist: Path, path: str) -> Path | None:
    """Map a request path to a file INSIDE dist, or None.

    Percent-decoded ASGI paths can carry ``..`` segments; ``resolve()``
    collapses them before the containment check, so nothing outside the
    dist root is ever served (unauthenticated arbitrary-file-read would
    otherwise be one request away).
    """
    try:
        candidate = (dist / path).resolve()
    except (OSError, ValueError):
        return None
    if candidate == dist or dist not in candidate.parents:
        return None
    if not candidate.is_file():
        return None
    return candidate


def mount_console(app: FastAPI, settings: object) -> None:
    """Register static serving + the SPA fallback. Called AFTER the API and
    MCP routers so a catch-all can never shadow them."""
    dist = _settings_dist(settings)
    if dist is None:

        @app.get("/", include_in_schema=False)
        async def _no_console() -> JSONResponse:
            return JSONResponse(_NOT_FOUND, 404)

        return

    shell = (dist / "index.html").read_text()
    turnstile = bool(getattr(settings, "turnstile_sitekey", None))
    csp = CSP_TURNSTILE if turnstile else CSP
    # §3 browser hardening. These are set HERE (not only in a middleware) because
    # the shell reaches the browser through three paths: the / route, the
    # index.html asset branch, and the 404 rewrite. All three must agree.
    shell_headers = {
        "cache-control": "no-store",
        "content-security-policy": csp,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "x-frame-options": "DENY",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
    }

    assets = dist / "assets"
    if assets.is_dir():

        class _ImmutableStatic(StaticFiles):
            """§3: hashed Vite assets are immutable for a year."""

            async def get_response(self, path: str, scope: Any) -> Response:
                resp = await super().get_response(path, scope)
                resp.headers["cache-control"] = _ASSET_CACHE
                return resp

        app.mount("/assets", _ImmutableStatic(directory=assets), name="console-assets")

    def _shell_response() -> Response:
        # HTMLResponse would append its own headers; pass the full set once and
        # override the response's defaults so no header is duplicated.
        resp = HTMLResponse(shell)
        for name, value in shell_headers.items():
            resp.headers[name] = value
        return resp

    @app.get("/", include_in_schema=False)
    async def _index() -> Response:
        return _shell_response()

    dist_root: Path = dist  # narrowed: the None case returned above

    class _SpaFallback:
        """Serve the shell for a client-side route by REWRITING the app's own
        404 — never by registering a catch-all.

        A route-based catch-all is registered before any router added after
        ``create_app`` (tests, extensions) and would shadow it. Reacting to a
        real 404 keeps registration order irrelevant and leaves /api/* and
        /mcp untouched.
        """

        def __init__(self, inner: Any) -> None:
            self.inner = inner

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] != "http" or scope["method"] not in ("GET", "HEAD"):
                await self.inner(scope, receive, send)
                return
            path = scope["path"].lstrip("/")
            if (
                path == "api"
                or path.startswith("api/")
                or path == "mcp"
                or path.startswith("mcp/")
                # A missing hashed asset must 404, not become the HTML shell:
                # serving 200 HTML for a JS import turns a stale deploy into an
                # opaque MIME error.
                or path.startswith("assets/")
            ):
                await self.inner(scope, receive, send)
                return
            asset = _resolve_asset(dist_root, path) if path else None
            if asset is not None:
                # The shell keeps its security headers no matter which URL
                # delivered it; only hashed build output is immutable.
                is_shell = asset.name == "index.html"
                if is_shell:
                    # the shell keeps exactly the route's header set (no
                    # duplicate cache-control)
                    headers = [
                        (k.encode(), v.encode()) for k, v in shell_headers.items()
                    ]
                    headers.append((b"content-type", b"text/html; charset=utf-8"))
                else:
                    immutable = path.startswith("assets/")
                    cache = _ASSET_CACHE if immutable else "no-store"
                    media = _media_type(asset.suffix) or "application/octet-stream"
                    headers = [
                        (b"cache-control", cache.encode()),
                        (b"content-type", media.encode()),
                    ]
                    if media.startswith("text/html"):
                        # any HTML from dist/ is potentially renderable: give it
                        # the same hardening as the shell, never bare HTML
                        headers.extend(
                            (k.encode(), v.encode())
                            for k, v in shell_headers.items()
                            if k != "cache-control"
                        )
                await send({
                    "type": "http.response.start",
                    "status": 200,
                    "headers": headers,
                })
                await send({"type": "http.response.body", "body": asset.read_bytes()})
                return
            shell_sent = False

            async def _send(message: Any) -> None:
                nonlocal shell_sent
                if (
                    message["type"] == "http.response.start"
                    and message["status"] == 404
                    and not shell_sent
                ):
                    # the app found no route: this is a client-side console route
                    shell_sent = True
                    # This rewrite bypasses the inner middleware stack, so the
                    # browser-hardening headers are added explicitly here; the
                    # shell must not gain or lose headers by URL.
                    headers = [(k.encode(), v.encode()) for k, v in shell_headers.items()]
                    headers.append((b"content-type", b"text/html; charset=utf-8"))
                    await send({
                        "type": "http.response.start",
                        "status": 200,
                        "headers": headers,
                    })
                    return
                if shell_sent:
                    if message["type"] == "http.response.body":
                        await send({
                            "type": "http.response.body",
                            "body": shell.encode(),
                        })
                    return
                await send(message)

            await self.inner(scope, receive, _send)

    app.add_middleware(_SpaFallback)


def _media_type(suffix: str) -> str | None:
    return {
        ".html": "text/html; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
        ".js": "application/javascript",
        ".mjs": "application/javascript",
        ".css": "text/css",
        ".woff2": "font/woff2",
        ".woff": "font/woff",
        ".svg": "image/svg+xml",
        ".json": "application/json",
        ".png": "image/png",
        ".ico": "image/x-icon",
    }.get(suffix)
