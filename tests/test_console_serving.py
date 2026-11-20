"""Console static serving contract (design §3, plan 4 Task 1).

The SPA shell is no-store, hashed assets are immutable, the CSP header is
present on HTML, and the catch-all never swallows /api/* (JSON 404) or
/mcp (transport) — a bad fallback breaks either the API contract or the
MCP transport.
"""

import pytest
from fastapi.testclient import TestClient

from custos.app import create_app
from custos.config import load_settings
from tests.test_config import env

pytestmark = pytest.mark.usefixtures("pg_db")

SENTINEL = "cu-test-console-shell-sentinel"
CSP_PARTS = ("default-src 'self'", "script-src 'self'", "frame-ancestors 'none'")


@pytest.fixture
def dist(tmp_path):
    d = tmp_path / "dist"
    (d / "assets").mkdir(parents=True)
    (d / "index.html").write_text(
        f'<!doctype html><html><body><div id="root"></div>'
        f'<script type="module" src="/assets/app-abc123.js"></script>'
        f"<!--{SENTINEL}--></body></html>"
    )
    (d / "assets" / "app-abc123.js").write_text("console.log('cu-test-asset');")
    return d


def _client(dist_path, db, **extra):
    settings = load_settings(env(CUSTOS_DATABASE_URL=db, CUSTOS_SKIP_MIGRATE="1",
                                 CUSTOS_CONSOLE_DIST=str(dist_path), **extra))
    return TestClient(create_app(settings))


def test_console_absent_is_json_404(tmp_path, pg_db: str) -> None:
    with _client(tmp_path / "missing", pg_db) as c:
        r = c.get("/")
        assert r.status_code == 404
        assert r.json()["code"] == "not_found"
        assert c.get("/healthz").json() == {"status": "ok"}


def test_index_shell_and_assets_headers(dist, pg_db: str) -> None:
    with _client(dist, pg_db) as c:
        r = c.get("/")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert SENTINEL in r.text
        assert "no-store" in r.headers["cache-control"]
        csp = r.headers["content-security-policy"]
        for part in CSP_PARTS:
            assert part in csp
        a = c.get("/assets/app-abc123.js")
        assert a.status_code == 200
        cache = a.headers["cache-control"]
        assert "max-age=31536000" in cache and "immutable" in cache


def test_spa_fallback_serves_shell(dist, pg_db: str) -> None:
    with _client(dist, pg_db) as c:
        for path in ("/items", "/keys", "/device", "/settings/nested"):
            r = c.get(path)
            assert r.status_code == 200, path
            assert SENTINEL in r.text


def test_api_404_stays_json(dist, pg_db: str) -> None:
    with _client(dist, pg_db) as c:
        r = c.get("/api/nope")
        assert r.status_code == 404
        assert r.headers["content-type"].startswith("application/json")
        assert r.json()["code"] == "not_found"
        assert SENTINEL not in r.text


def test_mcp_and_healthz_not_swallowed(dist, pg_db: str) -> None:
    with _client(dist, pg_db) as c:
        assert c.get("/healthz").json() == {"status": "ok"}
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 401  # agent auth required, not the SPA shell
        assert SENTINEL not in r.text


def test_path_traversal_blocked(dist, pg_db: str) -> None:
    """Unauthenticated arbitrary file read must be impossible."""
    (dist.parent / "secret.txt").write_text("cu-test-outside-file")
    with _client(dist, pg_db) as c:
        for attempt in (
            "/../secret.txt",
            "/%2e%2e/secret.txt",
            "/assets/../../secret.txt",
            "/..%2fsecret.txt",
        ):
            r = c.get(attempt)
            assert "cu-test-outside-file" not in r.text, attempt
            assert r.status_code in (200, 404), attempt


def test_shell_requested_by_name_is_no_store(dist, pg_db: str) -> None:
    with _client(dist, pg_db) as c:
        r = c.get("/index.html")
        assert r.status_code == 200
        assert "no-store" in r.headers["cache-control"]


def test_dist_without_shell_is_json_404(tmp_path, pg_db: str) -> None:
    bare = tmp_path / "bare"
    bare.mkdir()
    with _client(bare, pg_db) as c:
        r = c.get("/")
        assert r.status_code == 404
        assert r.json()["code"] == "not_found"


def test_index_html_carries_csp_via_both_urls(dist, pg_db: str) -> None:
    """The shell must never reach a browser without its §3 CSP."""
    with _client(dist, pg_db) as c:
        for path in ("/", "/index.html", "/items"):
            r = c.get(path)
            assert r.status_code == 200, path
            csp = r.headers.get("content-security-policy", "")
            for part in CSP_PARTS:
                assert part in csp, (path, part)
            assert "no-store" in r.headers["cache-control"], path


def test_relative_console_dist_resolves(tmp_path, monkeypatch, pg_db: str) -> None:
    d = tmp_path / "dist"
    (d / "assets").mkdir(parents=True)
    (d / "index.html").write_text("<html>cu-test-relative</html>")
    monkeypatch.chdir(tmp_path)
    settings = load_settings(
        env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1", CUSTOS_CONSOLE_DIST="dist")
    )
    with TestClient(create_app(settings)) as c:
        r = c.get("/")
        assert r.status_code == 200
        assert "cu-test-relative" in r.text


def test_html_is_served_as_html(dist, pg_db: str) -> None:
    """A bookmarked /index.html must render, not download."""
    with _client(dist, pg_db) as c:
        r = c.get("/index.html")
        assert r.headers["content-type"].startswith("text/html")


def test_missing_asset_404s_instead_of_serving_the_shell(dist, pg_db: str) -> None:
    """A stale deploy must surface as 404, not as 200 HTML for a JS import."""
    with _client(dist, pg_db) as c:
        r = c.get("/assets/chunk-missing.js")
        assert r.status_code == 404
        assert SENTINEL not in r.text


def test_shell_headers_are_identical_on_every_url(dist, pg_db: str) -> None:
    """The shell must not gain or lose hardening headers by entry URL."""
    with _client(dist, pg_db) as c:
        seen = []
        for path in ("/", "/index.html", "/items", "/keys/deep/link"):
            r = c.get(path)
            assert r.status_code == 200, path
            seen.append(
                (
                    r.headers.get("content-security-policy"),
                    r.headers.get("x-content-type-options"),
                    r.headers.get("referrer-policy"),
                    r.headers.get("cache-control"),
                )
            )
        assert len(set(seen)) == 1, seen
        csp, nosniff, referrer, cache = seen[0]
        assert csp and "frame-ancestors 'none'" in csp
        assert nosniff == "nosniff"
        assert referrer == "no-referrer"
        assert "no-store" in cache
