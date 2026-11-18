#!/usr/bin/env bash
# e2e.sh — API + remote-MCP end-to-end gate (design §11, plan-1 scope).
# Throwaway postgres + app via compose; fake secrets generated per run.
# Operator setup/mint arrives with plan 2 — keys are seeded directly into
# the throwaway DB via scripts/e2e_seed.py (documented E2E scaffolding).
set -euo pipefail
cd "$(dirname "$0")/.."

LOG_DIR="/tmp/custos-e2e"
mkdir -p "$LOG_DIR"
RUN_DIR="$(mktemp -d "$LOG_DIR/run-XXXXXX")"
PROJECT="custos-e2e-$$"
export E2E_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
COMPOSE=(docker compose -p "$PROJECT" --env-file "$RUN_DIR/env" -f deploy/docker-compose.yml)

cleanup() {
  if [ "${E2E_KEEP:-}" = "1" ]; then
    echo "E2E_KEEP=1: stack and run dir preserved ($RUN_DIR)" >&2
    return
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if [ "${E2E_FAILED:-0}" = "1" ]; then
    echo "run artifacts preserved: $RUN_DIR" >&2
  else
    rm -rf "$RUN_DIR"
  fi
}
trap cleanup EXIT

fail() { E2E_FAILED=1; echo "E2E FAIL: $1 (artifacts: $RUN_DIR; E2E_KEEP=1 keeps the stack)" >&2; exit 1; }

echo "== generate throwaway secrets"
python3 - "$RUN_DIR" <<'PYEOF'
import base64, os, secrets, sys
run = sys.argv[1]
b64url = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
os.makedirs(f"{run}/secrets", exist_ok=True)
pw = b64url(secrets.token_bytes(18))
with open(f"{run}/secrets/keyring", "w") as f: f.write(f"k1:{b64url(secrets.token_bytes(32))}\n")
with open(f"{run}/secrets/pepper", "w") as f: f.write(b64url(secrets.token_bytes(32)) + "\n")
with open(f"{run}/secrets/database-url", "w") as f:
    f.write(f"postgresql+asyncpg://custos:{pw}@db:5432/custos\n")
for name in ("keyring", "pepper", "database-url"):
    os.chmod(f"{run}/secrets/{name}", 0o600)
# the app container runs as uid 10001: hand ownership over (Linux hosts
# enforce it; Docker Desktop ignores it). Best-effort via a one-shot container.
import subprocess
try:
    subprocess.run(
        ["docker", "run", "--rm", "--user", "0", "-v", f"{run}/secrets:/s",
         "alpine:3", "sh", "-c", "chown 10001:10001 /s /s/* && chmod 600 /s/* && chmod 755 /s"],
        check=True, capture_output=True,
    )
except subprocess.CalledProcessError as exc:
    sys.exit(f"secrets chown failed: {exc.stderr.decode(errors='replace')}")
with open(f"{run}/env", "w") as f:
    f.write(f"CUSTOS_DB_PASSWORD={pw}\nCUSTOS_SECRETS_DIR={run}/secrets\n"
            f"CUSTOS_TRUSTED_PROXIES=172.16.0.0/12\nCUSTOS_PORT={os.environ['E2E_PORT']}\n")
PYEOF

echo "== start stack"
"${COMPOSE[@]}" up -d --build > "$RUN_DIR/compose.log" 2>&1 || fail "compose up (see $RUN_DIR/compose.log)"
BASE="http://127.0.0.1:$E2E_PORT"
for i in $(seq 1 60); do
  curl -fsS -m 2 "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 1
  [ "$i" = 60 ] && fail "app did not become healthy"
done

echo "== seed agent keys (E2E scaffolding, pre-operator-auth)"
docker exec -i "$PROJECT-app-1" /app/.venv/bin/python - < scripts/e2e_seed.py > "$RUN_DIR/tokens.json" \
  || fail "seed"

echo "== assertions"
uv run python - "$BASE" "$RUN_DIR/tokens.json" <<'PYEOF'
import json, subprocess, sys, tempfile, os
import httpx

base, tokens_path = sys.argv[1], sys.argv[2]
tokens = json.load(open(tokens_path))
rw = {"Authorization": f"Bearer {tokens['rw']}"}
ro = {"Authorization": f"Bearer {tokens['ro']}"}
scoped = {"Authorization": f"Bearer {tokens['scoped']}"}
c = httpx.Client(base_url=base, timeout=15)

def check(cond, msg):
    if not cond:
        print(f"ASSERT FAIL: {msg}", file=sys.stderr); sys.exit(1)

# create as read-write agent over REST
r = c.post("/api/items", headers=rw, json={"name": "e2e-item", "notes": "n", "fields": [
    {"name": "API_KEY", "secret": True, "value": "cu-test.e2e-secret"},
    {"name": "URL", "secret": False, "value": "https://example.invalid"},
]})
check(r.status_code == 201, "create 201")
etag = r.headers["etag"]
ok = c.put("/api/items/e2e-item", headers={**rw, "If-Match": etag},
           json={"notes": "n", "fields": [
               {"name": "API_KEY", "secret": True, "value": "cu-test.e2e-secret"},
               {"name": "URL", "secret": False, "value": "https://example.invalid"}]})
check(ok.status_code == 200 and ok.headers["etag"] == '"2"', "if-match positive")

# out-of-scope read AND write -> 404 identical to missing
a = c.get("/api/items/e2e-item", headers=scoped)
b = c.get("/api/items/never-existed", headers=scoped)
w = c.put("/api/items/e2e-item", headers=scoped, json={"notes": "", "fields": []})
m = c.put("/api/items/never-existed", headers=scoped, json={"notes": "", "fields": []})
check(a.status_code == b.status_code == w.status_code == m.status_code == 404, "scope 404s")
check(a.content == b.content == w.content == m.content, "byte-identical 404 bodies")

# read-only write -> 403
r = c.post("/api/items", headers=ro, json={"name": "e2e-ro", "fields": []})
check(r.status_code == 403 and r.json()["code"] == "read_only", "read-only 403")

# If-Match conflict
r = c.put("/api/items/e2e-item", headers={**rw, "If-Match": '"99"'},
          json={"notes": "", "fields": []})
check(r.status_code == 409, "if-match 409")

# hostile env value round-trips through eval without execution
hostile = "'; touch /tmp/custos-e2e-pwn; echo '"
r = c.patch("/api/items/e2e-item", headers=rw, json={"fields": [
    {"name": "HOSTILE", "secret": True, "value": hostile}]})
check(r.status_code == 200, "patch hostile")
env_resp = c.get("/api/items/e2e-item/env", headers=rw)
check(env_resp.status_code == 200, "env 200")
env_out = env_resp.text
with tempfile.TemporaryDirectory() as td:
    marker = f"{td}/pwn"
    script = env_out.replace("/tmp/custos-e2e-pwn", marker) + '\nprintf %s "$HOSTILE"'
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    check(res.stdout == hostile.replace("/tmp/custos-e2e-pwn", marker), "eval round-trip")
    check(not os.path.exists(marker), "no execution")

# soft-delete hides; upsert on deleted -> 409
r = c.delete("/api/items/e2e-item", headers=rw)
check(r.status_code == 204, "delete 204")
check(c.get("/api/items/e2e-item", headers=rw).status_code == 404, "deleted hidden")
r = c.put("/api/items/e2e-item?upsert=1", headers=rw, json={"notes": "", "fields": []})
check(r.status_code == 409, "upsert-on-deleted 409")

# caps: 413 on oversize value
r = c.post("/api/items", headers=rw, json={"name": "e2e-big", "fields": [
    {"name": "K", "secret": False, "value": "x" * (16 * 1024 + 1)}]})
check(r.status_code == 413, "value cap 413")

# uniform 401
r1 = c.get("/api/items", headers={"Authorization": "Bearer garbage"})
r2 = c.get("/api/items", headers={"Authorization": "Bearer cu-000000000000." + "A" * 43})
check(r1.status_code == r2.status_code == 401 and r1.content == r2.content, "uniform 401")

print("REST ASSERTIONS OK")
PYEOF
echo "== remote MCP path (real client over Streamable HTTP)"
uv run python - "$BASE" "$RUN_DIR/tokens.json" <<'PYEOF'
import anyio, json, sys
import httpx2
from contextlib import AsyncExitStack
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

base, tokens_path = sys.argv[1], sys.argv[2]
tokens = json.load(open(tokens_path))

def check(cond, msg):
    if not cond:
        print(f"ASSERT FAIL: {msg}", file=sys.stderr); sys.exit(1)

class _HttpTransportCM:
    def __init__(self, token):
        self.token = token

    async def __aenter__(self):
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()
        http = await self._stack.enter_async_context(httpx2.AsyncClient(
            base_url=base, headers={"Authorization": f"Bearer {self.token}"}))
        return await self._stack.enter_async_context(
            streamable_http_client(f"{base}/mcp", http_client=http))

    async def __aexit__(self, *exc):
        return await self._stack.__aexit__(*exc)


async def with_client(token, fn):
    async with Client(_HttpTransportCM(token)) as client:
        return await fn(client)

async def main():
    async def flow(client):
        r = await client.call_tool("custos_put_item", {
            "name": "e2e-mcp", "notes": "", "fields": [
                {"name": "K", "secret": True, "value": "cu-test.mcp-e2e"}]})
        check(not r.is_error, "mcp upsert create")
        g = await client.call_tool("custos_get_item", {"name": "e2e-mcp"})
        check("cu-test.mcp-e2e" in str(g.content), "mcp get round-trip")
        r = await client.call_tool("custos_put_item", {
            "name": "e2e-mcp", "notes": "x", "fields": [
                {"name": "K", "secret": True, "value": "cu-test.mcp-e2e-2"}]})
        check(not r.is_error, "mcp upsert replace")
        listing = await client.call_tool("custos_list_items", {})
        check("e2e-mcp" in str(listing.content), "mcp list")
        d = await client.call_tool("custos_delete_item", {"name": "e2e-mcp"})
        check(not d.is_error, "mcp delete")
    await with_client(tokens["rw"], flow)

    # read-only key sees write tools but gets read_only errors
    async def ro_flow(client):
        from mcp.shared.exceptions import MCPError
        try:
            await client.call_tool("custos_put_item",
                                   {"name": "e2e-mcp-ro", "notes": "", "fields": []})
            check(False, "read-only mcp write must fail")
        except MCPError as e:
            check("read_only" in str(e), "read_only error code")
    await with_client(tokens["ro"], ro_flow)
    print("MCP ASSERTIONS OK")

anyio.run(main)
PYEOF
echo "== revoke bites on the next MCP request"
BEFORE_AUTHFAIL=$(docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc \
  "SELECT count(*) FROM auth_events WHERE kind='agent_auth' AND NOT ok;")
BEFORE_AUDITFAIL=$(docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc \
  "SELECT count(*) FROM audit WHERE action='auth.failure' AND ok=false;")
docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc \
  "UPDATE agent_keys SET revoked_at = now() WHERE label = 'e2e-rw';" >/dev/null
uv run python - "$BASE" "$RUN_DIR/tokens.json" <<'PYEOF'
import anyio, json, sys
import httpx2
base, tokens_path = sys.argv[1], sys.argv[2]
tokens = json.load(open(tokens_path))
async def main():
    async with httpx2.AsyncClient(base_url=base,
            headers={"Authorization": f"Bearer {tokens['rw']}"}) as http:
        r = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                          "method": "tools/list", "params": {}})
        if r.status_code != 401:
            print(f"ASSERT FAIL: revoked key got {r.status_code}", file=sys.stderr)
            sys.exit(1)
    print("REVOCATION OK")
anyio.run(main)
PYEOF
AFTER_AUTHFAIL=$(docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc \
  "SELECT count(*) FROM auth_events WHERE kind='agent_auth' AND NOT ok;")
[ "$AFTER_AUTHFAIL" -gt "$BEFORE_AUTHFAIL" ] || fail "MCP gate auth-failure ledger delta"
AFTER_AUDITFAIL=$(docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc \
  "SELECT count(*) FROM audit WHERE action='auth.failure' AND ok=false;")
[ "$AFTER_AUDITFAIL" -gt "$BEFORE_AUDITFAIL" ] || fail "MCP gate auth.failure audit delta"

echo "== audit rows exist for the specific writes/auth performed"
docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc \
  "SELECT count(*) FROM audit WHERE item_name='e2e-item' AND action IN ('create','put','patch','delete');" \
  | grep -qv '^0$' || fail "e2e-item write audit rows"
docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc \
  "SELECT count(*) FROM audit WHERE item_name='e2e-mcp' AND action IN ('create','put','delete');" \
  | grep -qv '^0$' || fail "e2e-mcp write audit rows"
docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc \
  "SELECT count(*) FROM auth_events WHERE kind='agent_auth' AND NOT ok;" \
  | grep -qv '^0$' || fail "auth failure ledger rows"
# MCP-path auth failure verified by the before/after deltas above

echo "E2E PASS (log dir: $LOG_DIR)"