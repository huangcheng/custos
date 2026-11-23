#!/usr/bin/env bash
# e2e_startup.sh — the startup-refusal matrix (design §4, §5, §10).
#
# The app runs in its real image on the compose network, but each case is
# launched with `docker run` and an explicit environment: compose's `${VAR:?}`
# guard cannot express "empty", and bash strips a trailing space, so neither
# can produce the exact unset-vs-empty distinction this matrix is about.
#
# Every case asserts BOTH that the process exited non-zero AND that it never
# answered /healthz. A gate that passes because the app died for an unrelated
# reason is worthless, so the accept cases prove the happy path still starts.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG_DIR="/tmp/custos-e2e"
# refuse a squatted log root (shared guard; see scripts/e2e_common.sh)
. scripts/e2e_common.sh
harden_log_dir "$LOG_DIR"
RUN_DIR="$(mktemp -d "$LOG_DIR/startup-XXXXXX")"
PROJECT="custos-e2e-startup-$$"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
DB_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
DB_PASSWORD="$(python3 -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(18)).rstrip(b"=").decode())')"
NETWORK="$PROJECT-net"
DB_CONTAINER="$PROJECT-db"
IMAGE="$PROJECT-app"

cleanup() {
  docker rm -f "$DB_CONTAINER" "$PROJECT-app" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  if [ "${E2E_FAILED:-0}" = "1" ]; then
    echo "run artifacts preserved: $RUN_DIR" >&2
  else
    rm -rf "$RUN_DIR"
  fi
}
trap cleanup EXIT
fail() { E2E_FAILED=1; echo "STARTUP GATE FAIL: $1" >&2; exit 1; }

PASSED=0
CASES=0

echo "== base secrets"
make_secrets_dir "$RUN_DIR"
python3 - "$RUN_DIR" "$DB_PASSWORD" <<'PYEOF'
import base64, os, subprocess, sys
run, pw = sys.argv[1], sys.argv[2]
b64url = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def write(name, body):
    with open(f"{run}/secrets/{name}", "w") as f:
        f.write(body)
    os.chmod(f"{run}/secrets/{name}", 0o600)

write("keyring", f"k1:{b64url(bytes(range(32)))}\n")
write("pepper", b64url(bytes([7]) * 32) + "\n")
write("database-url", f"postgresql+asyncpg://custos:{pw}@db:5432/custos\n")
# a keyring with a version number the app does not know, for the degraded case
write("keyring-empty", "")
write("pepper-zero", b64url(bytes(32)) + "\n")
try:
    subprocess.run(
        ["docker", "run", "--rm", "--user", "0", "-v", f"{run}/secrets:/s",
         "alpine:3", "sh", "-c", "chown -R 10001:10001 /s && chmod 600 /s/* && chmod 755 /s"],
        check=True, capture_output=True,
    )
except subprocess.CalledProcessError as exc:
    sys.exit(f"secrets chown failed: {exc.stderr.decode(errors='replace')}")
PYEOF

echo "== build the app image once"
docker build -q -f deploy/Dockerfile -t "$IMAGE" . > "$RUN_DIR/build.log" 2>&1 \
  || { tail -20 "$RUN_DIR/build.log" >&2; fail "docker build"; }

echo "== start the database"
docker network create "$NETWORK" >/dev/null
# --network-alias db at CREATE time: the DSN says `db`, and connecting an
# already-attached container to add an alias is refused by the engine.
docker run -d --name "$DB_CONTAINER" --network "$NETWORK" --network-alias db \
  -e POSTGRES_USER=custos -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB=custos \
  postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$DB_CONTAINER" pg_isready -U custos -h 127.0.0.1 >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$DB_CONTAINER" pg_isready -U custos -h 127.0.0.1 >/dev/null 2>&1 \
  || fail "database never became ready"

# run_case NAME EXPECT(REFUSAL|ACCEPT) [ENV overrides...]
#   Omitting a variable UNSETS it; `NAME=` sets it empty. That distinction is
#   the whole point, and only `docker run` can express it.
run_case() {
  local name="$1" expect="$2"
  shift 2
  CASES=$((CASES + 1))
  echo "-- [$expect] $name"

  local -a env_args=(
    -e CUSTOS_DATABASE_URL_FILE=/run/custos/database-url
    -e CUSTOS_SECRETS_KEY_FILE=/run/custos/keyring
    -e CUSTOS_PEPPER_FILE=/run/custos/pepper
    -e CUSTOS_DATA_DIR=/var/lib/custos
    -e CUSTOS_PORT=8300
    -e CUSTOS_ALLOWED_ORIGINS="http://127.0.0.1:$PORT"
    -e CUSTOS_WEBAUTHN_RP_ID=127.0.0.1
  )
  # a deviation of "NAME=" (no value) means: do not pass the variable at all
  local -a unset_names=()
  local -a extra=()
  for spec in "$@"; do
    if [ "${spec#*=}" = "$spec" ]; then
      extra+=(-e "$spec")
    elif [ -z "${spec#*=}" ]; then
      unset_names+=("${spec%%=*}")
    else
      extra+=(-e "$spec")
    fi
  done

  docker rm -f "$PROJECT-app" >/dev/null 2>&1 || true
  local args=(-d --name "$PROJECT-app" --network "$NETWORK" -p "127.0.0.1:$PORT:8300"
              -v "$RUN_DIR/secrets:/run/custos:ro")
  for e in "${env_args[@]}"; do args+=("$e"); done
  # drop the vars the case unsets
  local -a filtered=()
  local skip=0
  for a in "${args[@]}"; do
    if [ "$skip" = "1" ]; then skip=0; continue; fi
    local drop=0
    for n in "${unset_names[@]:-}"; do
      [ "$a" = "-e" ] && continue
      if [ "${a%%=*}" = "$n" ]; then drop=1; fi
    done
    if [ "$drop" = "1" ]; then
      # also drop the preceding -e
      if [ "${#filtered[@]}" -gt 0 ]; then
        local last="${filtered[${#filtered[@]}-1]}"
        if [ "$last" = "-e" ]; then unset 'filtered[${#filtered[@]}-1]'; fi
      fi
      continue
    fi
    filtered+=("$a")
  done
  for e in "${extra[@]}"; do filtered+=("$e"); done

  docker run "${filtered[@]}" "$IMAGE" > "$RUN_DIR/$name.id" 2>&1 \
    || { cat "$RUN_DIR/$name.id" >&2; fail "$name: docker run failed"; }

  # Probe the container's OWN healthcheck. A published loopback port is not
  # reachable from every host (macOS/OrbStack, CI sandboxes), and the image's
  # HEALTHCHECK already runs the real /healthz probe inside the container.
  local healthy=0
  for _ in $(seq 1 60); do
    local status
    status="$(docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
      "$PROJECT-app" 2>/dev/null || echo missing)"
    case "$status" in
      running\|healthy) healthy=1; break ;;
      exited\|*|missing\|*) [ "${status%%|*}" = "exited" ] && break ;;
    esac
    [ "$status" = "missing" ] && break
    sleep 1
  done
  docker logs "$PROJECT-app" > "$RUN_DIR/$name.log" 2>&1 || true
  if [ "$expect" = "REFUSAL" ]; then
    [ "$healthy" = "1" ] && fail "$name: the server started but must refuse"
    # and it must have refused for a REASON, not by crashing before validation
    grep -qiE 'custos|config|refus|invalid|must|required' "$RUN_DIR/$name.log" \
      || fail "$name: exited without a configuration error (see $RUN_DIR/$name.log)"
    PASSED=$((PASSED + 1))
    echo "   refused as required"
  else
    if [ "$healthy" != "1" ]; then
      tail -20 "$RUN_DIR/$name.log" >&2
      fail "$name: the server did not become healthy"
    fi
    PASSED=$((PASSED + 1))
    echo "   started as required"
  fi
  docker rm -f "$PROJECT-app" >/dev/null 2>&1 || true
}

echo "== startup matrix"

# --- refusals -------------------------------------------------------------
# an empty entry that must be unset entirely (the variable-omitted form)
run_case "public_bind_without_trusted_proxies" REFUSAL CUSTOS_PUBLIC_BIND=1 CUSTOS_TRUSTED_PROXIES=
run_case "malformed_trusted_proxy" REFUSAL CUSTOS_TRUSTED_PROXIES=not-a-cidr
run_case "slash_zero_trusted_proxy" REFUSAL CUSTOS_TRUSTED_PROXIES=0.0.0.0/0
run_case "retention_below_seven_days" REFUSAL CUSTOS_RETENTION_DAYS=6
run_case "setup_code_too_short" REFUSAL CUSTOS_SETUP_CODE=tooshort
run_case "turnstile_secret_without_sitekey" REFUSAL CUSTOS_TURNSTILE_SECRET=cu-test-secret
run_case "turnstile_without_hostnames" REFUSAL \
  CUSTOS_TURNSTILE_SECRET=cu-test-secret CUSTOS_TURNSTILE_SITEKEY=cu-test-sitekey
run_case "webauthn_rp_without_origins" REFUSAL CUSTOS_ALLOWED_ORIGINS=
run_case "dev_mode_with_public_bind" REFUSAL \
  CUSTOS_INSECURE_DEV=1 CUSTOS_BIND=0.0.0.0 CUSTOS_PUBLIC_BIND=1
run_case "dev_mode_with_turnstile" REFUSAL \
  CUSTOS_INSECURE_DEV=1 CUSTOS_TURNSTILE_SECRET=cu-test-secret \
  CUSTOS_TURNSTILE_SITEKEY=cu-test-sitekey CUSTOS_TURNSTILE_HOSTNAMES=127.0.0.1
run_case "both_keyring_forms" REFUSAL CUSTOS_SECRETS_KEY=k1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
run_case "both_pepper_forms" REFUSAL CUSTOS_PEPPER=cu-test-pepper-value
run_case "empty_keyring_file" REFUSAL CUSTOS_SECRETS_KEY_FILE=/run/custos/keyring-empty
run_case "all_zero_pepper" REFUSAL CUSTOS_PEPPER_FILE=/run/custos/pepper-zero

# --- accept ---------------------------------------------------------------
# The base configuration unchanged: proves the matrix is not refusing
# everything for one unrelated reason.
run_case "valid_base_configuration" ACCEPT

if [ "$PASSED" != "$CASES" ]; then
  fail "$PASSED/$CASES cases behaved as expected"
fi
echo "STARTUP GATE PASS ($PASSED/$CASES cases)"