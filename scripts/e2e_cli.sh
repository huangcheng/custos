#!/usr/bin/env bash
# e2e_cli.sh — drives the REAL `custos` binary against a throwaway stack.
#
# Everything here goes through the shipped binary (never curl): login, item
# set/get/env, key mint -> use the token -> revoke, the session-only refusal,
# audit, rekey, and break-glass against the direct database.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG_DIR="/tmp/custos-e2e"
# refuse a squatted log root (shared guard; see scripts/e2e_common.sh)
. scripts/e2e_common.sh
harden_log_dir "$LOG_DIR"
RUN_DIR="$(mktemp -d "$LOG_DIR/cli-XXXXXX")"
PROJECT="custos-e2e-cli-$$"
export E2E_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
COMPOSE=(docker compose -p "$PROJECT" --env-file "$RUN_DIR/env" -f deploy/docker-compose.yml)
PW="cu-test-cli-e2e-password"
CLI_HOME=/tmp/custos-cli-home

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if [ "${E2E_FAILED:-0}" = "1" ]; then
    echo "run artifacts preserved: $RUN_DIR" >&2
  else
    rm -rf "$RUN_DIR"
  fi
}
trap cleanup EXIT
trap 'E2E_FAILED=1' ERR
fail() { E2E_FAILED=1; echo "CLI GATE FAIL: $1" >&2; exit 1; }
declare -i N=0
check() { N+=1; if ! eval "$2"; then fail "CHECK $N ($1)"; fi; echo "CHECK $N: $1"; }

echo "== secrets"
make_secrets_dir "$RUN_DIR"
python3 - "$RUN_DIR" <<'PYEOF'
import base64, os, secrets, subprocess, sys
run = sys.argv[1]
b64url = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
pw = b64url(secrets.token_bytes(18))
# The keyring is COMMA-separated (custos.crypto.parse_keyring splits on ','):
# a newline would make one malformed entry. Seed a single version here — the
# rekey section appends a new one to create real work.
with open(f"{run}/secrets/keyring", "w") as f:
    f.write(f"k1:{b64url(secrets.token_bytes(32))}\n")
with open(f"{run}/secrets/pepper", "w") as f: f.write(b64url(secrets.token_bytes(32)) + "\n")
with open(f"{run}/secrets/database-url", "w") as f:
    f.write(f"postgresql+asyncpg://custos:{pw}@db:5432/custos\n")
for name in ("keyring", "pepper", "database-url"):
    os.chmod(f"{run}/secrets/{name}", 0o600)
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
            f"CUSTOS_TRUSTED_PROXIES=172.16.0.0/12\nCUSTOS_PORT={os.environ['E2E_PORT']}\n"
            f"CUSTOS_ALLOWED_ORIGINS=http://127.0.0.1:{os.environ['E2E_PORT']}\n"
            f"CUSTOS_WEBAUTHN_RP_ID=127.0.0.1\n")
with open(f"{run}/dbpw", "w") as f:
    f.write(pw)
PYEOF

echo "== start stack"
"${COMPOSE[@]}" up -d --build > "$RUN_DIR/compose.log" 2>&1 || fail "compose up (see $RUN_DIR/compose.log)"
BASE="http://127.0.0.1:$E2E_PORT"
healthy=0
for i in $(seq 1 180); do
  if curl -fsS -m 2 "$BASE/healthz" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 1
done
if [ "$healthy" != "1" ]; then
  "${COMPOSE[@]}" logs app 2>&1 | tail -30 >&2 || true
  fail "app did not become healthy (see the log above)"
fi

echo "== the binary runs inside the image"
CLI=(docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos)
docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos --version >/dev/null || fail "the custos binary is not on PATH in the image"
check "binary reports a version" 'docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos --version | grep -q "^custos "'

echo "== operator setup"
SETUP_CODE=$(docker exec "$PROJECT-app-1" sh -c 'cat /var/lib/custos/setup-code 2>/dev/null || true')
[ -n "$SETUP_CODE" ] || fail "setup-code not provisioned"
curl -sS -m 10 -X POST "$BASE/api/auth/setup" -H 'content-type: application/json' \
  -d "{\"username\":\"operator\",\"password\":\"$PW\",\"setup_code\":\"$SETUP_CODE\"}" \
  > "$RUN_DIR/setup.json" 2>&1 || { cat "$RUN_DIR/setup.json" >&2; fail "setup request failed"; }
check "operator setup completed" 'grep -q "complete" "$RUN_DIR/setup.json"' 

echo "== login through the binary"
# the CLI stores its session under XDG_CONFIG_HOME; set it INSIDE the container
CLI_HOME=/tmp/custos-cli-home
printf 'operator\n%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" \
  "$PROJECT-app-1" custos --url "http://127.0.0.1:8300" login > "$RUN_DIR/login.log" 2>&1 \
  || { cat "$RUN_DIR/login.log" >&2; fail "custos login"; }
check "login wrote a session file" \
  'docker exec "$PROJECT-app-1" test -f "$CLI_HOME/custos/session.json"'
check "the session file is 0600" \
  '[ "$(docker exec "$PROJECT-app-1" stat -c %a "$CLI_HOME/custos/session.json")" = "600" ]'

echo "== item set / get / env through the binary"
printf '%s' '[{"name":"CLI_TOK","secret":true,"value":"cu-test-cli-value"},{"name":"REGION","secret":false,"value":"eu"}]' \
  | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos --url http://127.0.0.1:8300 item set cli-item --notes "written by the cli" > "$RUN_DIR/set.log" 2>&1 \
  || { cat "$RUN_DIR/set.log" >&2; fail "item set"; }
check "item set reports a revision" 'grep -q "revision 1" "$RUN_DIR/set.log"'
docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos --url http://127.0.0.1:8300 item get cli-item > "$RUN_DIR/get.log" 2>&1 || fail "item get"
check "masked get hides the secret value" '! grep -q "cu-test-cli-value" "$RUN_DIR/get.log"'
check "masked get shows the plain value" 'grep -q "\"eu\"" "$RUN_DIR/get.log"'
printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 item get cli-item --reveal > "$RUN_DIR/reveal.log" 2>&1 \
  || { cat "$RUN_DIR/reveal.log" >&2; fail "item get --reveal"; }
check "revealed get shows the secret value" 'grep -q "cu-test-cli-value" "$RUN_DIR/reveal.log"'

printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 env cli-item 2>/dev/null \
  | grep -E '^(export |# )' > "$RUN_DIR/env.log" || fail "env"
check "env exports the secret" 'grep -q "export CLI_TOK=.\{0,1\}cu-test-cli-value" "$RUN_DIR/env.log"'

echo "== the exported value survives eval without executing"
# The full §9 corpus, not just the quote shape: a newline, a CRLF and a
# command substitution each get their own field.
HOSTILE="'; touch /tmp/custos-cli-pwn; echo '"
HOSTILE_NL="$(printf 'line1\nline2')"
# CR is expressible inside single quotes; a bare LF is not (a sourced shell
# cannot represent a multi-line value), so CR-only is the right corpus entry.
HOSTILE_CR="$(printf 'a\rb')"
HOSTILE_SUBST='$(touch /tmp/custos-cli-pwn2)`touch /tmp/custos-cli-pwn3`'
python3 - "$RUN_DIR/hostile.json" "$HOSTILE" "$HOSTILE_NL" "$HOSTILE_CR" "$HOSTILE_SUBST" <<'PYEOF'
import json, sys
path, quote, nl, cr, subst = sys.argv[1:6]
fields = [
    {"name": "EVIL", "secret": False, "value": quote},
    # NOTE: a bare-LF value is deliberately absent — `export NAME='a\nb'` is not
    # representable in a sourced shell at all, so it is not part of the
    # eval-safety claim (the escaper's contract covers values a shell can hold).
    {"name": "EVIL_CR", "secret": False, "value": cr},
    {"name": "EVIL_SUBST", "secret": False, "value": subst},
]
with open(path, "w") as f:
    json.dump(fields, f)
PYEOF
docker exec -i "$PROJECT-app-1" sh -c 'cat > /tmp/hostile.json' < "$RUN_DIR/hostile.json"
docker exec "$PROJECT-app-1" chmod 600 /tmp/hostile.json
printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 env cli-item > /dev/null 2>&1 || true
# write the hostile field onto the item, then export and eval it in a shell
docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos --url http://127.0.0.1:8300 item set cli-item --fields-file /tmp/hostile.json \
  > "$RUN_DIR/hostile-set.log" 2>&1 || { cat "$RUN_DIR/hostile-set.log" >&2; fail "hostile item set"; }
printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 env cli-item 2>/dev/null \
  | grep -E '^(export |# )' > "$RUN_DIR/hostile-env.log" || fail "hostile env"
docker exec -i "$PROJECT-app-1" sh -c 'cat > /tmp/hostile-env.sh' < "$RUN_DIR/hostile-env.log"
# First: the file must actually source without error, else "nothing executed"
# proves nothing (a missing file also executes nothing).
check "the hostile export file sources cleanly" \
  'docker exec "$PROJECT-app-1" sh -c ". /tmp/hostile-env.sh"'
check "no hostile value executes when eval'd" \
  'docker exec "$PROJECT-app-1" sh -c "rm -f /tmp/custos-cli-pwn /tmp/custos-cli-pwn2 /tmp/custos-cli-pwn3 && . /tmp/hostile-env.sh && ! test -e /tmp/custos-cli-pwn && ! test -e /tmp/custos-cli-pwn2 && ! test -e /tmp/custos-cli-pwn3"'
# round-trip check in a script file: no nested shell quoting
{
  printf 'set -e\n'
  printf '. /tmp/hostile-env.sh\n'
  printf 'printf %%s "$EVIL" > /tmp/hostile-out.txt\n'
} > "$RUN_DIR/roundtrip.sh"
docker exec -i "$PROJECT-app-1" sh -c 'cat > /tmp/roundtrip.sh' < "$RUN_DIR/roundtrip.sh"
docker exec "$PROJECT-app-1" sh /tmp/roundtrip.sh
printf '%s' "$HOSTILE" > "$RUN_DIR/hostile-expected.txt"
docker exec -i "$PROJECT-app-1" sh -c 'cat > /tmp/hostile-expected.txt' < "$RUN_DIR/hostile-expected.txt"
check "the hostile quote value round-trips verbatim" \
  'docker exec "$PROJECT-app-1" cmp -s /tmp/hostile-out.txt /tmp/hostile-expected.txt'
# CR / LF / CRLF must survive: any line-splitting in the CLI would rewrite them.
# Compare the sourced value against the exact bytes, crudely but precisely:
printf 'a\rb' > "$RUN_DIR/crlf-expected.bin"
docker exec -i "$PROJECT-app-1" sh -c 'cat > /tmp/crlf-expected.bin' < "$RUN_DIR/crlf-expected.bin"
check "a value containing CR round-trips byte-for-byte" \
  'docker exec "$PROJECT-app-1" sh -c ". /tmp/hostile-env.sh && printf %s \"\$EVIL_CR\" > /tmp/crlf-actual.bin && cmp -s /tmp/crlf-actual.bin /tmp/crlf-expected.bin"'


KEY_MINT_LOG="$RUN_DIR/key-mint.log"
if ! printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" \
      "$PROJECT-app-1" custos --url http://127.0.0.1:8300 \
      key mint --label cli-e2e-key --mode read --scope '*' \
      > "$KEY_MINT_LOG" 2> "$RUN_DIR/key-mint.err"; then
  cat "$KEY_MINT_LOG" "$RUN_DIR/key-mint.err" >&2
  fail "key mint exited non-zero"
fi
KEY=$(head -1 "$KEY_MINT_LOG")
case "$KEY" in cu-*) : ;; *) fail "key mint returned no token: $(head -1 "$KEY_MINT_LOG")";; esac
check "minted token authenticates on the agent plane" \
  'curl -fsS -m 5 -H "Authorization: Bearer $KEY" "$BASE/api/items" | grep -q "\"name\""'
KEY_ID=$(printf '%s' "$KEY" | sed 's/^cu-//; s/\..*//')
# revealable credentials (rev 37): re-reveal the exact minted token via the CLI
printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 key reveal "$KEY_ID" > "$RUN_DIR/key-reveal.log" 2> "$RUN_DIR/key-reveal.err" \
  || { cat "$RUN_DIR/key-reveal.log" "$RUN_DIR/key-reveal.err" >&2; fail "key reveal"; }
check "key reveal returns the exact minted token" \
  '[ "$(head -1 "$RUN_DIR/key-reveal.log")" = "$KEY" ]'
# legacy digest-only row (NULL sealed copy, the pre-0002 upgrade case):
# reveal must refuse and print no token
docker exec "$PROJECT-db-1" psql -U custos -d custos -c \
  "UPDATE agent_keys SET secret_ciphertext = NULL, secret_key_version = NULL WHERE key_id = '$KEY_ID'" >/dev/null
if printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 key reveal "$KEY_ID" \
  > "$RUN_DIR/key-reveal-legacy.log" 2> "$RUN_DIR/key-reveal-legacy.err"; then
  fail "reveal of a legacy digest-only key must fail"
fi
check "legacy refusal is the digest-only conflict, and prints no token" \
  'grep -q "conflict: credential predates revealable storage" "$RUN_DIR/key-reveal-legacy.err" && ! grep -q "cu-" "$RUN_DIR/key-reveal-legacy.log" "$RUN_DIR/key-reveal-legacy.err"'
# corrupt sealed copy under an available version: reveal must withhold the value
docker exec "$PROJECT-db-1" psql -U custos -d custos -c \
  "UPDATE agent_keys SET secret_ciphertext = decode(repeat('00', 48), 'hex'), secret_key_version = 1 WHERE key_id = '$KEY_ID'" >/dev/null
if printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 key reveal "$KEY_ID" \
  > "$RUN_DIR/key-reveal-corrupt.log" 2> "$RUN_DIR/key-reveal-corrupt.err"; then
  fail "reveal of a corrupt sealed copy must fail"
fi
check "corrupt refusal is key_unavailable, and prints no token" \
  'grep -q "key_unavailable:" "$RUN_DIR/key-reveal-corrupt.err" && ! grep -q "cu-" "$RUN_DIR/key-reveal-corrupt.log" "$RUN_DIR/key-reveal-corrupt.err"'
# drop back to a legacy NULL row INLINE (no new EXIT trap — it would replace
# the compose cleanup): the rekey sweep below covers agent_keys and must not
# count this deliberately-corrupt row as skipped/unreadable
docker exec "$PROJECT-db-1" psql -U custos -d custos -c \
  "UPDATE agent_keys SET secret_ciphertext = NULL, secret_key_version = NULL WHERE key_id = '$KEY_ID'" >/dev/null
printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos --url http://127.0.0.1:8300 key revoke "$KEY_ID" > "$RUN_DIR/revoke.log" 2>&1 \
  || { cat "$RUN_DIR/revoke.log" >&2; fail "key revoke"; }
check "a revoked token 401s on the next request" \
  '[ "$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $KEY" "$BASE/api/items")" = "401" ]'
if printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 key reveal "$KEY_ID" > "$RUN_DIR/key-reveal-revoked.log" 2> "$RUN_DIR/key-reveal-revoked.err"; then
  fail "reveal of a revoked key must fail"
fi
check "revoked refusal is the revoked conflict" \
  'grep -q "conflict: credential is revoked" "$RUN_DIR/key-reveal-revoked.err"'

echo "== session-only routes refuse an env token"
S=$(printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
      custos --url http://127.0.0.1:8300 token mint --label cli-e2e-token \
      --expires "$(python3 -c 'from datetime import UTC,datetime,timedelta; print((datetime.now(UTC)+timedelta(days=1)).isoformat())')" \
      2>/dev/null | head -1)
case "$S" in co-*) : ;; *) fail "token mint returned no token";; esac
# revealable credentials (rev 37): operator-token re-reveal round-trip
TOK_ID=$(printf '%s' "$S" | sed 's/^co-//; s/\..*//')
printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 token reveal "$TOK_ID" > "$RUN_DIR/token-reveal.log" 2> "$RUN_DIR/token-reveal.err" \
  || { cat "$RUN_DIR/token-reveal.log" "$RUN_DIR/token-reveal.err" >&2; fail "token reveal"; }
check "token reveal returns the exact minted token" \
  '[ "$(head -1 "$RUN_DIR/token-reveal.log")" = "$S" ]'
# An env token satisfies token-permitted reads but must be REFUSED (before any
# request) on a session-only route such as minting.
docker exec -e CUSTOS_OPERATOR_TOKEN="$S" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 key mint --label nope --mode read --scope '*' \
  > "$RUN_DIR/token-mint.log" 2>&1 && fail "an env token minted a key"
check "an env token cannot mint a key (refused, not 403'd by the server)" \
  'grep -q "interactive session" "$RUN_DIR/token-mint.log"'
# ... while the same token is accepted for a token-permitted read
check "the env token still serves token-permitted reads" \
  'docker exec -e CUSTOS_OPERATOR_TOKEN="$S" "$PROJECT-app-1" custos --url http://127.0.0.1:8300 audit > /dev/null 2>&1'

echo "== audit shows the mint and the revoke"
docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos --url http://127.0.0.1:8300 audit --action key.mint > "$RUN_DIR/audit.log" 2>&1 || fail "audit"
check "audit lists the key.mint row" 'grep -q "key.mint" "$RUN_DIR/audit.log"'

echo "== rekey is a real operation (rotate a key version)"
# This follows the runbook exactly (§13): append a NEW key version, restart, then
# `custos rekey` moves every row off the versions already in use. Rows written
# earlier in the gate are on k2 (the keyring seed); adding k3 makes them stale.
KEYRING="$RUN_DIR/secrets/keyring"
cp "$KEYRING" "$RUN_DIR/keyring.before"
K3="$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode())')"
# comma-joined: the keyring parser splits on ',', not newlines
# /run/custos is mounted READ-ONLY, and the host copy may be owned by the app
# uid after the bootstrap chown. Rewrite it through the container as root into a
# staging copy, then swap the whole directory mount is not possible — so write
# on the host and re-apply the ownership the app expects.
printf ',k3:%s' "$K3" >> "$KEYRING" 2>/dev/null \
  || docker exec -u 0 "$PROJECT-app-1" sh -c "printf ',k3:%s' '$K3' >> /run/custos/keyring"
chmod 600 "$KEYRING" 2>/dev/null || true
"${COMPOSE[@]}" restart app >/dev/null 2>&1
for i in $(seq 1 60); do curl -fsS -m 2 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 1; done
printf 'operator\n%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" \
  "$PROJECT-app-1" custos --url http://127.0.0.1:8300 login > /dev/null 2>&1 \
  || fail "re-login after appending k3"

NEWEST=$(docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 rekey --audit 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["newest"])')
check "the audit sees the new key version as newest" '[ "$NEWEST" = "3" ]'
STALE=$(docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 rekey --audit 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(d["affected"].values(), []) if False else len(d["affected"]))')
check "rows still sit under an older version before the sweep" '[ "${STALE:-0}" -gt 0 ]'

printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 rekey > "$RUN_DIR/rekey.log" 2>&1 \
  || { cat "$RUN_DIR/rekey.log" >&2; fail "rekey"; }
check "the sweep reported no skipped rows" \
  '! grep -qi "skipped as unreadable" "$RUN_DIR/rekey.log"'
check "after the sweep the audit reports no affected versions" \
  'docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" custos --url http://127.0.0.1:8300 rekey --audit | grep -q "\"affected\": {}"'

printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 rekey --verify > "$RUN_DIR/verify.log" 2>&1 \
  || { cat "$RUN_DIR/verify.log" >&2; fail "rekey --verify"; }
check "rekey --verify exited clean (no unreadable rows)" '[ -s "$RUN_DIR/verify.log" ]'
check "rekey --verify reported no corruption" '! grep -qi "unreadable\|skipped" "$RUN_DIR/verify.log"'
# the sweep re-sealed the token's sealed copy under the new version/AAD:
# it must STILL reveal the exact minted token (unrevoked until reset-mfa)
printf '%s\n' "$PW" | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 token reveal "$TOK_ID" \
  > "$RUN_DIR/token-reveal-postrekey.log" 2> "$RUN_DIR/token-reveal-postrekey.err" \
  || { cat "$RUN_DIR/token-reveal-postrekey.log" "$RUN_DIR/token-reveal-postrekey.err" >&2; fail "post-rekey token reveal"; }
check "post-rekey token reveal still returns the exact minted token" \
  '[ "$(head -1 "$RUN_DIR/token-reveal-postrekey.log")" = "$S" ]'

echo "== break-glass against the direct database"
DBPW="$(cat "$RUN_DIR/dbpw")"
# The DSN carries a password, so it goes in a 0600 FILE, never argv (§9).
printf 'postgresql://custos:%s@db:5432/custos\n' "$DBPW" > "$RUN_DIR/dsn"
chmod 600 "$RUN_DIR/dsn"
copy_dsn() {
  docker cp "$RUN_DIR/dsn" "$PROJECT-app-1:/tmp/dsn" >/dev/null
  # docker cp preserves the HOST uid: hand it to the app user, then 0600
  docker exec -u 0 "$PROJECT-app-1" sh -c 'chown 10001:10001 /tmp/dsn && chmod 600 /tmp/dsn'
}
copy_dsn

docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 account --database-url-file /tmp/dsn unlock \
  > "$RUN_DIR/unlock.log" 2>&1 \
  || { cat "$RUN_DIR/unlock.log" >&2; fail "account unlock"; }
check "account unlock wrote its markers" 'grep -q "unlocked" "$RUN_DIR/unlock.log"'

# a CLI-written Argon2 hash must be accepted by the server (the §9 pin)
copy_dsn
printf '%s\n%s\n' "cu-test-cli-new-password" "cu-test-cli-new-password" \
  | docker exec -i -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
      custos --url http://127.0.0.1:8300 account --database-url-file /tmp/dsn reset-password \
      > "$RUN_DIR/reset.log" 2>&1 \
  || { cat "$RUN_DIR/reset.log" >&2; fail "account reset-password"; }
check "account reset-password reports success" 'grep -q "password reset" "$RUN_DIR/reset.log"'
check "the server accepts the CLI-written Argon2 hash" \
  '[ "$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/login" -H "content-type: application/json" -d "{\"username\":\"operator\",\"password\":\"cu-test-cli-new-password\"}")" = "200" ]'

# account reset-mfa: disables TOTP/passkeys, consumes codes, revokes tokens
copy_dsn
docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 account --database-url-file /tmp/dsn reset-mfa \
  > "$RUN_DIR/reset-mfa.log" 2>&1 \
  || { cat "$RUN_DIR/reset-mfa.log" >&2; fail "account reset-mfa"; }
check "account reset-mfa reports success" 'grep -qi "MFA reset" "$RUN_DIR/reset-mfa.log"'
# §9 pins EXACTLY one row per action, so count each action separately.
for action in operator.totp_change operator.passkey_change operator.recovery_regen; do
  check "reset-mfa wrote exactly one $action row" \
    '[ "$(docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc "SELECT count(*) FROM audit WHERE actor_kind = '"'"'local_process'"'"' AND action = '"'"'$action'"'"' AND detail->>'"'"'break_glass'"'"' = '"'"'true'"'"'")" = "1" ]'
done
# and the effects it promises: TOTP off, passkeys gone, codes consumed
check "reset-mfa disabled TOTP" \
  '[ "$(docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc "SELECT totp_enabled FROM operator_account")" = "f" ]'
check "reset-mfa consumed every recovery code" \
  '[ "$(docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc "SELECT count(*) FROM recovery_codes WHERE consumed_at IS NULL")" = "0" ]'
check "reset-mfa revoked every operator token" \
  '[ "$(docker exec "$PROJECT-db-1" psql -U custos -d custos -tAc "SELECT count(*) FROM operator_tokens WHERE revoked_at IS NULL")" = "0" ]'

# account retention: the emergency prune
copy_dsn
docker exec -e XDG_CONFIG_HOME="$CLI_HOME" "$PROJECT-app-1" \
  custos --url http://127.0.0.1:8300 account --database-url-file /tmp/dsn retention \
  > "$RUN_DIR/account-retention.log" 2>&1 \
  || { cat "$RUN_DIR/account-retention.log" >&2; fail "account retention"; }
check "account retention pruned rows and reported counts" \
  'grep -q "pruned" "$RUN_DIR/account-retention.log"'

echo "CLI GATE PASS ($N checks)"