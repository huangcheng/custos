# Custos

A self-hosted credential vault for AI agents. One operator stores named,
multi-field credentials; scoped agent keys read exactly what they are allowed
to read, and every access is audited.

> **Custos** — the Roman keeper of the keys.

## What it does

- **Items** are named records with typed fields (`secret` fields are encrypted
  at rest, `plain` fields are metadata). Items support soft-delete, restore,
  overwrite history, and a field-level `secret` policy.
- **Agent keys** (`cu-…`) carry a mode (`read` or `read-write`) and fnmatch
  scopes. An out-of-scope name is indistinguishable from a missing one.
- **Operator tokens** (`co-…`) are for the CLI: bounded-lifetime, revocable,
  and optionally allowed to perform sensitive reads.
- **The admin plane** adds reveal, history, key/token management, rekey,
  retention, and the audit log — behind an operator session with step-up.

Every write is audited, every failure is ledgered, and secrets never reach a
log, an audit row, or an error message.

## Two planes

| | Authenticated by | Can do |
|---|---|---|
| **Agent plane** (`/api/items`, `/api/search`, `/mcp`) | agent key `cu-…` bearer | read/write items within scope; never admin operations |
| **Admin plane** (`/api/admin/…`) | operator session + CSRF, or `co-…` bearer | everything, gated per route (see below) |

Some admin routes are **session + step-up only** and refuse any token with
`403 session_required` before looking at state: `purge`, `force-drop`,
`retention`, minting/revoking keys or tokens, and re-revealing a minted
key/token. Item reveal, history-reveal, admin env, rekey, and restore accept
an `allow_sensitive` token instead.

## Quick start

Custos needs four things before it will start: a database password, a keyring,
a pepper, and the four deployment variables the compose file requires. This
block is the whole of it — copy it, edit the two `<…>` values, run it.

```bash
# 1. secrets (0600 files in a 0700 directory)
mkdir -p -m 0700 ./secrets
# base64url, no padding. `basenc` is GNU coreutils; the python fallback works
# everywhere else (macOS, minimal images).
gen_key() {
  if command -v basenc >/dev/null 2>&1; then
    openssl rand 32 | basenc --base64url -w0 | tr -d '='
  else
    python3 -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))'
  fi
}
printf 'k1:%s\n' "$(gen_key)" > ./secrets/keyring
gen_key > ./secrets/pepper
chmod 600 ./secrets/keyring ./secrets/pepper

# 2. the deployment variables (put these in a file you gitignore, or export them)
export CUSTOS_DB_PASSWORD='<a URL-safe random string, e.g. from gen_key>'
export CUSTOS_SECRETS_DIR="$PWD/secrets"
export CUSTOS_TRUSTED_PROXIES='127.0.0.1/32'          # your reverse proxy's CIDR
export CUSTOS_ALLOWED_ORIGINS='https://vault.example'  # the browser origin
export CUSTOS_WEBAUTHN_RP_ID='vault.example'          # bare host of that origin
printf 'postgresql+asyncpg://custos:%s@db:5432/custos\n' "$CUSTOS_DB_PASSWORD" \
  > ./secrets/database-url
chmod 600 ./secrets/database-url

# 3. start it
docker compose -f deploy/docker-compose.yml up -d

# 4. the one-shot setup code, then finish setup in the console
docker compose -f deploy/docker-compose.yml exec app cat /var/lib/custos/setup-code
```

The console is published on loopback (`http://127.0.0.1:8300`) by default. For a
real deployment put your own TLS-terminating proxy in front and point
`CUSTOS_ALLOWED_ORIGINS` / `CUSTOS_WEBAUTHN_RP_ID` at its public origin — see
[`docs/operations.md`](docs/operations.md).

Then: paste the setup code, choose a password, enable TOTP, and **Keys → Mint**
produces the first agent key (re-revealable later with a step-up).

### Passkeys are optional

`CUSTOS_WEBAUTHN_RP_ID` and `CUSTOS_ALLOWED_ORIGINS` are a both-or-neither pair.
If you do not want passkeys, unset *both* and the endpoints return 404 with
`auth/status` reporting `passkey_available: false`. The compose file requires
them because its default deployment enables passkeys.

### Checking the secrets by hand

The app refuses to start on a malformed keyring or an all-zero pepper. To check
before starting:

```bash
python3 - <<'PY'
import base64, pathlib
for entry in pathlib.Path("secrets/keyring").read_text().strip().split(","):
    version, _, value = entry.partition(":")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    print(version, len(raw), "bytes", "OK" if len(raw) == 32 else "BAD")
PY
```

## Configuration

The full table lives in `.env.example`. The rules that bite:

- Every `CUSTOS_*` variable treats an empty string as unset; boolean flags
  accept exactly `1`.
- Secret material has an env form and a preferred **file** form
  (`_FILE` suffixes); setting both is a startup failure, and a group- or
  other-readable file is refused.
- `CUSTOS_PUBLIC_BIND=1` requires `CUSTOS_TRUSTED_PROXIES`.
- `CUSTOS_RETENTION_DAYS` has a floor of 7.

## The CLI

The image ships a `custos` binary at `/app/bin/custos` for scripting and
break-glass. It is not installed on the host, so run it through the container
(or copy it out — it is a self-contained binary):

```bash
C="docker compose -f deploy/docker-compose.yml exec -T app /app/bin/custos"
export CUSTOS_URL=http://127.0.0.1:8300   # or pass --url to every command

$C login                         # password + TOTP, or the device hand-off
$C item set svc --fields-file ./fields.json   # values never in argv
$C item get svc                  # secrets masked
$C env svc                       # export NAME='value', eval-safe
$C key mint --label ci --mode read --scope 'stock-*'
$C audit --action key.mint
$C account unlock                # break-glass: direct DB, host shell = authz
```

`CUSTOS_OPERATOR_TOKEN` is the non-interactive path. Secret *values* are never
accepted as command-line flags — `item set` reads them from stdin or a 0600
file, and `account reset-password` prompts.

## The MCP wrapper

```bash
CUSTOS_URL=https://vault.example CUSTOS_AGENT_KEY=cu-… npx custos-mcp
```

Exposes exactly the seven agent tools (list, search, get, env, put, patch,
delete) — never the admin surface. See `mcp/README.md`.

## Security posture, in five lines

1. AES-256-GCM at rest, one keyring, per-row AAD; the operator password is
   Argon2id, and TOTP/passkey/recovery codes are additional factors.
2. Operator sessions are HttpOnly cookies with CSRF and an Origin check;
   step-up re-authentication gates every sensitive action.
3. Agent keys are HMAC-verified with a uniform 401 on every failure path.
4. Secrets appear in no log, audit row, error message, or telemetry attribute.
5. The public surface is one process behind your own TLS-terminating reverse
   proxy; there is no CORS and no service worker.

## Operations

Backup, keyring rotation, restore, pepper rotation, break-glass ordering, and
the retention cadence are in [`docs/operations.md`](docs/operations.md). Read
the restore section before you need it.

## Design

The design of record is
[`docs/superpowers/specs/2026-11-17-custos-design.md`](docs/superpowers/specs/2026-11-17-custos-design.md);
implementation plans are alongside it in `docs/superpowers/plans/`.

## Testing

```bash
uv run python -m pytest -q          # unit + integration against a throwaway postgres
cd cli && cargo test                # the CLI
bash scripts/e2e.sh                 # API + real MCP path
bash scripts/e2e_startup.sh         # the startup-refusal matrix
bash scripts/e2e_console.sh         # real browser, needs CUSTOS_BROWSER_CMD
bash scripts/e2e_cli.sh             # the shipped binary end to end
```
