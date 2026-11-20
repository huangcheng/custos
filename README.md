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
`retention`, and minting/revoking keys or tokens. Reveal, history-reveal,
admin env, rekey, and restore accept an `allow_sensitive` token instead.

## Quick start

```bash
# 1. create the secrets the app needs (all 0600)
mkdir -p ./secrets
openssl rand 32 | basenc --base64url -w0 | tr -d '=' \
  | sed 's/^/k1:/' > ./secrets/keyring
openssl rand 32 | basenc --base64url -w0 | tr -d '=' > ./secrets/pepper
printf 'postgresql+asyncpg://custos:%s@db:5432/custos\n' "$DB_PASSWORD" \
  > ./secrets/database-url
chmod 600 ./secrets/*

# 2. start it (see deploy/docker-compose.yml for every variable)
CUSTOS_SECRETS_DIR=./secrets docker compose -f deploy/docker-compose.yml up -d

# 3. read the one-shot setup code and finish setup in the console
docker compose -f deploy/docker-compose.yml exec app cat /var/lib/custos/setup-code
```

Then open the console, paste the setup code, choose a password, and enable
TOTP. From there: **Keys → Mint** produces the first agent key — the token is
shown once.

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

The image ships a `custos` binary for scripting and break-glass:

```bash
custos login                     # password + TOTP, or the device hand-off
custos item set svc --fields-file ./fields.json
custos item get svc              # secrets masked
custos env svc                   # export NAME='value', eval-safe
custos key mint --label ci --mode read --scope 'stock-*'
custos audit --action key.mint
custos account unlock            # break-glass: direct database, host shell = authz
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
