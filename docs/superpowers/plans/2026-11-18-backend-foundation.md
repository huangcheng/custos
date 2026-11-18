# Custos Backend Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Custos service foundation: config validation, crypto core, full schema, agent-key auth, the agent-plane REST API, and the remote MCP mount — provable end-to-end with `scripts/e2e.sh` (API half).

**Architecture:** One FastAPI app (`custos/` package at repo root) over PostgreSQL via SQLAlchemy 2 async ORM + Alembic. Pure modules (crypto, keyring, scopes, escaping) are unit-tested without a DB; routes go through a session layer. Patterns are copied from the sibling project's `vault.py`/`keys.py` shapes (read-only reference, no imports).

**Tech Stack:** Python ≥3.12, uv, FastAPI, SQLAlchemy 2 (asyncpg), Alembic, cryptography, argon2-cffi, mcp (FastMCP), OpenTelemetry; pytest + httpx for tests; docker compose (postgres:16-alpine) for E2E.

**Spec:** `docs/superpowers/specs/2026-11-17-custos-design.md` (rev 36) — the binding authority. Section references below (§N) point into it.

**Plan series:** this is plan 1 of 4. Later plans: (2) operator auth + admin plane, (3) console + MCP stdio wrapper + full E2E gates, (4) Rust CLI + deploy. Do not implement their scope here.

## Global Constraints

- All DB access through the ORM/session layer; no raw SQL in route code (Alembic excepted).
- Never commit or echo secrets; fixtures use obviously fake values (`cu-test.…`, `k1:` + 32 zero bytes).
- Secret values/full tokens never in logs, audit rows, error messages, telemetry (§11).
- No personal/environment-specific data in any artifact; relative paths only.
- Every commit gated: `ocr review --audience agent`, read findings, resolve or record false-positive reason in commit body. Review intermediates to `/tmp` only.
- English everywhere in artifacts. One logical change per commit.
- Dependencies pinned to the design's list; anything extra needs a stated reason.
- Error envelope `{"code", "message"}` with §6's status table; messages never echo submitted values.
- Item name grammar `^[a-z0-9][a-z0-9._-]{0,199}$`; field name grammar `^[A-Z][A-Z0-9_]{0,63}$`.
- Check order on agent plane: scope → mode → existence/uniqueness; out-of-scope = 404 identical to missing.
- After each task: `uv run ruff check .` and `uv run mypy custos` (or pyright) clean for touched files.

## Review Focus

- Concurrent writes to one item (two PUTs, or PUT vs retype PATCH): row lock + If-Match must serialize; no lost history append, no CHECK violation from interleaved delete/insert.
- Adversarial string inputs: names/values with unicode, quotes, NUL, invalid UTF-8, 16 KiB+1 values — caps measured as pinned (raw UTF-8 for value/notes, canonical escaped JSON for item), 413 vs 422 exactly per §4/§6.
- Scope patterns with fnmatch metacharacters (`[`, `?`, `*`) against names containing dots/dashes: fail-closed, no existence oracle, empty scopes read nothing.
- Soft-deleted names: every verb in §4's matrix incl. upsert-create 409 and collection exclusion; read-only key on in-scope deleted write gets 403 (mode before existence).
- Auth timing/shape uniformity: unknown key_id, bad secret, revoked, expired all return the identical 401 body and run the dummy digest; one `auth_events` row per verified failure, none for 429-gated requests.

---

### Task 1: Project skeleton, config loader, bind/TLS contract

**Files:**
- Create: `pyproject.toml`, `custos/__init__.py`, `custos/config.py`, `custos/errors.py`, `custos/app.py`, `tests/test_config.py`, `.env.example`
- Modify: `.gitignore` (only if a new artifact class appears)

**Interfaces:**
- Produces: `Settings` dataclass from `load_settings(env: Mapping[str, str]) -> Settings` raising `ConfigError(msg)`; fields `bind: str`, `port: int`, `public_bind: bool`, `insecure_dev: bool`, `database_url: str`, `data_dir: Path`, `retention_days: int`, `skip_migrate: bool`, `allow_missing_key_version: bool`, `trusted_proxies: list[ipaddress.IPv4Network | IPv6Network]`, `keyring_raw: str`, `pepper_raw: bytes`. `AppError(code: str, status: int, message: str)` + FastAPI exception handler in `errors.py`. `create_app(settings: Settings) -> FastAPI` in `app.py` (health route `GET /healthz` only for now).

- [ ] **Step 1: Write failing tests** in `tests/test_config.py`:
  - `test_empty_env_is_unset`: `CUSTOS_PORT=""` behaves as default 8300; boolean flag `"0"`/`"yes"` → `ConfigError`; `"1"` accepted (§10 env conventions).
  - `test_bind_host_port_rejected`: `CUSTOS_BIND="127.0.0.1:8300"` → `ConfigError`.
  - `test_non_loopback_requires_public_bind`: `CUSTOS_BIND="0.0.0.0"` alone → `ConfigError`; with `CUSTOS_PUBLIC_BIND=1` and `CUSTOS_TRUSTED_PROXIES="10.0.0.0/8"` → ok; public bind without proxies → `ConfigError`.
  - `test_dev_flag_loopback_only`: `CUSTOS_INSECURE_DEV=1` + non-loopback → `ConfigError` even with public bind; both flags → `ConfigError`; dev implies insecure cookie (assert `settings.insecure_cookie`).
  - `test_loopback_classifier`: `127.0.0.1`, `127.5.5.5`, `::1` loopback; `localhost` resolved via `socket.getaddrinfo` mocked to return only loopback → ok, mixed → `ConfigError` (§3 classifier).
  - `test_trusted_proxies_validation`: malformed CIDR → error; `0.0.0.0/0` → error; `127.0.0.1/32` and bare `127.0.0.1` normalized (`strict=False`).
  - `test_retention_minimum`: `CUSTOS_RETENTION_DAYS=6` → error; default 365.
  - `test_insecure_cookie_requires_dev`: `CUSTOS_INSECURE_COOKIE=1` without dev+loopback → error.
- [ ] **Step 2: Run** `uv run pytest tests/test_config.py -x -q` — expect collection error/FAIL (module missing).
- [ ] **Step 3: Implement** `pyproject.toml` (deps: fastapi, uvicorn, sqlalchemy[asyncio], asyncpg, alembic, cryptography, argon2-cffi, pyotp, mcp, httpx, opentelemetry-api/sdk/exporter-otlp-proto-http; dev: pytest, pytest-asyncio, ruff, mypy; `requires-python = ">=3.12"`), `config.py` per §3/§10 (file forms `*_FILE` read with 0600/0400 mode check, both-set → error; keyring/pepper parsing lands in Task 2 — config only carries raw strings/bytes and enforces presence), `errors.py` with the §6 code→status map as a constant `ERROR_STATUS: dict[str, int]`, `app.py` with `create_app` wiring the error handler + `GET /healthz`.
- [ ] **Step 4: Run** `uv run pytest tests/test_config.py -q` — expect PASS; `uv run ruff check .` clean.
- [ ] **Step 5: ocr gate + commit** `feat: add project skeleton, config validation, and bind/TLS contract`.

### Task 2: Crypto core — keyring, vault, pepper digests, operator seal

**Files:**
- Create: `custos/crypto.py`, `tests/test_crypto.py`
- Modify: `custos/config.py` (parse keyring/pepper through crypto module validators)

**Interfaces:**
- Produces: `parse_keyring(raw: str) -> dict[int, bytes]` (raises `CryptoError`); `Vault(keys: dict[int, bytes])` with `.current_version: int`, `.seal(domain: str, row_id: str, plaintext: bytes) -> tuple[bytes, int]` (blob, version), `.open(domain: str, row_id: str, blob: bytes, version: int) -> bytes` (raises `UnreadableError` on missing version OR `InvalidTag`); `parse_pepper(raw: str) -> bytes`; `credential_digest(pepper: bytes, presented_secret: str) -> bytes` (HMAC-SHA256 over UTF-8 of the presented text); `operator_seal_key(key: bytes) -> bytes` (HKDF-SHA256, empty salt, info `custos-operator-seal|v1`).
- AAD formats frozen (§4): `field:{field_id}|{version}`, `fieldh:{history_id}|{version}`, `operator:totp|{version}` — `seal`/`open` take the domain prefix (`"field"`, `"fieldh"`, `"operator:totp"`) and build `f"{domain}:{row_id}|{version}"` except operator domain which is `f"operator:totp|{version}"` (row_id ignored) — implement as exact-string builders `field_aad`, `history_aad`, `operator_aad` to keep the freeze auditable.

- [ ] **Step 1: Write failing tests** `tests/test_crypto.py` (fixtures: `k1:` + b64url(32 zero bytes), `k2:` + b64url(32 0x01 bytes)):
  - keyring: numeric ordering `k2,k10` → current 10; duplicate version → error; `+`/`/`/`=` chars → error (RFC 4648 §5 only); wrong decoded length → error; `k0`/`k-1`/`kabc` → error; comment lines/whitespace tolerated in file form.
  - seal/open round-trip per domain; nonce uniqueness across 100 concurrent seals (set of first-12-bytes has len 100); blob layout len = 12 + len(pt) + 16.
  - cross-domain rejection: field blob opened as history → `UnreadableError`; moved row id → `UnreadableError`; wrong version → `UnreadableError`; missing version → `UnreadableError` (same exception type for corruption and absence, §4).
  - pepper: <32 bytes → error; all-zero → error; valid round-trip; `credential_digest` equals `hmac.new(pepper, secret_text.encode(), sha256)` for a fake `cu-test` secret; base64url text used as-is, not decoded.
  - operator seal: derived key ≠ raw key; deterministic per version; seal/open through operator AAD.
- [ ] **Step 2: Run** `uv run pytest tests/test_crypto.py -x -q` — expect FAIL.
- [ ] **Step 3: Implement** `custos/crypto.py` following the sibling `vault.py` structure but with base64url validation, numeric max-wins, the three AAD builders, CSPRNG nonce per seal, and `UnreadableError` unifying missing-version and tag failure. `hmac.compare_digest` is the only presented-vs-stored comparison helper: export `digests_equal(a: bytes, b: bytes) -> bool`.
- [ ] **Step 4: Run** tests — PASS; wire `config.py` to call `parse_keyring`/`parse_pepper` (both-set env+file → `ConfigError`); rerun Task 1 tests.
- [ ] **Step 5: ocr gate + commit** `feat: add crypto core (keyring, AES-GCM domains, pepper digests)`.

### Task 3: Database models + initial Alembic migration

**Files:**
- Create: `custos/db/__init__.py`, `custos/db/models.py`, `custos/db/session.py`, `alembic.ini`, `alembic/env.py`, `alembic/versions/0001_initial.py`, `tests/test_models.py`, `tests/conftest.py`
- Modify: `custos/app.py` (lifespan: engine, optional `alembic upgrade head` unless `skip_migrate`; schema-version assertion when skipped, §10)

**Interfaces:**
- Produces: SQLAlchemy models for every §4 schema table: `Item`, `Field`, `FieldHistory`, `AgentKey`, `OperatorToken`, `OperatorAccount`, `OperatorSession`, `StepUpToken`, `DeviceCode`, `LockoutSuppression`, `PasskeyCredential`, `RecoveryCode`, `AuthEvent`, `AuditRow`, `WebAuthnChallenge`. `async_session(settings) -> async_sessionmaker`; `get_session` FastAPI dependency.
- Column pins (§4): `fields` CHECK exactly-one-of value/ciphertext matching `secret`; unique `(item_id, name)`; `field_history` plain uuid `field_id`/`item_id` **no FK cascade**, index `(item_id, name)`; `operator_account.id` int pk CHECK `id = 1`, four TOTP counters `NOT NULL DEFAULT 0` (`totp_last_step_login`, `_stepup`, `_confirm`); `operator_sessions.idle_ttl_seconds` default 43200 (0 = disabled), `revoked_at`; `audit.actor_id` text nullable, `actor_label` text; `auth_events.ip` + `peer_ip`; `step_up_tokens` exactly-one-non-null FK CHECK, `kind` enum `single`/`rekey_run`; `device_codes` with `approved_at`, `exchange_attempts` int default 0, `client_ip`, `user_agent`.

- [ ] **Step 1: Write failing tests** `tests/test_models.py` against a throwaway postgres (conftest fixture `pg_db`: starts `postgres:16-alpine` via docker on a random port with fake password, creates schema via alembic, yields DSN; skip with clear message if docker absent):
  - `test_fields_check`: insert secret row with plaintext value → IntegrityError; plain row with ciphertext → IntegrityError; correct pairs ok.
  - `test_history_survives_delete`: delete field row + item row → history rows still present (no cascade).
  - `test_operator_account_single_row`: second insert (id=2) → IntegrityError.
  - `test_step_up_exactly_one_principal`: both FKs set → IntegrityError; both null → IntegrityError.
  - `test_session_step_up_no_cascade_on_revoke`: set `revoked_at` → session row still exists.
- [ ] **Step 2: Run** — FAIL (models missing).
- [ ] **Step 3: Implement** models + migration (single hand-written initial revision covering all tables/indexes/CHECKs; enums as PG enums or text+CHECK, pick text+CHECK for migration simplicity), session layer, app lifespan with migrate/skip+assert.
- [ ] **Step 4: Run** — PASS. `uv run alembic upgrade head` against the fixture DB works from CLI too.
- [ ] **Step 5: ocr gate + commit** `feat: add schema models and initial migration`.

### Task 4: Audit + auth-event ledger layer

**Files:**
- Create: `custos/audit.py`, `tests/test_audit.py`
- Modify: `custos/db/session.py` (independent-transaction helper)

**Interfaces:**
- Produces: `async record_audit(session_maker, *, actor_kind: str, actor_id: str | None, actor_label: str, action: str, item_name: str | None, ok: bool, detail: dict) -> None` and `async record_auth_event(session_maker, *, kind: str, ok: bool, ip: str, peer_ip: str) -> None` — each opens its **own session/transaction and commits before returning** (§4 independent commit); on ledger-write failure raises `LedgerError` (caller fails the request closed, 503). `ACTION_ENUM: frozenset[str]` and `DETAIL_KEYS: frozenset[str]` validate inputs (closed sets per §4); a `detail` containing a key outside the set or a value longer than 256 chars raises `ValueError` (defense against accidental value leakage).
- Global ledger budget: `LedgerBudget` class — 600 failure rows/min process-wide; `.allow() -> bool`; when exhausted, failure rows are skipped and an in-process `FailureCounter` (sliding 15-min window per ip/account) is incremented instead (lockout fallback, §5 rate limits). Success rows always written.

- [ ] **Step 1: Write failing tests**: closed-enum rejection (`action="bogus"` → ValueError); detail key whitelist; independent commit (raise inside caller's transaction after `record_audit` → audit row still present); budget: 601st failure in a minute not ledgered, counter incremented, success row still written.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** per interfaces; no secret material may pass through — `record_audit` never accepts a `value` parameter at all.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add independent-commit audit and auth-event ledger`.

### Task 5: Agent-key auth, scopes, rate limiting

**Files:**
- Create: `custos/keys.py`, `custos/scopes.py`, `custos/ratelimit.py`, `custos/auth_agent.py`, `tests/test_keys.py`, `tests/test_scopes.py`, `tests/test_ratelimit.py`
- Modify: `custos/app.py` (middleware wiring)

**Interfaces:**
- Produces: `mint_agent_key(pepper) -> tuple[str, AgentKeyDraft]` (full token `cu-<12 hex>.<43 b64url>` returned once; draft carries `key_id`, `digest`, never the secret); `verify_agent_key(session, pepper, presented: str) -> AgentKey` raising `AgentAuthError` (single shape); `scope_allows(scopes: list[str], name: str) -> bool` using `fnmatch.fnmatchcase`; `RateLimiter` (in-process): agent bucket 120 req/min/key + 8 concurrent, failed-auth 30/min/IP → 429, admin/unauth buckets stubbed for plan 2. FastAPI dependency `agent_principal` resolving bearer → `AgentKey` or the uniform 401.
- Verify path (§5): parse token shape → look up `key_id` → compute digest → **single `digests_equal`**; unknown id / revoked / expired paths compare against a fixed `_DUMMY_DIGEST`; DB-lookup timing residual accepted. Every verified failure → one `agent_auth` auth-event + `auth.failure` audit row (actor `anonymous`, ip in detail); 429-gated requests produce neither.

- [ ] **Step 1: Write failing tests**:
  - keys: minted token matches `^cu-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$`; digest = HMAC(pepper, presented secret text); verify ok; unknown id / wrong secret / revoked / expired each raise the **same** `AgentAuthError` with identical message; code-review assertion: verify function contains exactly one `digests_equal` call reachable on all paths (AST check in test).
  - scopes: empty list → False for any name; `*` matches dotted names; `stock-*` matches `stock-a.b` not `stocks-a`; `[abc]` literal class works; case-sensitive (`ALIYUN` name invalid at write, pattern `Aliyun` doesn't match `aliyun`).
  - ratelimit: 121st request in window → 429 with Retry-After; 9th concurrent → 429; failed-auth 31st/min/IP → 429 and **no ledger row** (spy).
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** modules + dependency; uniform 401 body `{"code": "unauthorized", "message": "authentication failed"}`.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add agent-key auth, fnmatch scopes, and rate limiting`.

### Task 6: Item write engine (history, caps, soft-delete, concurrency)

**Files:**
- Create: `custos/items.py`, `custos/limits.py`, `tests/test_items.py`, `tests/test_limits.py`

**Interfaces:**
- Produces: pure `canonical_item_bytes(name: str, notes: str, fields: list[FieldView]) -> bytes` (sorted keys, fields sorted by name, `ensure_ascii`, no whitespace, `""` notes counted); `check_caps(...)` raising `AppError("payload_too_large", 413)`; `validate_write_body(...)` implementing §6's single precedence rule (keep/no-op/422 matrix), duplicate-pair rule, pre/post downgrade classification table returning `DowngradeError` or the op list.
- Async engine: `create_item`, `put_item(name, body, if_match: str | None, upsert: bool)`, `patch_item`, `soft_delete`, each taking `(session, principal, ...)`, all under `SELECT … FOR UPDATE` on the item row; history append only on actual value change/removal, re-sealed under history AAD at newest version; 20-per-`(item_id, name)` eviction (detail `evicted: n` + ids); global 100 000-row ceiling → 429 `history_budget_exceeded`; revision bump + quoted-ETag If-Match compare under the lock; whole write one transaction.
- Response shaping: `agent_item_response` (full values for supplied fields, `{name, secret: true, kept: true}` for kept secrets), `masked_item_response` for plan 2.

- [ ] **Step 1: Write failing tests** (DB fixture from Task 3):
  - limits: 16 KiB value passes / +1 byte → 413; 4 KiB notes; 33 fields → 413; canonical measurement on post-merge PATCH; no-op write passes; `""` notes counted; unicode escaping counted (`ensure_ascii`).
  - write body: POST without name → 422; PUT name mismatch → 422; PATCH keep-secret round-trip `{name, secret: true}` keeps value; omission on plain/new/POST → 422; neither-secret-nor-value no-op; duplicate names outside sanctioned pair → 422; single-entry flag flip → 422; pair `secret:false` on existing secret → `secret_downgrade_denied` 403 atomically (nothing applied); `plain→secret` pair allowed, history row keeps old flag+value and opens under history AAD.
  - engine: PUT drops absent fields with history; identical resend writes no history; 21 distinct writes leave exactly 20 snapshots (oldest evicted, ids in audit detail); If-Match mismatch → 409 with current revision; malformed If-Match → 422; concurrent PUTs serialized (asyncio.gather, both succeed, revisions n+1/n+2, history complete); soft-delete verb matrix incl. upsert-create 409, read-only in-scope deleted write 403; degraded mode: corrupt one blob → get 500 `key_unavailable`, masked metadata fine, writes fail, soft-delete ok, force-drop removes unreadable field+history rows only (readable untouched), item writable after.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** `limits.py` (pure) then `items.py` (engine) per interfaces; delete-flush-insert for retype pairs.
- [ ] **Step 4: Run** — PASS (full suite).
- [ ] **Step 5: ocr gate + commit** `feat: add item write engine with history, caps, and concurrency`.

### Task 7: Agent-plane routes + env export + search

**Files:**
- Create: `custos/routes_agent.py`, `custos/envexport.py`, `tests/test_routes_agent.py`, `tests/test_envexport.py`
- Modify: `custos/app.py` (router include, no-store middleware for `/api/*`, access-log query redaction)

**Interfaces:**
- Produces: the §6 agent table exactly: `GET /api/items` (metadata, notes truncated 256, cursor pages 50/100), `GET /api/items/{name}`, `GET /api/items/{name}/env`, `POST /api/items`, `PUT /api/items/{name}` (+`?upsert=1`, `created: bool`, If-Match+upsert-on-missing → 409), `PATCH`, `DELETE` (204), `GET /api/search?q=` (names/plain field names/notes, case-insensitive, never values; audit detail = result count only).
- `env_lines(fields: list[FieldView], allow_hazardous: bool) -> str`: POSIX single-quote escaping (`'` → `'\''`), NUL rejected at write (Task 6 validation), hazardous names commented out unconditionally on this plane (§9 deny-set + `LD_*`/`DYLD_*`/`*_OPT`/`*_OPTIONS`/`PYTHON*` patterns); 4 MiB output bound → 413.
- Pagination cursors: `mint_cursor(payload: dict, pepper) -> str` / `read_cursor(token, pepper, endpoint, principal_id) -> dict` (HMAC tag, 15-min TTL, 422 on foreign/expired).

- [ ] **Step 1: Write failing tests** (httpx ASGI client + DB fixture): full verb matrix through HTTP incl. scope 404 indistinguishability (byte-identical bodies for out-of-scope vs missing), read-only 403, create/upsert flows, ETag/If-Match round-trip, list/search exclude soft-deleted and never contain values, notes truncation, `no-store` + `Vary` headers on every `/api/*` response, env escaping adversarial corpus (`'; cmd; echo '`, newline, `$(touch pwn)`) round-trips through a real `bash -c 'eval …'` subprocess without execution, hazardous `PATH` line commented, search audit row has count not `q`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** routes (thin: parse → engine → shape → audit), envexport, cursors, middleware.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add agent-plane REST API with env export and search`.

### Task 8: Remote MCP mount + telemetry + E2E gate (API half)

**Files:**
- Create: `custos/mcp_surface.py`, `custos/telemetry.py`, `scripts/e2e.sh`, `deploy/docker-compose.yml`, `deploy/compose.e2e.yml`, `tests/test_mcp_surface.py`
- Modify: `custos/app.py` (mount `/mcp`, OTel install)

**Interfaces:**
- Produces: FastMCP mounted at `/mcp` (Streamable HTTP), bearer verified **per request** via the same `agent_principal` dependency; tools `custos_list_items`, `custos_get_item`, `custos_search`, `custos_put_item` (upsert, `if_match` arg), `custos_patch_item` (`if_match`), `custos_delete_item`, `custos_env` — each a thin call into the same engine functions as REST (no duplicated logic); 401 terminates the MCP session; SSE stream exempt from the 8-slot cap; tool results ≤1 MiB (env 4 MiB).
- `telemetry.install(app, env)`: TracerProvider always; OTLP export only when standard `OTEL_*` env set; bad config never blocks startup; spans carry actor/action/item-name only.
- `scripts/e2e.sh`: throwaway compose stack (app + postgres:16-alpine, fake keyring/pepper env), waits for health, then runs the §11 assertion set for this plan's scope: setup deferred (plan 2) — keys minted via a test-only direct-DB seed helper `scripts/e2e_seed.py` (documented as E2E scaffolding, not an API); create via REST, read via **remote /mcp** (real MCP client from the `mcp` package), out-of-scope read+write 404 identical, read-only 403, revoke bites next MCP request + session drop, soft-delete/restore-via-engine, history survives overwrite, If-Match conflict, hostile env eval safety, upsert via MCP, audit rows for writes/auth, 413 caps, uniform-401 shapes; teardown traps. Exit nonzero on any failure; log to `/tmp/custos-e2e/`.

- [ ] **Step 1: Write failing test** `tests/test_mcp_surface.py`: initialize + tool call over ASGI transport with valid key succeeds; revoked key → 401 and session unusable; `custos_put_item` creates then replaces (audit `create` then `put`).
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** MCP surface, telemetry, compose files (generic shape, no real hosts), e2e script.
- [ ] **Step 4: Run** unit tests PASS, then `bash scripts/e2e.sh` — expect full PASS; read the log tail.
- [ ] **Step 5: ocr gate + commit** `feat: add remote MCP surface, telemetry, and API E2E gate` (commit body references `/tmp/custos-e2e/` run date + result and `scripts/e2e.sh` as the reproducible artifact).

---

## Self-review notes

- Spec coverage for this plan's scope: §3 (bind/CSRF middleware/no-store/log redaction — Tasks 1,7), §4 (crypto/schema/history/caps/degraded — Tasks 2,3,6), §5 agent keys/scopes/rate limits (Task 5), §6 agent plane + write body + errors (Tasks 6,7), §7 remote MCP (Task 8), §10 config (Task 1), §11 unit+E2E subset (all tasks). Operator auth (§5 rest), admin plane (§6 rest), console (§8), CLI (§9), stdio wrapper (§7 local) are explicitly plans 2–4.
- Type consistency: `AgentKey` model (Task 3) consumed by Task 5/6/7; `FieldView` = the model row typed alias defined in Task 6 and used by 7/8; `AppError` codes match `ERROR_STATUS` (Task 1).
- The E2E seed helper is scaffolding for the pre-operator-auth phase; plan 2 replaces it with real setup+key-mint flow and extends the same script.