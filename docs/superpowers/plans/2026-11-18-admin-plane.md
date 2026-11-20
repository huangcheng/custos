# Admin Plane + Maintenance Ops Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the operator admin plane (`/api/admin/*`): dual auth (session or `co-` token), the §6 authority matrix, masked item management, reveal/env/history, key/token mint+revoke, rekey/verify with run tokens, retention, audit read — and replace the E2E key-seeding scaffolding with the real mint flow.

**Architecture:** One admin auth layer (`custos/admin/auth.py`) resolves session-or-token principals and enforces the session-only / sensitive gate matrix; thin routers (`routes_admin*.py`) delegate to engine functions (`admin_items.py`, `rekey.py`, `retention.py`) that reuse the plan-1 write engine and crypto. Run tokens extend the existing `step_up_tokens` table (`kind: rekey_run`); rekey/verify cursors are a new pepper-HMAC format without TTL.

**Tech Stack:** Python ≥3.12, FastAPI, SQLAlchemy 2 async (PostgreSQL), existing `custos.crypto.Vault` (AES-256-GCM), pytest + throwaway postgres:16 (session fixture `pg_db`).

**Spec:** `docs/superpowers/specs/2026-11-17-custos-design.md` (rev 36) — §§4 (crypto/rekey/degraded), 5 (tokens/step-up/limits), 6 (admin routes/errors), 11 (invariants). Read it before changing behavior.

## Global Constraints

- Authority matrix (§6, single source of truth): `purge`/`force-drop`/`retention` + key/token mint/revoke = **session + step-up only** — any bearer token → 403 `session_required` **before any state check**, audited `auth.failure`. `reveal`/`history-reveal`/`admin env`/`rekey` (all batches)/`rekey verify`/`restore`/`secret→plain downgrade` = session+step-up **or** `allow_sensitive` token. Everything else = session or any `co-` token.
- Error precedence (§4): authentication → authorization (scope/mode/session/step-up) → state/conflict → value materialization.
- Admin write responses are **always masked**: plain values visible, secret fields `{name, secret: true}` — never a secret value, never `kept` echoes of prior values (§11).
- Operator tokens: `co-<12hex>.<43 base64url>`, separate table, HMAC(pepper, secret-text-as-presented) digest; `expires_at` mandatory, **max 90 days; `allow_sensitive` max 30 days**; revoke = `revoked_at` + `DELETE FROM step_up_tokens WHERE operator_token_id = :id AND consumed_at IS NULL` in the same transaction.
- All admin endpoints: 300 req/min per session-or-token; exceeding → 429 `rate_limited` + `Retry-After`.
- List/search/audit/history cursors: existing `mint_cursor`/`read_cursor` (TTL 15 min, principal+endpoint bound, foreign/expired/tampered → 422 `invalid`). Rekey/verify cursors: new format, **no TTL**, payload `{endpoint, table, last_id, plane}`, HMAC(pepper) tag, mismatch → **401**.
- Step-up/run tokens: 32 random bytes base64url, SHA-256 `nonce_hash` at rest; presenter binding re-checked on every use; `rekey_run` TTL 30 min, extended +30 min per successful batch; one active run per vault → 409 `conflict`.
- Audit: closed action enum + closed `DETAIL_KEYS` (extend only via Task 8/9 additions below); `allow_sensitive` use marked `detail.allow_sensitive: true`; failure rows commit independently; ledger write failure → fail closed.
- Retention: `CUSTOS_RETENTION_DAYS` default 365, **minimum 7 (already startup-enforced)**; never prune the current value or the 20 most recent snapshots per `(item_id, name)`; consumed `recovery_codes` retained.
- ORM only in route/engine code; no raw SQL outside Alembic. No new dependencies. `uv run ruff check .` + `uv run mypy` (strict) clean per task; full suite `uv run python -m pytest -q`.
- Tests: factory fixtures — the **test body owns the app lifespan** (`async with app.router.lifespan_context(app)`); shared session-scoped DB — clear `AuthEvent`/`LockoutSuppression` and delete `StepUpToken`/`WebAuthnChallenge`/`DeviceCode` **before** `OperatorSession`, reset account counters, in teardown. Never real credentials; `cu-test.…` fixtures only.
- Every commit passes `ocr review --audience agent` first; findings fixed or false-positive reason in the commit body. English messages, one logical change per commit.

## Review Focus

1. **Masked-shape leak on any admin write path** (create/put/patch/restore) — a secret value (or a `kept` echo carrying one) appearing in an admin write response is an §11 invariant break. Pinned in Task 3 (all four verbs asserted value-free).
2. **Token reaching a session-only route after passing state checks** — a `co-` token (even `allow_sensitive`) probing purge/force-drop/retention/mint on an absent name must get 403 `session_required`, never 404 — the gate fires before state. Pinned in Task 2 matrix test with nonexistent names.
3. **Run-token/cursor cross-binding** — a rekey cursor presented to verify (or another principal's plane) must 401 even with a valid run token; a revoked token's live run row must be dead. Pinned in Tasks 6/7.
4. **Retention destroying the recent-prior floor** — 25 snapshots of one field, prune at 7 days: exactly the 20 newest survive regardless of age. Pinned in Task 9.
5. **Degraded-mode admin flows** — masked get/list still succeed with `unavailable: true`; restore/purge/force-drop work on unreadable items; reveal/env/write fail 500 `key_unavailable` only after gates pass. Pinned in Tasks 3/4/5.

## File Structure

| File | Responsibility |
|---|---|
| Create `custos/operator_tokens.py` | `co-` token mint/verify (mirrors `keys.py`), expiry-cap validation |
| Create `custos/admin/__init__.py` | package marker |
| Create `custos/admin/auth.py` | `AdminPrincipal`, `require_admin`, `require_session_only`, `require_sensitive`, admin 300/min bucket wiring |
| Create `custos/admin/items.py` | masked get/list/history/reveal/env/restore/purge engines; downgrade pre-gate |
| Create `custos/admin/routes_items.py` | `/api/admin/items*` routes (read + write + lifecycle) |
| Create `custos/admin/routes_keys.py` | `/api/admin/keys`, `/api/admin/tokens` routes |
| Create `custos/rekey.py` | run-token mechanics, scan cursors, batch re-seal, verify sweep, SQL audit |
| Create `custos/admin/routes_maintenance.py` | `/rekey`, `/rekey/audit`, `/rekey/verify`, `/retention`, `/audit` routes |
| Create `custos/retention.py` | pruning engine + counts |
| Modify `custos/items.py` | `include_deleted` reads, `mask` responses, `allow_downgrade`, shared list deleted-flag |
| Modify `custos/routes_agent.py` | `list_via_engine` gains `include_deleted` (default False — agent behavior unchanged) |
| Modify `custos/envexport.py` | `env_lines(fields, allow_hazardous=False)` admin override |
| Modify `custos/operator/stepup.py` | token-principal consumption, `rekey_run` mint/validate helpers |
| Modify `custos/operator/sessions.py` | admin-path purpose deny for `recovery_reset` |
| Modify `custos/ratelimit.py` | `check_admin_request(principal_key)` 300/min |
| Modify `custos/audit.py` | `DETAIL_KEYS` += `unreadable_fields`, `unreadable_history`, `unreadable_operator`, `pruned` (Task 8/9) |
| Modify `custos/app.py` | include the three admin routers |
| Modify `scripts/e2e.sh`; delete `scripts/e2e_seed.py` | real setup/login/step-up/mint flow (Task 10) |
| Tests | `tests/test_operator_tokens.py`, `tests/test_admin_auth.py`, `tests/test_admin_items.py`, `tests/test_admin_writes.py`, `tests/test_admin_lifecycle.py`, `tests/test_admin_keys.py`, `tests/test_rekey.py`, `tests/test_rekey_verify.py`, `tests/test_retention.py`, `tests/test_admin_audit.py` |

**Shared test fixture (Task 2 creates, later tasks import):** `tests/admin_conftest.py` exposes `admin_stack(pg_db)` factory yielding `(client, maker, helpers)` inside the app lifespan, with helpers: `login()` (seeds account `operator` / `cu-test-password-12ch` like `tests/test_login.py`, POSTs `/api/auth/login`, returns csrf), `step_up(client, csrf)` (POST `/api/auth/step-up` with the password, returns token), `mint_co(maker, settings, *, allow_sensitive=False, days=30)` (direct DB mint via Task 1 for tests that need a token without the HTTP flow). Teardown clears the shared tables per Global Constraints.

---

### Task 1: Operator-token credentials (`co-`)

**Files:**
- Create: `custos/operator_tokens.py`
- Test: `tests/test_operator_tokens.py`

**Interfaces:**
- Consumes: `custos.crypto.credential_digest(pepper, text)`, `digests_equal`, `OperatorToken` model (exists).
- Produces:
  - `mint_operator_token(pepper: bytes) -> tuple[str, AgentKeyDraft]` (reuses the draft dataclass from `custos.keys`; token `co-<12hex>.<43b64url>`)
  - `class OperatorAuthError(Exception)` (uniform 401)
  - `async verify_operator_token(session: AsyncSession, pepper: bytes, presented: str) -> OperatorToken`
  - `validate_expiry(expires_at: datetime | None, allow_sensitive: bool, now: datetime) -> None` → `AppError("invalid", …)` on absent/past/over-cap (90 d plain, 30 d sensitive)

- [ ] **Step 1: Write failing tests** — `tests/test_operator_tokens.py` (plain async tests, `pg_db` + maker; no app):

```python
async def test_mint_verify_roundtrip(pg_db): ...
    # token startswith "co-", len(secret part) == 43; verify returns the row
async def test_wrong_secret_revoked_expired_unknown_all_raise_same(pg_db): ...
    # each raises OperatorAuthError; tamper one char of secret; revoked_at set;
    # expires_at in past; unknown key_id; garbage string — all one exception type
async def test_agent_key_never_verifies_as_operator_token(pg_db): ...
    # mint_agent_key token presented to verify_operator_token → OperatorAuthError
def test_expiry_caps():
    # None → invalid; now+91d plain → invalid; now+90d plain → ok;
    # now+31d sensitive → invalid; now+30d sensitive → ok; past → invalid
```

- [ ] **Step 2: Run to verify failure** — `uv run python -m pytest tests/test_operator_tokens.py -q` → ImportError.
- [ ] **Step 3: Implement** — mirror `custos/keys.py` exactly: `_TOKEN_RE = re.compile(r"^co-([0-9a-f]{12})\.([A-Za-z0-9_-]{43})\Z")`, dummy-digest constant-time path on every failure branch, digest over the secret **text** after the `.` (§4). `validate_expiry` compares `expires_at - now` against `timedelta(days=90 if not allow_sensitive else 30)`.
- [ ] **Step 4: Run tests + lint/typecheck** — pytest file green; `uv run ruff check .`; `uv run mypy` clean.
- [ ] **Step 5: ocr gate + commit** — `feat: operator-token credentials with mandatory expiry caps`.

### Task 2: Admin auth layer + authority matrix

**Files:**
- Create: `custos/admin/__init__.py`, `custos/admin/auth.py`, `tests/admin_conftest.py`
- Modify: `custos/ratelimit.py`, `custos/operator/sessions.py` (`check_purpose`: `recovery_reset` denied on any `/api/admin` path), `custos/app.py` (include a minimal placeholder admin router with `GET /api/admin/ping` → `{"ok": true}` for auth tests; replaced by real routes in later tasks — keep the ping route permanently as an auth-only smoke endpoint)
- Test: `tests/test_admin_auth.py`

**Interfaces:**
- Consumes: Task 1 verify/mint; `require_session` (sessions.py); `OperatorSession`, `OperatorToken` rows.
- Produces:
  - `@dataclass(frozen=True) class AdminPrincipal` satisfying the `custos.items.Principal` protocol: `actor_id: str`, `actor_label: str`, `actor_kind: str` (`"operator_session"` | `"operator_token"`), `mode: str = "read-write"`, `scopes: tuple[str, ...] = ("*",)`, `allow_sensitive: bool = False`, `row_id: uuid.UUID` (session/token row pk), `key_id: str | None` (token key_id else None). `plane` property: `"session"` for sessions else the token `key_id` (cursor binding, Task 6).
  - `async require_admin(request: Request) -> AdminPrincipal` — cookie XOR bearer (both → 401 `unauthorized`); cookie path delegates to `require_session` (CSRF/Origin/purpose already enforced there); bearer path: `verify_operator_token`, then 300/min bucket keyed `admin:<actor_kind>:<row_id>`; failures → uniform 401; **failed bearer auth writes `auth_events`? No — operator-token failures are audited `auth.failure` only (actor anonymous, `detail.reason: "admin_auth"`), no lockout kind exists for them (§5 closed kind list)**.
  - `async require_session_only(request: Request) -> AdminPrincipal` — resolves via `require_admin`; if `actor_kind != "operator_session"` → audit `auth.failure` (`detail.reason: "session_required"`, ip) then 403 `session_required` **before any route body runs**; then consumes `x-step-up-token` (missing/invalid → 401 `step_up_required`) via Task-2-extended `consume_step_up`.
  - `async require_sensitive(request: Request) -> AdminPrincipal` — session: consume single step-up; token: `allow_sensitive` must be True, else 401 `step_up_required` (a plain token may still step up interactively); `allow_sensitive` token passes without header. Marks `request.state.allow_sensitive = True` when the token path was used (routes copy it into audit detail).
  - `async peek_step_up(request: Request, sess: OperatorSession) -> None` — validates the `x-step-up-token` (bound, live, unconsumed, kind `single`) **without consuming**; missing/invalid → 401 `step_up_required`. Used by the write pre-gate below so a rejected write never burns a token.
  - `consume_step_up(session, token, presenter: OperatorSession | OperatorToken) -> StepUpToken` — extended: binding checks `session_id == presenter.id` for sessions, `operator_token_id == presenter.id` for tokens; token presenter must be unrevoked/unexpired. Existing session behavior unchanged.
  - `RateLimiter.check_admin_request(key: str) -> None` — 300/min sliding window, 429 + `Retry-After`.
  - `tests/admin_conftest.py` helpers as described in File Structure.

- [ ] **Step 1: Write failing tests** — `tests/test_admin_auth.py` using `admin_stack`:

```python
async def test_session_and_token_both_reach_ping(admin_stack): ...
async def test_cookie_plus_bearer_401(admin_stack): ...
async def test_bad_token_uniform_401(admin_stack): ...
async def test_csrf_required_on_session_mutation(admin_stack): ...
    # POST /api/auth/logout without x-csrf-token → 403 (existing guard, regression)
async def test_recovery_reset_session_denied_on_admin(admin_stack): ...
    # purpose='recovery_reset' row → GET /api/admin/ping 403 purpose_denied
async def test_session_only_matrix_precedes_state(admin_stack): ...
    # unit-test require_session_only with a Request whose resolved principal is
    # an operator_token (plain AND allow_sensitive) → AppError session_required
    # + auth.failure audit row; real-route coverage follows in Tasks 5/7/9
async def test_sensitive_gate(admin_stack): ...
    # unit: session w/o header → step_up_required; plain token → step_up_required;
    # allow_sensitive token → passes, request.state.allow_sensitive True
async def test_step_up_bound_to_token_principal(admin_stack): ...
    # mint single step-up bound to operator_token row; consume from that token ok;
    # from a session → step_up_required; revoked token → step_up_required
async def test_admin_rate_limit(admin_stack): ...
    # RateLimiter().check_admin_request: 300 pass, 301st raises rate_limited
```

- [ ] **Step 2: Run to verify failure** — pytest file → ImportError.
- [ ] **Step 3: Implement** auth layer + `consume_step_up` extension + limiter method + purpose deny + ping route. Gate dependencies are FastAPI dependencies returning `AdminPrincipal`; routes in later tasks use `Depends(require_admin)` etc. Audit calls use `record_audit(maker, …)` with the closed enum.
- [ ] **Step 4: Full check** — file green, whole suite green (consume_step_up signature change must not break plan-2 tests), ruff + mypy clean.
- [ ] **Step 5: ocr gate + commit** — `feat: admin dual-auth layer with the authority matrix`.

### Task 3: Admin item reads + masked writes

**Files:**
- Create: `custos/admin/items.py`, `custos/admin/routes_items.py`
- Modify: `custos/items.py` (`get_item(..., include_deleted: bool = False, mask: bool = False)`; `create_item/put_item/patch_item(..., mask: bool = False, allow_downgrade: bool = False)`), `custos/routes_agent.py` (`list_via_engine(..., include_deleted: bool = False)` adds `deleted` bool to rows only when True; agent calls unchanged), `custos/envexport.py` (`env_lines(fields, allow_hazardous: bool = False)`), `custos/app.py`
- Test: `tests/test_admin_items.py`, `tests/test_admin_writes.py`

**Interfaces:**
- Consumes: `require_admin`, `require_sensitive` (Task 2); engine functions above; `list_via_engine`.
- Produces:
  - `async masked_get(session, vault, p: AdminPrincipal, name: str) -> dict` — full notes, plain values, secrets `{name, secret: true}` or `{name, secret: true, unavailable: true}` when the blob fails trial decryption; **works on soft-deleted items**; no audit (enumeration read).
  - `async reveal(session, maker, vault, p, name) -> dict` — full values via existing `get_item(..., include_deleted=True)`; audited `reveal`; unreadable → 500 `key_unavailable` after gates.
  - `async admin_env(session, maker, vault, p, name, allow_hazardous: bool) -> str` — decrypted views → `env_lines(views, allow_hazardous)`; audited `env` (`detail.allow_sensitive` when token path); 4 MiB bound already in `env_lines`.
  - `async history_list(session, p, name, cursor, limit) -> dict` — metadata rows `{id, name, secret, superseded_at, superseded_by, actor_label}` (`name` = the field name), 50/100 pages via `mint_cursor`/`read_cursor` endpoint `"admin_history:<name>"`; audited `history` (count only); works on soft-deleted items; 404 unknown name.
  - `async history_reveal(session, maker, vault, p, name, snapshot_id) -> dict` — snapshot's `item_id` must match the named item else 404; one step-up per call (route gate); response `{id, name, secret, value, superseded_at}` (one snapshot = one field value); audited `reveal` with `item_name` = snapshot's item, `detail.count: 1`; unreadable → 500.
  - Masking in engine: when `mask=True`, `_response` output replaces every secret entry with `{name, secret: true}` (drops `value`/`kept`); plain entries unchanged. When `allow_downgrade=True`, `DowngradeError` is not raised (the route gate already ran).
  - Downgrade pre-gate (routes, PUT/PATCH): load current views read-only, run `plan_put_ops`/`plan_patch_ops` in try/except `DowngradeError`. **No downgrade → normal engine call, no step-up needed.** Downgrade detected: token principal must be `allow_sensitive` (else 401 `step_up_required`); session principal must pass `peek_step_up` (else 401, nothing burned, nothing written). Gate passed → call engine with `allow_downgrade=True`; the engine raises `DowngradeError` again under the row lock if concurrent state changed — the route then consumes the step-up via `consume_step_up` and retries the engine call once with `allow_downgrade=True` (a second concurrent flip → 409 `conflict`).

Routes (all `Depends(require_admin)` unless noted): `GET /items` (list incl. deleted), `GET /items/{name}` (masked_get), `GET /items/{name}/reveal` + `/env` + `/history/{id}/reveal` (`Depends(require_sensitive)`), `GET /items/{name}/history`, `POST /items`, `PUT/PATCH/DELETE /items/{name}`, all writes masked.

- [ ] **Step 1: Write failing tests** — key assertions:

```python
# tests/test_admin_items.py
async def test_masked_get_and_list(admin_stack): ...
    # secret field: {"name","secret":true} exactly, no value key; plain visible;
    # full notes on get; list rows notes ≤256 chars + deleted flag
async def test_soft_deleted_visible_to_admin_reads(admin_stack): ...
    # DELETE via engine → agent GET 404, admin masked get 200, list deleted:true
async def test_reveal_and_env_gate(admin_stack): ...
    # no step-up → 401; with step-up → full values; env exports quoted lines;
    # allow_sensitive token: no header needed; plain token: 401
async def test_env_hazardous_override(admin_stack): ...
    # field PATH: default commented refusal; ?allow_hazardous=1 + gate → exported
async def test_history_list_and_reveal(admin_stack): ...
    # PUT new value → 1 snapshot; reveal returns OLD value; wrong item name → 404;
    # each reveal needs its own step-up (second call with same token → 401)
async def test_degraded_masked_get(admin_stack): ...
    # corrupt one ciphertext byte via maker → masked get unavailable:true;
    # reveal → 500 key_unavailable; list still 200 without unavailable keys

# tests/test_admin_writes.py
async def test_all_admin_write_responses_masked(admin_stack): ...
    # POST/PUT/PATCH with secret fields: response JSON contains no secret value
    # substring anywhere; secret entries exactly {name, secret:true}
async def test_downgrade_needs_gate_atomic(admin_stack): ...
    # PATCH remove+re-add secret as plain, no step-up → 401 step_up_required,
    # field STILL secret afterwards; with step-up → 200 and field plain
async def test_write_echo_never_decrypts_kept(admin_stack): ...
    # PUT omitting a secret value succeeds; response has no kept value
async def test_etag_and_validation_shared(admin_stack): ...
    # If-Match mismatch → 409; duplicate field names → 422 (engine reuse regression)
```

- [ ] **Step 2: Run to verify failure** — both files fail (routes 404).
- [ ] **Step 3: Implement** engine kwargs + admin engines + routes; register router in `create_app`.
- [ ] **Step 4: Full check** — new files green; **whole suite green** (agent-plane responses must be byte-identical: `mask`/`include_deleted` default False); ruff + mypy.
- [ ] **Step 5: ocr gate + commit** — `feat: admin item reads and masked writes`.

### Task 4: Restore + purge

**Files:**
- Modify: `custos/admin/items.py`, `custos/admin/routes_items.py`
- Test: `tests/test_admin_lifecycle.py` (restore/purge half; Task 5 appends force-drop)

**Interfaces:**
- Consumes: Task 2 gates, Task 3 routes module.
- Produces:
  - `async restore(session, maker, vault, p, name) -> dict` — live item → 409 `conflict`; absent → 404; soft-deleted → clear `deleted_at`, bump revision, audit `restore`, **masked response**; metadata-only (no decryption — degraded restore works). Route: `POST /items/{name}/restore`, `Depends(require_sensitive)`.
  - `async purge(session, maker, p, name) -> None` — any state; delete history rows first, then fields, then item row, one transaction; absent → 404; audit `purge` (`detail.count` = total rows deleted). Route: `DELETE /items/{name}/purge`, `Depends(require_session_only)`; 204.

- [ ] **Step 1: Write failing tests:**

```python
async def test_restore_flow(admin_stack): ...
    # soft-delete → restore w/ step-up → agent GET 200 again; revision bumped;
    # live restore → 409; allow_sensitive token restores without header
async def test_restore_gates(admin_stack): ...
    # no step-up → 401; plain token → 401; response masked (no secret values)
async def test_purge_session_only_before_state(admin_stack): ...
    # co- allow_sensitive token on ABSENT name → 403 session_required (not 404),
    # auth.failure audit row exists
async def test_purge_hard_deletes(admin_stack): ...
    # purge soft-deleted item w/ history → items/fields/field_history rows gone
    # (maker counts); name reusable via POST; absent name → 404; no step-up → 401
async def test_degraded_restore_and_purge(admin_stack): ...
    # corrupted ciphertext: restore 200, purge 204 (metadata-only paths)
```

- [ ] **Step 2: Verify failure** — 404s / ImportError.
- [ ] **Step 3: Implement** (purge order pinned by §4 schema note: history → fields → item; no FK cascade reliance).
- [ ] **Step 4: Full check** — file + suite green, ruff + mypy.
- [ ] **Step 5: ocr gate + commit** — `feat: admin restore and purge with session-only purge gate`.

### Task 5: Force-drop route + degraded remedy E2E

**Files:**
- Modify: `custos/admin/routes_items.py`
- Test: `tests/test_admin_lifecycle.py` (append)

**Interfaces:**
- Consumes: existing `custos.items.force_drop(session, maker, vault, p, name, actor_kind) -> int` (plan 1), `require_session_only`.
- Produces: `POST /api/admin/items/{name}/force-drop` → `{"dropped_unreadable": n}`; session+step-up only; keeps item row + `deleted_at` state; audited `force_drop` by the engine.

- [ ] **Step 1: Write failing tests:**

```python
async def test_force_drop_drops_only_unreadable(admin_stack): ...
    # item with 1 corrupted secret + 1 readable secret + 1 corrupted history row
    # → dropped 2; readable field still decrypts; item row + name kept
async def test_force_drop_gates(admin_stack): ...
    # token (any) → 403 session_required before state (absent name too);
    # session w/o step-up → 401; absent name w/ session+step-up → 404
async def test_degraded_remedy_chain(admin_stack): ...
    # §11: corrupt → masked get unavailable → PUT fails 500 → force-drop →
    # PUT succeeds; soft-deleted item stays 404 to agents after force-drop
```

- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement** — thin route over the engine; `actor_kind="operator_session"`.
- [ ] **Step 4: Full check.**
- [ ] **Step 5: ocr gate + commit** — `feat: force-drop route completing the degraded-mode remedy`.

### Task 6: Key + token management routes

**Files:**
- Create: `custos/admin/routes_keys.py`
- Modify: `custos/app.py`
- Test: `tests/test_admin_keys.py`

**Interfaces:**
- Consumes: `mint_agent_key` (keys.py), `mint_operator_token`/`validate_expiry` (Task 1), `require_admin`, `require_session_only`.
- Produces routes:
  - `POST /api/admin/keys` body `{label, mode, scopes, expires_at?}` → 201 `{token, key_id, label, mode, scopes, expires_at, created_at}` — token shown **once**; validation: mode in enum, scopes list of str (empty allowed = no access), label 1..200 chars; audit `key.mint` (`detail.key_id`).
  - `GET /api/admin/keys` → `{keys: [{key_id, label, mode, scopes, expires_at, revoked_at, created_at}]}` — never digest/token; audited `key.list` (`detail.count`).
  - `DELETE /api/admin/keys/{key_id}` → 204; sets `revoked_at`; unknown → 404; audit `key.revoke`.
  - `POST /api/admin/tokens` body `{label, allow_sensitive?, expires_at}` (ISO 8601, mandatory) → 201 `{token, key_id, label, allow_sensitive, expires_at, created_at}`; `validate_expiry` caps; audit `token.mint` (`detail.key_id`, `allow_sensitive`).
  - `GET /api/admin/tokens` → masked inventory; audited `token.list`.
  - `DELETE /api/admin/tokens/{key_id}` → 204; `revoked_at` + **`DELETE FROM step_up_tokens WHERE operator_token_id = :id AND consumed_at IS NULL` same transaction**; audit `token.revoke`.
  - All mutating routes `Depends(require_session_only)`.

- [ ] **Step 1: Write failing tests:**

```python
async def test_key_mint_once_and_agent_auth(admin_stack): ...
    # mint via HTTP → returned token authenticates GET /api/items; inventory
    # has no token/digest substring; key.mint audit row
async def test_mint_revoke_session_only(admin_stack): ...
    # co- token (allow_sensitive too) POST /keys → 403 session_required + audit;
    # session w/o step-up → 401; step-up consumed exactly once (reuse → 401)
async def test_revoke_bites_next_request(admin_stack): ...
    # minted agent key works, DELETE /keys/{id}, next agent GET → 401
async def test_token_expiry_caps_http(admin_stack): ...
    # absent expires_at → 422; +91d → 422; sensitive +31d → 422; +30d ok
async def test_token_revoke_kills_bound_run_and_stepup(admin_stack): ...
    # mint token, bind an unconsumed single step-up row to it via maker,
    # revoke → step_up_tokens row deleted; token auth → 401
async def test_inventory_audited(admin_stack): ...
    # GET /keys and /tokens with a co- token → 200 + key.list/token.list rows
```

- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Full check.**
- [ ] **Step 5: ocr gate + commit** — `feat: admin key and operator-token management`.

### Task 7: Rekey engine + route

**Files:**
- Create: `custos/rekey.py`, `custos/admin/routes_maintenance.py` (rekey half)
- Modify: `custos/operator/stepup.py` (run-token helpers), `custos/app.py`
- Test: `tests/test_rekey.py`

**Interfaces:**
- Consumes: `Vault.seal/open` (domains `"field"`, `"fieldh"`, `"operator:totp"`; operator row_id `"totp"`), `consume_step_up` (Task 2), `AdminPrincipal.plane`.
- Produces:
  - `mint_scan_cursor(payload: dict, pepper: bytes, endpoint: str, plane: str) -> str` / `read_scan_cursor(token, pepper, endpoint, plane) -> dict` — base64url JSON `{endpoint, table, last_id, plane}` + `.` + base64url HMAC-SHA256(pepper, payload-bytes); **no TTL**; tag/endpoint/plane mismatch → `AppError("unauthorized", …)` (401). Payload holds only the scan position.
  - `async mint_run(session, maker, presenter: OperatorSession, single_token: str) -> str` — guarded consume of the `single` + insert `StepUpToken(kind="rekey_run", session_id=…, expires_at=now+30min)` **in one transaction**; an existing unexpired `rekey_run` row (any principal) → 409 `conflict`; returns the opaque run token once.
  - `async validate_run(session, token: str, presenter: OperatorSession | OperatorToken) -> StepUpToken` — kind `rekey_run`, unexpired, presenter-bound + live; **does not consume**; extends `expires_at = now + 30min` on each successful batch (caller commits).
  - `async rekey_batch(session, maker, vault, p: AdminPrincipal, *, run_token: str | None, cursor: str | None) -> dict` — selection: fixed table order `fields` → `field_history` → `operator_account`, `id` ascending, `key_version != vault.current_version` (NULL never selected; **higher-than-keyring versions selected and skipped**), resume after `(table, last_id)`, ≤200 rows; per row: trial-open under its stored version → on success re-seal newest + guarded `UPDATE … WHERE id = :id AND key_version = :old AND ciphertext = :old_blob` (rowcount 0 → concurrent write, counted neither skipped nor blocking); open failure → `skipped += 1`; response `{remaining, skipped, run_token?, cursor?}` — `remaining` = COUNT of matching rows strictly ahead of the new cursor (SQL, no decrypt); first batch (session) returns `run_token`; `allow_sensitive` token path: no run row, same cursors. Audit `rekey` once per run start (`detail.allow_sensitive` when token).
  - Route `POST /api/admin/rekey` body `{cursor?}` + `x-step-up-token` header: session first batch = `single` token (mint run); session later batches = run token; token principal must be `allow_sensitive` (plain token → 401 `step_up_required`). Auth resolution lives in the route, engine takes the resolved principal.

- [ ] **Step 1: Write failing tests:**

```python
async def test_rekey_moves_all_domains(admin_stack): ...
    # seed rows under k1 (vault1), app vault k1+k2 → loop batches until
    # remaining 0 → every fields/field_history/totp blob opens under k2 only
async def test_batch_cursor_and_termination_with_unreadable(admin_stack): ...
    # 250 rows, 50 corrupted → loop terminates; skipped sums to 50;
    # remaining strictly decreases; corrupted rows keep old version
async def test_run_token_lifecycle(admin_stack): ...
    # first batch returns run_token; second batch with same single → 401
    # (consumed); with run token → 200; expiry extended per batch (maker check);
    # expired run row → 401; fresh step-up mints new run resuming from cursor
async def test_one_active_run(admin_stack): ...
    # second first-batch while run live → 409 conflict
async def test_cursor_binding(admin_stack): ...
    # rekey cursor on verify endpoint → 401 (Task 8 route may not exist yet —
    # unit-test read_scan_cursor endpoint mismatch); tampered tag → 401;
    # cursor from token plane presented by session → 401
async def test_sensitive_token_all_batches(admin_stack): ...
    # allow_sensitive token: no step-up ever; plain token → 401
async def test_concurrent_write_guard(admin_stack): ...
    # unit: after selection, mutate the row's blob via a second session, then
    # batch → row untouched by rekey, not counted skipped
```

- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement** — one transaction per batch; guarded UPDATE via ORM `update()` with the three-column WHERE; operator blob re-seal writes `totp_secret` + `totp_key_version` together.
- [ ] **Step 4: Full check.**
- [ ] **Step 5: ocr gate + commit** — `feat: batched rekey with run tokens and keyset cursors`.

### Task 8: Rekey audit + verify

**Files:**
- Modify: `custos/rekey.py`, `custos/admin/routes_maintenance.py`, `custos/audit.py` (`DETAIL_KEYS` += `unreadable_fields`, `unreadable_history`, `unreadable_operator`)
- Test: `tests/test_rekey_verify.py`

**Interfaces:**
- Consumes: Task 7 cursors/run mechanics.
- Produces:
  - `async rekey_audit(session, vault) -> dict` — `{versions: {fields: {<version>: n}, history: {…}, operator: {…}}, affected: {<version>: [item names]}}`; GROUP BY on `key_version` (ciphertext rows only — `key_version IS NOT NULL`), affected names via join for non-newest versions; **SQL only, no decryption**; route `GET /api/admin/rekey/audit`, plain `require_admin`, not audited.
  - `async verify_batch(session, maker, vault, p, *, run_token, cursor) -> dict` — visits **all** rows (no version filter), same order/cursor/run mechanics as rekey; trial-open each secret row; response `{remaining, unreadable: {fields: n, history: n, operator: n}, run_token?, cursor?}`; re-seals nothing; audit `rekey_verify` once per run start.
  - Route `POST /api/admin/rekey/verify` — same auth as rekey; `kind: rekey_run` accepted here too; cursors endpoint-tagged `"rekey_verify"` (not interchangeable with `"rekey"`).

- [ ] **Step 1: Write failing tests:**

```python
async def test_audit_sql_counts(admin_stack): ...
    # mixed-version rows + one plain field → audit counts exclude NULL versions;
    # affected names listed per old version; corrupt blob under AVAILABLE
    # version does NOT appear (SQL-only) but DOES appear in verify unreadable
async def test_verify_visits_newest_rows(admin_stack): ...
    # all rows k2, one corrupted → rekey remaining 0 immediately, verify
    # unreadable.fields 1; verify never changes key_version/blob bytes
async def test_verify_run_and_cursor(admin_stack): ...
    # first batch run_token; rekey cursor → 401 on verify; verify cursor → 401
    # on rekey; same run token works on both endpoints
async def test_verify_gates(admin_stack): ...
    # session w/o step-up → 401; plain token → 401; allow_sensitive ok
```

- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Full check.**
- [ ] **Step 5: ocr gate + commit** — `feat: rekey audit and trial-decrypt verification sweep`.

### Task 9: Retention

**Files:**
- Create: `custos/retention.py`
- Modify: `custos/admin/routes_maintenance.py`, `custos/audit.py` (`DETAIL_KEYS` += `pruned`), `custos/app.py` (final router wiring if not yet)
- Test: `tests/test_retention.py`

**Interfaces:**
- Consumes: `require_session_only`, `settings.retention_days`, models.
- Produces:
  - `async run_retention(session, maker, p: AdminPrincipal, days: int) -> dict[str, int]` — cutoff `now - days`; returns counts keyed `field_history`, `audit`, `auth_events`, `operator_sessions`, `step_up_tokens`, `device_codes`, `webauthn_challenges`, `lockout_suppressions`; deletes: history older than cutoff **except the 20 most recent per `(item_id, name)`** (window function `row_number() OVER (PARTITION BY item_id, name ORDER BY superseded_at DESC)` ≤ 20 kept — ORM `delete().where(id.in_(select…))`); audit/auth_events older than cutoff; sessions expired-or-revoked; step-ups consumed-or-expired; device codes expired-or-consumed; webauthn challenges expired-or-consumed; suppressions with marker ts older than cutoff. **Never touches `recovery_codes`, live sessions, live runs, items/fields.** Audit `retention` with `detail.pruned` = total count (per-table counts go in the response only — closed detail set stays scalar).
  - Route `POST /api/admin/retention` — `Depends(require_session_only)`; token → 403 `session_required` before state; response = the counts dict.

- [ ] **Step 1: Write failing tests:**

```python
async def test_recent_prior_floor(admin_stack): ...
    # 25 snapshots of one field ALL older than cutoff → prune keeps exactly 20
    # newest; current field value untouched
async def test_prunes_dead_rows_only(admin_stack): ...
    # expired session + live session; consumed step-up + live run; consumed
    # device code + live one; old audit row + fresh → only dead/old removed;
    # recovery_codes untouched even when consumed
async def test_lockout_ledger_floor(admin_stack): ...
    # auth_events newer than 7d never pruned at days=7; suppressions older
    # than cutoff removed
async def test_retention_session_only(admin_stack): ...
    # allow_sensitive token → 403 session_required + auth.failure audit;
    # session w/o step-up → 401; with → 200 counts + retention audit row
```

- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Full check.**
- [ ] **Step 5: ocr gate + commit** — `feat: operator retention with the recent-prior floor`.

### Task 10: Audit read endpoint + real-mint E2E

**Files:**
- Modify: `custos/admin/routes_maintenance.py`, `scripts/e2e.sh`
- Delete: `scripts/e2e_seed.py`
- Test: `tests/test_admin_audit.py`

**Interfaces:**
- Consumes: `mint_cursor`/`read_cursor`, `AuditRow`.
- Produces: `GET /api/admin/audit?actor=&action=&item=&from=&to=&cursor=&limit=` — 50/100 pages ordered by `id` ascending (keyset `after` id in cursor, endpoint `"admin_audit"`), filters AND-combined (`actor` = actor_id exact, `action` enum member, `item` = item_name exact, `from`/`to` ISO timestamps on `ts`); rows `{id, ts, actor_kind, actor_id, actor_label, action, item_name, ok, detail}`; plain `require_admin`; not audited.

- [ ] **Step 1: Write failing tests:**

```python
async def test_audit_filters_and_pagination(admin_stack): ...
    # >50 rows → two pages via next_cursor; actor/action/item filters narrow;
    # foreign cursor (other principal) → 422 invalid
async def test_audit_never_contains_values(admin_stack): ...
    # write items with sentinel secret values → no audit row detail contains
    # the sentinel (json dump scan)
```

- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement route.**
- [ ] **Step 4: Rework `scripts/e2e.sh`** — replace the `e2e_seed.py` call with real HTTP flow against the throwaway vault: setup (read the generated `setup-code` file) → login → step-up → `POST /api/admin/keys` ×3 (rw/ro/scoped, same labels/scopes as the old seed) → extract tokens with `python -c` JSON parsing → existing agent REST + MCP + revocation + audit-delta assertions unchanged; add admin assertions: masked get has no secret values, `GET /api/admin/audit` shows `key.mint`, revoke via `DELETE /api/admin/keys/{id}` replaces any direct-DB revocation. Delete `scripts/e2e_seed.py`.
- [ ] **Step 5: Run E2E** — `bash scripts/e2e.sh` → `E2E PASS` (this is the plan's proof; run it, don't claim it).
- [ ] **Step 6: Full check + ocr gate + commit** — `feat: audit read endpoint; E2E mints keys through the real admin flow`.

---

## Self-review notes

- Spec coverage: §6 admin table fully mapped (items T3–5, keys/tokens T6, rekey/verify/audit T7–8, retention T9, audit T10); §5 operator tokens T1/T6; §4 rekey/cursors/degraded T7–8 + T3/T5; §11 invariants in Review Focus tests. Account-management routes already shipped in plan 2 — out of scope here.
- Type consistency: `AdminPrincipal` satisfies the existing `Principal` protocol; `consume_step_up` presenter union introduced in T2 and consumed by T6/T7; `mint_scan_cursor`/`read_scan_cursor` names used identically in T7/T8.
- Deliberate scope cuts: no console (plan 4), no CLI (plan 5); `GET /api/admin/ping` is a permanent auth smoke endpoint, not scaffolding.