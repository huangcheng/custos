# Custos Operator Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operator account lifecycle: one-shot setup, password/TOTP/recovery login, sessions + CSRF, step-up, lockout, Turnstile, passkeys, and the CLI device hand-off — everything plan 3's admin plane will gate on.

**Architecture:** New `custos/operator/` subpackage (account, sessions, totp, recovery, lockout, turnstile, passkeys, device, routes_auth) over the existing schema/ledger/crypto. Argon2id via argon2-cffi with the pinned PHC parameters; WebAuthn via the `webauthn` library. All routes thin over module functions; every credential failure feeds the §5 lockout ledger through the existing independent-commit layer.

**Tech Stack:** existing stack + `webauthn>=2.0` (already declared), `pyotp`, `argon2-cffi` (declared). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-17-custos-design.md` (rev 36) §3 (CSRF/cookies/hardening), §5 (Operator account, Sessions, TOTP, Recovery, Passkeys, Lockout, Step-up, device hand-off), §6 (auth endpoints, error table), §10 (config), §11 (invariants).

**Plan series:** plan 2 of 5. Plan 1 (backend foundation) is complete on main. Plan 3: admin plane + keys/tokens + rekey/retention. Plan 4: console + stdio MCP wrapper. Plan 5: Rust CLI + deploy. Do NOT implement admin routes here — only the auth surface and the `require_session` / `require_step_up` dependencies plan 3 consumes.

## Global Constraints

- Same as plan 1: ORM-only DB access, no secrets in logs/audit/errors/telemetry, fake fixtures only (`cu-test.…`), ocr gate per commit (findings from aborted runs recovered from session JSONL checkpoints), English artifacts, ruff+mypy strict clean per task.
- Argon2id pinned: m=65536 KiB, t=3, p=4, salt 16B, hash 32B, PHC v0x13 (`argon2-cffi` defaults overridden explicitly).
- Password policy: ≥12 chars, no composition rules — enforced identically at setup, password change (plan 3 wires the route; the validator lives here).
- Session cookie: `custos_session`, 32 random bytes b64url, SHA-256 stored; `HttpOnly; Secure; SameSite=Lax` (Secure dropped only under the dev flag); idle 12h/absolute 7d defaults; `recovery_reset` fixed 30-min window, idle disabled; device-exchange sessions idle 1h/absolute 12h.
- CSRF: 32 random bytes b64url per session, constant-time compare, header `x-csrf-token` on cookie mutations; cookie+bearer together → 401; cross-site Origin/Referer on cookie mutations → 403.
- Lockout: per-IP 10 failures/15 min → 15-min block; per-account 30/30 min non-extending; counted kinds `login_password login_totp login_passkey login_recovery step_up setup` (setup per-IP only); order lockout → limiter → Turnstile → credentials; 429-gated requests never verify/ledger; suppressions honored (`ip:<addr>`, `ip:*`, `account`).
- TOTP: per-site monotonic counters (login/stepup/confirm), guarded UPDATE, ±1 step, reject step ≤ stored.
- Recovery codes: 16 chars from `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, normalize uppercase/strip dashes+spaces/I,L→1/O→0, other chars → uniform 401; scan all unconsumed rows with `digests_equal`; consume = guarded UPDATE on success only.
- Uniform login 401 body for every credential failure; one auth_events row per failed request (stage that failed).
- Test fixtures own app lifespans (plan-1 ruling: pytest-asyncio fixture tasks differ).

## Review Focus

- Concurrent login/step-up/recovery consumption races: exactly one winner per guarded UPDATE; no double session issuance from one recovery code.
- Lockout boundary math: 10th vs 11th failure, window expiry, non-extending account block, suppression markers incl. `ip:*`, 429 paths writing no ledger rows.
- Session lifecycle edges: idle vs absolute expiry, recovery_reset no-refresh, promotion invalidating siblings, revoked session + stale CSRF, cookie+bearer rejection.
- Turnstile fail-closed matrix: outage/timeout/already-spent/missing-hostname/hostname-mismatch all 422 before credentials; dev+Turnstile startup refusal.
- Device hand-off abuse: re-approval, 6th exchange attempt, expired windows, cross-row code mixups, flood cap ≤5 live rows/IP.

---

### Task 1: Password hashing + account store + one-shot setup

**Files:**
- Create: `custos/operator/__init__.py`, `custos/operator/account.py`, `custos/operator/routes_auth.py`, `tests/test_operator_account.py`
- Modify: `custos/app.py` (include auth router), `custos/config.py` (setup-code + bootstrap-password settings fields)

**Interfaces:**
- Produces: `hash_password(pw: str) -> str` / `verify_password(hash: str, pw: str) -> bool` (argon2-cffi, pinned params, `verify` never raises on mismatch); `validate_password(pw: str) -> None` (raises AppError invalid if <12); `async setup_account(session, maker, *, username, password, setup_code, ip, peer_ip, expected_code: str) -> None` (guarded single insert; consumed code; raises AppError `setup_complete` 403 forever after; wrong code → uniform 401 + `setup` auth-event); `Settings.setup_code: str | None`, `Settings.operator_password: str | None` (env/file paired, ≥12 validated at startup); generated setup code written 0600 to `data_dir/setup-code` at first startup when absent (reuse existing file), deleted on success.
- `router` (APIRouter prefix `/api/auth`) with `POST /setup` and `GET /status` stub returning `{setup_required, totp_required: false, turnstile_sitekey: null, passkey_available: false}` (+csrf later).

- [ ] **Step 1: Failing tests**: PHC string starts `$argon2id$v=19$m=65536,t=3,p=4$`; hash/verify round-trip; wrong password False; 11-char password rejected at setup and by validator; setup success creates single row + deletes code file; second setup → 403 `setup_complete` (audited); wrong code → 401 + one `setup` auth-event; env+file both set → ConfigError; bootstrap env password <12 → ConfigError; body+env password both → 422; both absent → 422; restart reuses existing code file.
- [ ] **Step 2: Run** — FAIL (module missing).
- [ ] **Step 3: Implement** per interfaces; setup exempt from Turnstile; setup failures feed lockout via Task 4's recorder — until then call `record_auth_event(kind="setup")` directly.
- [ ] **Step 4: Run** — PASS full suite; ruff+mypy.
- [ ] **Step 5: ocr gate + commit** `feat: add operator account store and one-shot setup`.

### Task 2: Sessions + CSRF + status

**Files:**
- Create: `custos/operator/sessions.py`, `tests/test_sessions.py`
- Modify: `custos/operator/routes_auth.py` (status csrf, logout), `custos/app.py` (cookie/CSRF middleware helpers)

**Interfaces:**
- Produces: `async create_session(session, *, purpose="full", idle_ttl=43200, absolute_ttl=604800) -> tuple[OperatorSession, str]` (returns row + opaque cookie value; csrf on row); `async resolve_session(session, cookie: str) -> OperatorSession` (raises AppError unauthorized; checks revoked/idle/absolute; refreshes last_seen unless purpose=recovery_reset); `async revoke_all_sessions(session, except_id=None)` (sets revoked_at + DELETE unconsumed step_up_tokens bound to them); `check_csrf(request, sess)` (constant-time; missing/wrong → 401); `require_session` FastAPI dependency (cookie → session; bearer+cookie → 401; recovery_reset outside allowlist → 403 purpose_denied); `set_session_cookie(response, value, settings)` honoring dev flag.
- `GET /status` returns csrf_token when a live session cookie is present; `POST /logout` (cookie+CSRF) revokes the session, clears cookie, audits operator.logout.

- [ ] **Step 1: Failing tests**: cookie shape 43-char b64url; resolve ok/refresh; idle expiry (freeze time via monkeypatched now); absolute expiry; revoked → 401; recovery_reset never refreshes and dies at created+30min; CSRF wrong/missing → 401 on mutation, GET status works without; cookie+bearer → 401; cross-site Origin on cookie mutation → 403; logout revokes + audits; revoke_all deletes bound step-up rows but keeps session rows.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement**; Origin check: if Origin header present and not in allowed set (loopback/dev or CUSTOS_ALLOWED_ORIGINS) → 403 on cookie mutations.
- [ ] **Step 4: Run** — PASS; ruff+mypy.
- [ ] **Step 5: ocr gate + commit** `feat: add operator sessions, CSRF, and logout`.

### Task 3: Password login + uniform failures

**Files:**
- Create: `custos/operator/login.py`, `tests/test_login.py`
- Modify: `custos/operator/routes_auth.py` (POST /login), status `totp_required`

**Interfaces:**
- Produces: `async login(session, maker, *, username, password, totp=None, recovery_code=None, ip, peer_ip) -> OperatorSession` — order: account exists? → password verify → factor (Task 5/6 plug in via `verify_second_factor` hook returning stage name); both factors present → 422; TOTP enabled + neither factor → 401 `login_totp` row; unknown user/bad password → 401 `login_password` row; ONE row per failed request; success audits operator.login + issues full session. Global Argon2 semaphore (2 concurrent, 10s queue → 429) around password verification.
- Login route sets cookie + returns `{csrf_token}`; failures raise the uniform AppError unauthorized AFTER ledger writes (LedgerError → 503-equivalent internal_error).

- [ ] **Step 1: Failing tests**: correct password (TOTP off) → 200 + cookie + csrf; wrong password/unknown user → byte-identical 401s; one auth_events row per failure with right kind; both factors → 422; semaphore: 3rd concurrent verify waits/429s (use slow fake hasher monkeypatch); ledger-down → internal_error not 401-success.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add password login with uniform failures and argon2 semaphore`.

### Task 4: Lockout + suppressions + unauthenticated limiter

**Files:**
- Create: `custos/operator/lockout.py`, `tests/test_lockout.py`
- Modify: `custos/operator/login.py` + setup (gate before verify), `custos/ratelimit.py` (unauth bucket 10/min/IP, setup 3/min/IP + global 10/min)

**Interfaces:**
- Produces: `async check_lockout(session, *, ip, account_exists: bool) -> None` (raises AppError locked_out 429 + Retry-After; queries auth_events minus suppressions; per-IP 10/15, per-account 30/30 non-extending — block window anchored at the 30th failure, later failures don't extend); `async record_failure(...)` wrapper = record_auth_event + budget/counter fallback (reuse FailureCounter windows); `check_unauth_bucket(limiter, ip, endpoint)` (setup gets 3/min/IP + global 10/min).
- Order enforced in login/setup: lockout → limiter → (Turnstile, Task 7) → credentials. 429 paths write no rows.

- [ ] **Step 1: Failing tests**: 10 failures → 11th 429 locked_out with Retry-After; window expiry unblocks; account block at 30 non-extending (failures during block don't push the end); `ip:*` suppression unblocks every IP; account suppression unblocks account only; setup counts per-IP only; 429-gated request adds no auth_events row; fallback counter path (budget exhausted) still blocks.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add credential lockout with suppressions and unauth rate limits`.

### Task 5: TOTP enable/confirm/disable + login/step-up factor

**Files:**
- Create: `custos/operator/totp.py`, `tests/test_totp.py`
- Modify: `custos/operator/login.py` (factor hook), routes (totp/setup, totp/confirm, totp/disable — session+step-up gated once Task 8 lands; until then session-only with a TODO-free interim: gate on session now, add step-up dependency in Task 8's step), status totp_required

**Interfaces:**
- Produces: `async begin_totp_setup(session, vault) -> tuple[str, str]` (secret b64 + provisioning URI, sealed under operator AAD at newest version, stored disabled); `async confirm_totp(session, vault, code) -> list[str]` (activates + returns 10 recovery codes via Task 6 — codes land in Task 6; here return [] and Task 6 wires); `async disable_totp(session)`; `async verify_totp(session, vault, code, site: str) -> bool` (guarded monotonic UPDATE per site, ±1 step, reject ≤ stored; unreadable blob → AppError key_unavailable, no auth-event).
- Login with totp enabled: bad code → 401 `login_totp`; disabled + code supplied → ignored.

- [ ] **Step 1: Failing tests**: setup→confirm activates (valid current code); replay same code rejected at same site; login-then-stepup same step works (independent counters); older step within ±1 rejected after newer accepted; disable clears secret; corrupted blob → 500 key_unavailable no ledger row; wrong code one login_totp row.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add TOTP with per-site replay guards`.

### Task 6: Recovery codes + recovery_reset session + promotion

**Files:**
- Create: `custos/operator/recovery.py`, `tests/test_recovery.py`
- Modify: login (recovery path), totp confirm (issue codes), routes (recovery/regen)

**Interfaces:**
- Produces: `issue_codes(session, pepper) -> list[str]` (10 codes, digests stored, prior unconsumed consumed soft); `async consume_code(session, pepper, presented) -> bool` (normalize; scan unconsumed with digests_equal; guarded UPDATE consumed_at IS NULL; exactly one winner); recovery login (password+code) → `recovery_reset` session (30-min fixed); `async change_password(session, maker, sess_row, *, current, new) -> OperatorSession` — verifies current password, ≥12 new, rehash, revoke all sessions+tokens+codes, promote recovery_reset → full (fresh TTLs) atomically disabling TOTP + issuing 10 fresh codes returned once; full-session change mints one replacement session.
- `POST /api/auth/password-change` (session; recovery_reset waiver: current password required, no step-up; full sessions: step-up required once Task 8 lands).

- [ ] **Step 1: Failing tests**: normalization collisions (IL→11, O→0) accepted; U rejected; concurrent consume exactly one winner (asyncio.gather); regen consumes prior; recovery login creates recovery_reset (no idle refresh); promotion disables TOTP + fresh codes + invalidates siblings; stolen recovery-reset cookie alone cannot change password (current password required); password change revokes operator tokens + consumes codes; last-code login still promotes.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add recovery codes, recovery-reset sessions, and password change`.

### Task 7: Turnstile + config validation

**Files:**
- Create: `custos/operator/turnstile.py`, `tests/test_turnstile.py`
- Modify: `custos/config.py` (secret/sitekey both-or-neither + hostnames required + file forms + dev-conflict), login route (verify before credentials), status sitekey

**Interfaces:**
- Produces: `async verify_turnstile(settings, token: str | None, ip: str) -> None` (POST siteverify with secret/response/remoteip, 5s timeout; success:false/any error-code/timeout/transport → AppError turnstile_failed 422; hostname missing/mismatch → reject; audit auth.failure reason=turnstile, NO auth_events row); injected httpx client for tests. Config: both-or-neither, hostnames required when enabled, dev+enabled → ConfigError.
- Login body gains `turnstile` field; verification runs after lockout+limiter, before credentials.

- [ ] **Step 1: Failing tests**: missing token → 422 before password check (wrong password never verified — spy); already-spent error-code → 422; timeout → 422; hostname mismatch/missing → 422; valid → login proceeds; no auth_events row on turnstile failure but audit row exists; config matrix (one-of → error, hostnames missing → error, dev+enabled → error).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add Turnstile verification with fail-closed config`.

### Task 8: Step-up tokens

**Files:**
- Create: `custos/operator/stepup.py`, `tests/test_stepup.py`
- Modify: routes (POST /step-up), totp/recovery/password-change management routes (add step-up dependency)

**Interfaces:**
- Produces: `async mint_step_up(session, maker, sess_row, *, password, totp=None, recovery_code=None, kind="single") -> str` (factor set = login's; recovery alternative consumes code on success only; failures feed lockout kind step_up; token 32B b64url, SHA-256 stored, TTL 5 min, bound to session); `require_step_up(action)` dependency factory: header `x-step-up-token`, guarded consume (single kind), presenter must equal bound principal + still live; `allow_sensitive` token substitution arrives in plan 3 — dependency exposes a hook.
- Apply to: totp setup/confirm/disable, recovery regen, password-change (full sessions), passkey management (Task 9).

- [ ] **Step 1: Failing tests**: password-only when TOTP enabled → 401 + step_up row; password+TOTP → token; token single-use (second use 401 step_up_required); expired → 401; token from another session → 401; recovery alternative consumes exactly one code on success, none on failure; management route without header → 401 step_up_required; recovery_reset waiver still works for password-change only.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add step-up tokens with presenter binding`.

### Task 9: Passkeys (WebAuthn)

**Files:**
- Create: `custos/operator/passkeys.py`, `tests/test_passkeys.py`
- Modify: routes (register options/verify, list, delete, assert options/verify), config (RP_ID/origins both-or-neither + dev exception), status passkey_available

**Interfaces:**
- Produces: registration/assertion options+verify via `webauthn` library; challenges in `webauthn_challenges` (2-min TTL, guarded single-use, session-bound for register / anonymous for assert); UV required both flows; sign-count rule: reject only when stored>0 and asserted>0 and asserted≤stored; assert success → full session (Turnstile-gated when configured); management step-up-gated; unset config → 404 + passkey_available false; one-of config → ConfigError; dev exception loopback origins only.
- [ ] **Step 1: Failing tests**: use `webauthn` library's own test helpers / soft-credential fixtures (fake ES256 key, construct attestation/assertion objects programmatically — no real authenticator needed unit-level); challenge replay rejected; expired challenge rejected; counter-0 authenticator accepted twice; rollback (5→3) rejected; UV flag missing rejected; unset config 404.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add WebAuthn passkeys with single-use challenges`.

### Task 10: Device hand-off + E2E extension

**Files:**
- Create: `custos/operator/device.py`, `tests/test_device.py`
- Modify: routes (device, device/lookup, device/approve, device-exchange), `scripts/e2e.sh` (real setup + device flow replacing seed for operator paths; agent keys still seeded until plan 3), `scripts/e2e_seed.py` (drop operator relevance note)

**Interfaces:**
- Produces: mint (≥128-bit code, SHA-256 stored, 5-min TTL, ≤5 live rows/IP → 429, returns {device_code, expires_at}); lookup (session+CSRF, {client_ip, user_agent, expires_at} or 404); approve (session+CSRF, single guarded approval, extends expires_at to max(now+2min), transfer code ≥128-bit shown once); exchange (unauth bucket; increment-then-consume two guarded UPDATEs, 5 tries, window min(expires_at, approved_at+2min); full session idle 1h/absolute 12h; audited device.login all three stages).
- E2E: real POST /setup with generated code from the container's data dir; login; device mint→approve→exchange; wrong transfer code ×5 kills row; assert session works on /status.
- [ ] **Step 1: Failing tests**: full happy path; re-approve 409; 6th attempt dead; expired device/transfer windows; cross-row codes 401; flood cap; exchange session TTLs shortened; approving-session revocation doesn't undo approval.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS + `bash scripts/e2e.sh` full PASS.
- [ ] **Step 5: ocr gate + commit** `feat: add CLI device hand-off and operator-auth E2E coverage`.

---

## Self-review notes

- Spec coverage: §5 operator account fully mapped (setup T1, login T3, lockout T4, TOTP T5, recovery T6, Turnstile T7, step-up T8, passkeys T9, device T10, sessions T2). §6 auth routes spread across tasks; admin plane deliberately plan 3.
- Dependency order is strict: T1→T2→T3→T4 gates retrofit into T1/T3 routes in T4's step; T5/T6 need T3's hook; T8 retrofits gates into T5/T6 routes; T9/T10 need T2+T7+T8.
- Types: `OperatorSession` ORM row is the session principal; plan 3 consumes `require_session`, `require_step_up(action)`, `revoke_all_sessions`, `change_password`.
- E2E grows in T10 only; interim tasks rely on the httpx ASGI integration tests against real postgres.