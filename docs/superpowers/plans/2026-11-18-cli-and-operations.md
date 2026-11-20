# Rust CLI, Startup Gate, and Operations Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the `custos` Rust CLI (items, keys, tokens, env, audit, rekey, retention, break-glass), the missing startup-refusal E2E gate, the E2E assertions §11 names but no script covers, and the operator-facing README/deploy runbook — closing the five-plan series.

**Architecture:** A new `cli/` Cargo crate: `clap` command tree, `reqwest`/rustls HTTP, `tokio` runtime, and `tokio-postgres`+`argon2` used **only** by `custos account` break-glass subcommands. Auth state (session + CSRF) lives in a 0600 `session.json` under `$XDG_CONFIG_HOME/custos/`; `CUSTOS_OPERATOR_TOKEN` is the non-interactive path, never mixed with the session on one request. Two shell gates join `scripts/`: `e2e_startup.sh` (config-refusal matrix) and additions to `e2e.sh` for restore/history/rekey-verify/error-precedence. Docs are a single `README.md` plus a deploy runbook.

**Tech Stack:** Rust ≥1.82 (`clap` 4, `reqwest` 0.12 with `rustls-tls`, `serde`/`serde_json`, `tokio` 1, `tokio-postgres` 0.7, `argon2` 0.5, `rpassword` for hidden prompts); bash + python3 for the gates.

**Spec:** `docs/superpowers/specs/2026-11-17-custos-design.md` — §9 (CLI contract), §4 (break-glass DSN + Argon2 parameters), §6 (admin routes it calls), §11 (the two E2E gates and their assertion list), §13 (operations runbook). Read §9 and §13 in full before Task 1.

## Global Constraints

- **Secret values never appear in argv.** `item set` takes fields from stdin JSON or `--fields-file` (0600); `account reset-password` reads the new password from a hidden TTY prompt or stdin. Plain (non-secret) field values may use flags.
- **No `--database-url` flag.** The DSN comes from `CUSTOS_DATABASE_URL` or `--database-url-file` (0600); a DSN carrying a password must never be visible in `ps`.
- **Credential precedence (§9):** the env token serves token-permitted routes; session-only routes (mint/revoke, purge, force-drop, retention, account management) use the session file. The two are **never sent on one request**. An expired/revoked env token fails verbatim with the server's 401 — no silent fallback.
- Break-glass Argon2id output must be byte-compatible with the server verifier: **argon2id v0x13, m=65536 KiB, t=3, p=4, salt 16 rand bytes, hash 32 bytes, standard base64 PHC**. One test proves a CLI-written hash authenticates through the server's `argon2-cffi`.
- Session storage: `$XDG_CONFIG_HOME/custos/session.json` (default `~/.config/custos`), file **0600**, directory **0700**. Never log the token, CSRF value, or any secret.
- `custos env` escaping is the pinned POSIX idiom (single-quote, `'\''`), and the hazardous-name deny-set/patterns live in one place in the CLI. `--allow-hazardous-names` maps to the admin `allow_hazardous=1` query and therefore needs step-up/`allow_sensitive`.
- The CLI talks to the **existing** REST surface only; no new server routes. Where a route is session+step-up only, the CLI must fall back to interactive login exactly as §9 states.
- Shell gates run against the throwaway compose stack and exit non-zero on the first failed assertion. A gate that cannot run its checks must fail, not silently pass.
- Every commit passes `ocr review --audience agent` first; findings fixed or a false-positive reason recorded in the commit body. English messages, one logical change per commit.
- Verification per task: `cd cli && cargo test && cargo clippy -- -D warnings && cargo fmt --check` for Rust; `bash -n <script>` plus a real run for the gates; `uv run python -m pytest -q` (must stay green) for anything else.

## Review Focus

1. **A secret reaching argv or a log.** `custos item set` with a secret in `--value`, or any `dbg!`/`eprintln!` of a token, silently violates the core claim. Pinned by a test that inspects the constructed command's argv for a sentinel and by a grep-style test over `src/` for print macros near secret fields.
2. **The env-escaping corpus.** `'; cmd; echo '`, newlines, `$(…)`, backticks and a lone `'` must all round-trip through `eval` without execution — the claim in §9 that the CLI may not weaken.
3. **Break-glass hash compatibility.** A hash written by `custos account reset-password` must verify through the server's own `argon2-cffi` — a drifting parameter set locks the operator out permanently.
4. **Credential precedence.** A token must never ride a session-only route (the server 403s), and an expired token must not silently fall back to the session file.
5. **A startup refusal that silently passes.** `e2e_startup.sh` must fail if the server starts when it should refuse; a gate that reports success because a command exited 0 for an unrelated reason is worse than none.

## File Structure

| File | Responsibility |
|---|---|
| Create `cli/Cargo.toml` | Crate `custos-cli`, bin `custos`, deps as pinned above, `rustls` feature selection |
| Create `cli/src/main.rs` | `clap` tree, runtime setup, exit-code mapping |
| Create `cli/src/api.rs` | HTTP client: base URL, credential selection per route class, error → typed `CliError` |
| Create `cli/src/session.rs` | `session.json` load/save (0600, 0700), CSRF, expiry check |
| Create `cli/src/env_export.rs` | POSIX escaping + the hazardous deny-set/patterns |
| Create `cli/src/breakglass.rs` | DSN parsing (`+asyncpg` stripped), Argon2id hashing, unlock/reset-password/reset-mfa/retention SQL |
| Create `cli/src/commands/{item,key,token,audit,maintenance,account}.rs` | One module per command family |
| Create `cli/tests/env_export.rs` | Escaping corpus + hazard set (pure) |
| Create `cli/tests/session_file.rs` | File mode 0600/0700, round-trip, expiry |
| Create `cli/tests/httptest.rs` | `wiremock`-free: a tiny `std::net` stub server asserting the exact request each command sends |
| Create `cli/tests/breakglass.rs` | Argon2 PHC compatibility against a known-good vector + DSN parsing |
| Create `scripts/e2e_startup.sh` | Startup-refusal matrix |
| Modify `scripts/e2e.sh` | Add restore / history-survives-overwrite / rekey-verify / error-precedence assertions |
| Create `scripts/e2e_cli.sh` | Drives the built binary against the throwaway stack |
| Create `README.md` | Product summary, quick start, config table, security posture |
| Create `docs/operations.md` | §13 runbook: backup, keyring/pepper rotation, restore, break-glass ordering, retention cadence, reverse proxy |

---

### Task 1: Crate skeleton, session storage, and the HTTP client

**Files:**
- Create: `cli/Cargo.toml`, `cli/src/main.rs`, `cli/src/api.rs`, `cli/src/session.rs`
- Create: `cli/tests/session_file.rs`
- Modify: `.gitignore` (`cli/target/`), `.dockerignore`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `session::Session { base_url: String, cookie: String, csrf: String, expires_at: OffsetDateTime }`
  - `session::load() -> Result<Option<Session>, CliError>`, `session::save(&Session) -> Result<PathBuf, CliError>`, `session::clear() -> Result<(), CliError>`
  - `session::session_path() -> Result<PathBuf, CliError>` honouring `XDG_CONFIG_HOME`
  - `api::Credentials { EnvToken(String), Session(Session) }`
  - `api::RouteClass { TokenPermitted, SessionOnly }`
  - `api::Client::new(base_url, creds)`, `async fn get/post/put/patch/delete(&self, class, path, body: Option<Value>, step_up: Option<&str>) -> Result<Value, CliError>`
  - `CliError` enum: `Config(String)`, `Auth(String)`, `Server { status: u16, code: String, message: String }`, `Io(std::io::Error)`, `Network(String)`; `Display` never carries a secret.
  - `main.rs` global flags: `--url` (default `CUSTOS_URL`), `--json`, and `CUSTOS_OPERATOR_TOKEN` detection.

- [ ] **Step 1: Write the failing tests** — `cli/tests/session_file.rs` (uses `tempfile` + `XDG_CONFIG_HOME` override):

```rust
#[test]
fn save_creates_a_0600_file_in_a_0700_dir() { ... }   // assert perms via MetadataExt::mode() & 0o777
#[test]
fn load_round_trips_and_reports_expiry() { ... }       // expired session loads but is_expired() true
#[test]
fn clear_removes_the_file_but_not_the_dir() { ... }
#[test]
fn an_env_token_is_never_persisted() { ... }           // save() only ever writes session data
```

- [ ] **Step 2: Run to verify failure** — `cd cli && cargo test` → compile error (no crate).
- [ ] **Step 3: Scaffold the crate** — `Cargo.toml` (`clap` derive, `reqwest` with `rustls-tls`+`json`+`cookies` off — the CLI manages the cookie itself, `serde`, `serde_json`, `tokio`, `thiserror`, `time`, `dirs`), `main.rs` with the `clap` tree and a `CliError` → exit-code map (2 config, 3 auth, 1 other), and `session.rs` writing 0600/0700 (create the dir with `0o700`, the file with `0o600` before writing, never `chmod` after the secret is on disk).
- [ ] **Step 4: Implement `api.rs`** — the client stores `Credentials`; `request()` picks the credential by `RouteClass` (a `SessionOnly` call with only an env token returns `CliError::Auth` naming the fix, never a request), attaches `x-csrf-token` from the session on mutations, attaches `x-step-up-token` when given, and maps a non-2xx body `{code,message}` to `CliError::Server` verbatim (§9: an expired token surfaces the server's 401 unchanged).
- [ ] **Step 5: Verify** — `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `uv run python -m pytest -q` unchanged.
- [ ] **Step 6: ocr gate + commit** — `feat: rust cli skeleton with session storage and credential selection`.

### Task 2: `custos item` + `custos env`

**Files:**
- Create: `cli/src/commands/item.rs`, `cli/src/env_export.rs`, `cli/tests/env_export.rs`, `cli/tests/httptest.rs`
- Modify: `cli/src/main.rs`

**Interfaces:**
- Consumes: `api::Client`, `api::RouteClass`.
- Produces:
  - `env_export::escape(value: &str) -> String` (POSIX `'\''` idiom), `env_export::is_hazardous(name: &str) -> bool` (the §9 deny-set + `LD_*`/`DYLD_*`/`*_OPT`/`*_OPTIONS`/`PYTHON*`).
  - `commands::item::{list, get, set, rm, restore, purge, force_drop, history}`; `set` reads a fields JSON array from stdin or `--fields-file`, **never** from a flag.
  - `commands::env::run(name, allow_hazardous: bool)` → prints the server's text, and warns on stderr when a `# refused hazardous name:` line is present.
  - `CliError::SecretInArgv` — returned when any secret-bearing flag is used.

- [ ] **Step 1: Write the failing tests:**

```rust
// cli/tests/env_export.rs — the escaping corpus (pure, no network)
#[test] fn escapes_the_posix_way() { ... }             // a'b -> 'a'\''b'
#[test] fn hostile_values_do_not_execute() { ... }      // spawn `bash -c "eval <out>; printf %s $V"`
#[test] fn hazardous_names_are_refused() { ... }        // PATH, LD_PRELOAD, NODE_OPTIONS, PYTHONPATH, BAKE_OPT
#[test] fn ordinary_names_pass() { ... }                // API_KEY, DB_URL, TOKEN_2
```

- [ ] **Step 2: Verify failure** — `cargo test` → missing symbols.
- [ ] **Step 3: Implement `env_export` + `commands::item`** — `set` accepts only `--fields-file`/stdin; the command builder is a pure function `item_set_request(name, fields) -> Value` so the test can assert its argv-free shape.
- [ ] **Step 4: Write the request-shape test** — `cli/tests/httptest.rs` spins a `std::net::TcpListener` on port 0, reads one request, asserts method/path/headers/body, and replies with a canned response. Cover: `item get --reveal` sends `x-step-up-token` and hits `/reveal`; `item purge` is `SessionOnly`; `item list` paginates with `cursor`.
- [ ] **Step 5: Verify** — `cargo test`, clippy, fmt.
- [ ] **Step 6: ocr gate + commit** — `feat: cli item and env commands with eval-safe escaping`.

### Task 3: `custos key`, `custos token`, `custos audit`, `custos rekey`, `custos retention`

**Files:**
- Create: `cli/src/commands/{key,token,audit,maintenance}.rs`
- Modify: `cli/src/main.rs`, `cli/tests/httptest.rs`

**Interfaces:**
- Consumes: `api::Client`, `RouteClass::SessionOnly` for every mint/revoke.
- Produces:
  - `key mint --label --mode --scope… [--expires]` (repeated `--scope`), `key ls`, `key revoke <key_id>`
  - `token mint --label --expires [--allow-sensitive]`, `token ls`, `token revoke`
  - `audit [--actor] [--item] [--action] [--from] [--to]` printing a table or `--json`
  - `rekey [--verify] [--audit]` — loops batches until `remaining == 0`, exits non-zero when any batch reported `skipped > 0`, then runs one final `GET /rekey/audit` and reports leftovers (§13's removal gate)
  - `retention` — session+step-up; prints the per-table counts
  - Interactive step-up helper: prompts password, then TOTP **or** recovery code, returning a token; used by every gated command.

- [ ] **Step 1: Write the failing tests** in `httptest.rs`:

```rust
#[test] fn key_mint_is_session_only_and_sends_step_up() { ... }
#[test] fn token_mint_requires_an_expiry() { ... }        // clap rejects a missing --expires
#[test] fn rekey_loops_until_remaining_zero() { ... }     // stub replies 200/200/0, asserts 3 calls + cursor echo
#[test] fn rekey_exits_nonzero_on_skipped() { ... }       // stub replies skipped:2
#[test] fn audit_builds_only_the_given_filters() { ... }
```

- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement** — one `step_up()` helper; `rekey`'s loop carries `run_token` across calls and passes `cursor` in the body.
- [ ] **Step 4: Verify** — cargo test/clippy/fmt; `uv run python -m pytest -q` unchanged.
- [ ] **Step 5: ocr gate + commit** — `feat: cli key, token, audit, rekey and retention commands`.

### Task 4: Break-glass (`custos account`)

**Files:**
- Create: `cli/src/breakglass.rs`, `cli/src/commands/account.rs`, `cli/tests/breakglass.rs`
- Modify: `cli/src/main.rs`

**Interfaces:**
- Consumes: nothing from `api.rs` (this path never talks HTTP).
- Produces:
  - `breakglass::strip_driver(dsn: &str) -> String` — removes `+asyncpg`
  - `breakglass::hash_password(plain: &str) -> String` — argon2id v0x13, m=65536, t=3, p=4, salt 16, out 32, PHC base64
  - `commands::account::{unlock, reset_password, reset_mfa, retention}`; `reset_password`/`reset_mfa`/`retention` follow §9's exact SQL effects (invalidate sessions/step-ups, revoke operator tokens, consume recovery codes; `reset-mfa` writes exactly three audit rows).

- [ ] **Step 1: Write the failing tests:**

```rust
#[test] fn strips_the_asyncpg_marker() { ... }            // postgresql+asyncpg:// -> postgresql://
#[test] fn phc_matches_the_server_parameters() { ... }    // parse $argon2id$v=19$m=65536,t=3,p=4$
#[test] fn a_cli_hash_verifies_under_argon2_cffi() { ... }// skip-if-python-absent; runs a python3 one-liner
#[test] fn a_missing_dsn_is_a_config_error() { ... }
```

- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement** — `tokio-postgres` connect from the DSN; every mutation in one transaction; audit rows written directly (`local_process`/`"local"`, matching the server's closed enums); the new password read from a hidden TTY prompt (`rpassword`) or stdin, **never** a flag.
- [ ] **Step 4: Verify** — cargo test/clippy/fmt.
- [ ] **Step 5: ocr gate + commit** — `feat: cli break-glass account commands`.

### Task 5: `scripts/e2e_startup.sh` + the E2E assertions §11 names

**Files:**
- Create: `scripts/e2e_startup.sh`
- Modify: `scripts/e2e.sh`

**Interfaces:**
- Consumes: the compose stack pattern from `scripts/e2e.sh`.
- Produces: two gates. `e2e_startup.sh` asserts the server **refuses to start** for each misconfiguration, and **starts** for the matching valid one: non-loopback bind without `CUSTOS_PUBLIC_BIND=1`; dev mode with a non-loopback bind; dev mode with Turnstile configured; both keyring forms; both pepper forms; a malformed/`/0` trusted proxy; a missing trusted-proxy list with `PUBLIC_BIND=1`; exactly one of the WebAuthn pair; an all-zero pepper; a short setup code; `CUSTOS_RETENTION_DAYS=6`. `e2e.sh` gains: restore recovers a soft-deleted item to agents; history survives a field overwrite **and** an item soft-delete; `rekey --verify` detects newest-version corruption; error precedence (`step_up_required` beats `key_unavailable`); the four item caps each yield 413 over HTTP; the history ceiling yields 429.

- [ ] **Step 1: Write the failing gate** — `scripts/e2e_startup.sh` as a table (`REFUSAL` / `ACCEPT`), each case a compose `run` with an env overlay, asserting on the exit code **and** the absence of a listening port.
- [ ] **Step 2: Verify it fails** — run it; the first case that the current build accepts-but-should-refuse (or vice versa) fails loudly.
- [ ] **Step 3: Fix the gaps the gate exposes.** Where the server already refuses correctly the case passes; a case that fails is a real startup-validation bug — fix it in `custos/config.py` with a unit test, not by weakening the gate.
- [ ] **Step 4: Extend `e2e.sh`** with the assertions above, each printing a named `CHECK`.
- [ ] **Step 5: Run both** — `bash scripts/e2e_startup.sh` and `bash scripts/e2e.sh` → PASS.
- [ ] **Step 6: ocr gate + commit** — `test: startup refusal gate and the remaining E2E assertions`.

### Task 6: CLI E2E, README, and the operations runbook

**Files:**
- Create: `scripts/e2e_cli.sh`, `README.md`, `docs/operations.md`
- Modify: `.github`-free: none (no CI config in this repo)

**Interfaces:**
- Consumes: the built `custos` binary and the throwaway stack.
- Produces: `scripts/e2e_cli.sh` exercising **the real binary**: `login` (direct flow, then device hand-off when a sitekey is configured), `item set` from stdin, `item get` masked then `--reveal`, `env` printing a hostile value that survives `eval`, `key mint` → use the token for `item list` → `key revoke` → the token 401s, `token mint` refused without an interactive session when only an env token is present, `audit` showing the mint rows, `rekey` looping to zero, and `account unlock` against the direct DB plus `account reset-password` whose hash the server accepts (log in with the new password through the API).

- [ ] **Step 1: Write the failing gate** — `scripts/e2e_cli.sh` with named checks, failing on the first one.
- [ ] **Step 2: Verify it fails** — no binary in the image yet → the gate fails on "binary missing".
- [ ] **Step 3: Ship the binary in the image** — add a `cli-build` stage to `deploy/Dockerfile` (`rust:1-slim` → `cargo build --release`, copy to `/app/bin/custos`), and make `e2e_cli.sh` run it inside the app container (same network as the server).
- [ ] **Step 4: Write `README.md`** — what Custos is, the two-plane model, quick start (compose + setup code + first key), config table (pointing at `.env.example`), the security posture in five lines, and where the runbook lives. No hostnames, no personal paths.
- [ ] **Step 5: Write `docs/operations.md`** — the §13 content as operator steps: backup unit and cadence, keyring rotation with the `rekey` + audit gate, restore (including the mandatory post-restore credential reset), pepper rotation, break-glass ordering, retention cadence, reverse-proxy note.
- [ ] **Step 6: Run everything** — `scripts/e2e_cli.sh`, `scripts/e2e.sh`, `scripts/e2e_startup.sh`, `scripts/e2e_console.sh`, `uv run python -m pytest -q`, `cargo test` + clippy + fmt.
- [ ] **Step 7: ocr gate + commit** — `feat: cli e2e gate, README, and operations runbook`.

---

## Self-review notes

- Spec coverage: §9 CLI surface → Tasks 1–4 (every subcommand named in §9 has a task); §4 break-glass parameters → Task 4; §11's `e2e_startup.sh` and the missing `e2e.sh` assertions → Task 5; §13 → Task 6's runbook; §9's `custos env` claim → Task 2's corpus.
- Deliberately out of scope: OS keychain integration (§9 says "file fallback" and v1 has no keychain crate pinned — the file path is the shipped behaviour, stated in the runbook), and WebAuthn assertion from the CLI (§9 lists passkeys as a console/browser concern).
- The `README.md` is a new top-level artifact; it must stay publishable (no internal URLs, no hostnames).
- Plan is deliberately shorter than the spec: the CLI is a thin client, so its plan is the command table plus the invariants it must not break.