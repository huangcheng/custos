# Operator Console + MCP Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the React operator console served same-origin at `/` (login/setup/device, items, keys, audit, settings) with the shared design system, and the `npx custos-mcp` stdio wrapper exposing the same seven tools as the remote `/mcp` surface.

**Architecture:** New `console/` Vite + React SPA (TypeScript, no router library — a tiny path switch) that talks only to the existing REST API with the session cookie plus in-memory CSRF; FastAPI serves `console/dist` as static files with the §3 cache/CSP contract and an SPA fallback. Separately, `mcp/` is a standalone Node package (`custos-mcp` bin) that speaks stdio MCP to the client and REST to `CUSTOS_URL` with `CUSTOS_AGENT_KEY`.

**Tech Stack:** React 19 + Vite 7 + TypeScript 5 (console); Node ≥22 + `@modelcontextprotocol/sdk` (wrapper); Python 3.12 FastAPI StaticFiles (serving); Playwright-free browser E2E via the operator's `ego-browser` for the final gate.

**Spec:** `docs/superpowers/specs/2026-11-17-custos-design.md` — §§3 (browser hardening), 6 (REST contracts), 7 (MCP surface), 8 (console screens). Read §3 and §8 in full before Task 1.

## Global Constraints

- Everything the console renders is plain text (`textContent`/JSX children) — never `dangerouslySetInnerHTML`, never markdown-to-HTML of agent-authored content (§3).
- Console never stores credentials outside the session cookie; the CSRF token lives **in module memory only** (never localStorage/sessionStorage/IndexedDB) and is re-obtained from `GET /api/auth/status` after a reload (§3).
- No CORS headers, no service worker, no inline scripts. CSP is served by the app (§3 pinned string); inline **style attributes** are allowed, inline scripts are not.
- Static asset contract: hashed Vite assets → `Cache-Control: public, max-age=31536000, immutable`; the SPA shell `index.html` → `no-store`. The exemption matches static paths only, never `/api/*` or `/mcp`.
- Console mutations: `x-csrf-token` header on every non-GET; step-up via `x-step-up-token` obtained from `POST /api/auth/step-up` (password, plus TOTP when enabled — the console prompts for both when `status.totp_required`).
- Item writes from the console always send `If-Match: "<revision>"` (§4: the console always sends If-Match).
- Admin write responses are masked — the console seeds its edit drawer from its own submitted form state, never from a write response (§6).
- The wrapper logs **nothing** about tool arguments, results, or raw bodies (§7); it exposes exactly the seven tools of §7 and no admin surface.
- Wrapper credential: `CUSTOS_URL` + `CUSTOS_AGENT_KEY` (or `--url`/`--key`), read once at startup; a non-2xx or non-JSON response becomes a tool error carrying the server's `{code, message}` only.
- No new Python dependencies. Console dependencies limited to React, React DOM, Vite, TypeScript, `@vitejs/plugin-react`, and the Geist font packages (per DESIGN.md). Wrapper dependencies limited to the official MCP SDK.
- Node ≥22 for both `console/` and `mcp/` (`package.json` `engines`).
- Every commit passes `ocr review --audience agent` first; findings fixed or a false-positive reason recorded in the commit body. English messages, one logical change per commit.
- Verification per task: `cd console && npm run build` (includes `tsc --noEmit`) for console tasks, `cd mcp && npm test` for wrapper tasks, `uv run python -m pytest -q` + `uv run ruff check .` + `uv run mypy` for Python-touching tasks.

## Review Focus

1. **A secret reaching the DOM without a step-up.** Revealing a field must require the step-up round-trip; the masked shapes the API returns must render as `••••` with no value in the DOM (assert the revealed value string is absent from `document.body.textContent` before the gate).
2. **CSRF dropped after a reload.** After `location.reload()`, the first mutation must still succeed because `auth/status` re-supplies the token; a mutation with a stale in-memory token must get 401 and the app must recover, not loop.
3. **Static serving swallowing the API.** A request to `/api/does-not-exist` must 404 as JSON (never the SPA shell), and `/mcp` must keep working while `/` serves HTML — a bad catch-all breaks either the API contract or the MCP transport.
4. **Device hand-off friction.** `/device#<code>` must strip the fragment immediately and never render the code in the page body or a `Referer`-capable URL.
5. **Wrapper leaking credentials or data in errors.** A 401 from the API must produce a tool error mentioning only the server `code`, and the wrapper must never write the key or a body to stdout/stderr.

## File Structure

| File | Responsibility |
|---|---|
| Create `console/package.json` | Vite/React/TS deps, `build`/`dev`/`typecheck` scripts, node engines |
| Create `console/vite.config.ts` | React plugin, dev proxy `/api` + `/mcp` → `CUSTOS_DEV_URL` (default `http://127.0.0.1:8300`), `build.outDir=dist` |
| Create `console/tsconfig.json` | Strict TS, `jsx: react-jsx`, DOM libs |
| Create `console/index.html` | SPA shell (single `<div id="root">`, module script) |
| Create `console/src/main.tsx` | Mount, global stylesheet import |
| Create `console/src/style.css` | Semantic variables per DESIGN.md (deep-ink frame, cool-gray workspace, chartreuse accent), layout, focus rings, reduced motion |
| Create `console/src/api.ts` | Typed fetch wrapper: in-memory CSRF, 401→`/api/auth/status` recovery, `ApiError`, step-up helper, `If-Match` support |
| Create `console/src/types.ts` | API response types (item, key, token, audit row, status) |
| Create `console/src/App.tsx` | Bootstrap (`auth/status`), path switch, chrome (sidebar + workspace) |
| Create `console/src/screens/Login.tsx` | Setup wizard, password+TOTP login, passkey button, recovery fallback, Turnstile widget hook |
| Create `console/src/screens/Device.tsx` | Fragment strip, lookup, approve, transfer-code display |
| Create `console/src/screens/Items.tsx` | Inventory table/cards, drawer, reveal, edit, delete/restore, history |
| Create `console/src/screens/Keys.tsx` | Mint wizard, one-time token display, inventory + revoke |
| Create `console/src/screens/Audit.tsx` | Filterable audit log with cursor paging |
| Create `console/src/screens/Settings.tsx` | Password change, TOTP, recovery codes, passkeys, operator tokens, retention/rekey |
| Create `console/src/components/*.tsx` | `Drawer`, `ConfirmStepUp`, `Field`, `Button`, `Table` primitives |
| Create `console/src/plain.ts` | Assertion helper used by tests: render-without-HTML contract note + `escape`-free text helpers |
| Modify `custos/app.py` | Static mounting, SPA fallback, CSP + cache headers per path class |
| Create `custos/console.py` | `mount_console(app, settings)` — dist discovery, index fallback, asset cache policy |
| Create `mcp/package.json` | `custos-mcp` bin, MCP SDK dep, `test` script |
| Create `mcp/src/index.js` | stdio server, seven tools, REST calls, error mapping |
| Create `mcp/src/tools.js` | Tool schema table (pure, unit-tested) + request builders |
| Create `mcp/src/http.js` | `request()` — fetch with bearer, JSON/error normalization, no logging |
| Create `mcp/test/tools.test.js` | Schema/builder/error-mapping unit tests (node:test) |
| Create `mcp/README.md` | Install + config (`npx custos-mcp`, env vars) |
| Modify `deploy/Dockerfile` | Multi-stage: node build for `console/dist` + `mcp/`, copy dist into the image |
| Modify `.gitignore` | `console/node_modules`, `console/dist`, `mcp/node_modules` |
| Modify `scripts/e2e_console.sh` | New: browser E2E through the built console (uses the operator's browser driver) |

---

### Task 1: Console scaffold + static serving contract

**Files:**
- Create: `console/package.json`, `console/vite.config.ts`, `console/tsconfig.json`, `console/index.html`, `console/src/main.tsx`, `console/src/style.css`, `console/src/App.tsx`, `console/src/types.ts`, `console/src/api.ts`
- Create: `custos/console.py`
- Modify: `custos/app.py` (mount console after routers), `.gitignore`
- Test: `tests/test_console_serving.py`

**Interfaces:**
- Consumes: `create_app(settings)` (existing), `settings.data_dir`.
- Produces:
  - `custos/console.py`: `console_dist_dir() -> Path | None` (resolves `<repo>/console/dist`; env override `CUSTOS_CONSOLE_DIST` for tests; `None` when absent) and `mount_console(app: FastAPI, settings: Settings) -> None` which (a) mounts `/assets` → `StaticFiles(directory=<dist>/assets)` with the immutable cache header, (b) serves `GET /` and any non-API, non-`/mcp`, non-`/healthz` path with `index.html` and `Cache-Control: no-store`, (c) returns JSON 404 (`{"code":"not_found", …}`) for unmatched `/api/*`, and (d) adds the §3 CSP header to HTML responses.
  - `console/src/api.ts`: `setCsrf(token: string): void`, `getCsrf(): string`, `ApiError {status, code, message}`, `api<T>(method, path, body?, opts?: {ifMatch?: string; stepUpToken?: string}): Promise<T>`, `refreshCsrf(): Promise<void>` (calls `/api/auth/status` and stores the token), `stepUp(password: string, totp?: string): Promise<string>`.
  - `console/src/types.ts`: `AuthStatus {setup_required, totp_required, turnstile_sitekey, passkey_available, csrf_token?}`, `Item`, `ItemList`, `HistoryRow`, `KeyRow`, `TokenRow`, `AuditRow`.

- [ ] **Step 1: Write the failing test** — `tests/test_console_serving.py` (pytest, no browser):

```python
def test_console_absent_is_404(tmp_path): ...     # CUSTOS_CONSOLE_DIST pointing at nothing → GET / is JSON 404, /healthz ok
def test_index_shell_and_assets_headers(tmp_path, console_dist): ...
    # GET / → 200 text/html + "no-store" + CSP header containing "frame-ancestors 'none'"
    # GET /assets/app-abc123.js → 200 + "max-age=31536000" + "immutable"
def test_spa_fallback_serves_shell(tmp_path, console_dist): ...  # GET /items → 200 text/html (shell)
def test_api_404_stays_json(tmp_path, console_dist): ...          # GET /api/nope → 404 application/json, code "not_found"
def test_mcp_and_healthz_not_swallowed(tmp_path, console_dist): ...# /healthz → {"status":"ok"}; /mcp unauthenticated → 401 (not HTML)
```

`console_dist` fixture writes a fake `dist/` (an `index.html` with a sentinel and `assets/app-abc123.js`) into `tmp_path` — no Vite build in the unit test.

- [ ] **Step 2: Run to verify failure** — `uv run python -m pytest tests/test_console_serving.py -q` → ImportError (`custos.console`).
- [ ] **Step 3: Scaffold the console package** — `package.json` (react 19, vite 7, typescript 5, `@vitejs/plugin-react`, `@fontsource-variable/geist{,-mono}`), `tsconfig.json` (strict), `vite.config.ts` (proxy `/api` and `/mcp` to `CUSTOS_DEV_URL ?? "http://127.0.0.1:8300"`), `index.html`, `main.tsx`, `style.css` with the DESIGN.md semantic variables (`--ink`, `--workspace`, `--surface`, `--accent` chartreuse, `--danger`, `--text`, `--text-dim`, focus ring, `@media (prefers-reduced-motion: reduce)`), `types.ts`, and `api.ts` (module-level `let csrf`, `refreshCsrf`, `stepUp`, `api<T>` that sets `x-csrf-token` on non-GET, unwraps `{code,message}` into `ApiError`, and on 401 calls `refreshCsrf()` once then retries).
- [ ] **Step 4: Implement `custos/console.py` + mount** — order matters: static mount and the fallback route must be registered **after** the API/MCP routers; the fallback must skip `api/`, `mcp`, `healthz`, and `docs`/`openapi.json`. Implement `cache` headers per path class and the CSP constant exactly as §3 states.
- [ ] **Step 5: Run tests + build** — `uv run python -m pytest tests/test_console_serving.py -q` green; `cd console && npm install && npm run build` succeeds and produces `dist/index.html`; full suite `uv run python -m pytest -q`; `uv run ruff check .`; `uv run mypy`.
- [ ] **Step 6: ocr gate + commit** — `feat: console scaffold with the static serving contract`.

### Task 2: Login, setup wizard, device hand-off

**Files:**
- Create: `console/src/screens/Login.tsx`, `console/src/screens/Device.tsx`, `console/src/components/Button.tsx`, `console/src/components/Field.tsx`
- Modify: `console/src/App.tsx` (route `/` → Login when unauthenticated, `/device` → Device)
- Test: `console/test/login.test.ts` (node:test on pure logic) + assertions pinned in the E2E script of Task 6

**Interfaces:**
- Consumes: `api`, `refreshCsrf`, `AuthStatus`.
- Produces:
  - `loginPayload(username, password, totp?, recoveryCode?, turnstile?) -> object` — returns `{username, password}` plus **at most one** of `totp`/`recovery_code` (never both; throwing a client error if both are provided).
  - `deviceCodeFromHash(hash: string) -> string | null` — parses `#<code>`, returns null when absent/empty, never mutates.
  - `maskedTransferCode(code: string) -> string` — groups a transfer code for display without altering the value sent.
  - `<Turnstile sitekey>` — a component that injects the Cloudflare script **only when `sitekey` is non-null**, calls back with the token, and renders nothing otherwise (no third-party request when Turnstile is unconfigured).

- [ ] **Step 1: Write the failing tests** — `console/test/login.test.ts`:

```js
test("loginPayload never sends both TOTP and recovery code", ...)   // throws on both
test("loginPayload omits empty factors", ...)                       // {username,password} only
test("deviceCodeFromHash parses and rejects", ...)                  // "#abc" → "abc"; "#" → null
test("Turnstile renders nothing without a sitekey", ...)            // no <script> appended
```

- [ ] **Step 2: Verify failure** — `cd console && npm test` → module not found.
- [ ] **Step 3: Implement the screens** — Login renders the setup wizard when `status.setup_required` (fields: username, password, setup code from the 0600 file), otherwise the credential form (password, TOTP input when `status.totp_required`, passkey button when `passkey_available` — button calls `/api/auth/passkeys/assert/options` then `/assert/verify` via `navigator.credentials.get`, recovery-code toggle, Turnstile when configured). On success call `refreshCsrf()` and hand control to the app. Device strips the fragment with `history.replaceState` **before** any await, looks up the code, shows `client_ip`/`user_agent`, and on approve displays the transfer code with the deadline.
- [ ] **Step 4: Verify** — `npm test`, `npm run build`, full pytest suite.
- [ ] **Step 5: ocr gate + commit** — `feat: console login, setup wizard, and device hand-off`.

### Task 3: Items screen (inventory, drawer, reveal, edit, history)

**Files:**
- Create: `console/src/screens/Items.tsx`, `console/src/components/Drawer.tsx`, `console/src/components/ConfirmStepUp.tsx`
- Modify: `console/src/App.tsx` (route `/items`)
- Test: `console/test/items.test.ts`

**Interfaces:**
- Consumes: `api`, `stepUp`, `ItemList`, `Item`, `HistoryRow`.
- Produces:
  - `itemEditBody(form) -> {notes, fields: [{name, secret, value}]}` — **omits `value` for a secret field the operator did not change** (that is what makes a masked round-trip safe) and always includes `notes` (§6: required on PUT).
  - `fieldDisplay(field) -> {label, shown}` — `shown` is `"••••••"` for a secret field until reveal ran, the plain value otherwise.
  - `historyLabel(row) -> string` — field name + superseded timestamp, no value.
  - `<ConfirmStepUp onToken>` — modal that asks for the password (and TOTP when `status.totp_required`) and returns a step-up token.

- [ ] **Step 1: Write the failing tests:**

```js
test("itemEditBody omits unchanged secret values", ...)  // keeps {name, secret:true} without value
test("itemEditBody includes notes always", ...)          // required by PUT
test("fieldDisplay masks secrets until revealed", ...)   // "••••••" and no value in the output
```

- [ ] **Step 2: Verify failure** — `npm test`.
- [ ] **Step 3: Implement** — table on wide screens (name, field count, revision, updated), cards under 720px; drawer with a dark identity header; reveal button per secret field issuing a **fresh** step-up (one token per reveal call); edit form seeded from the fetched masked item and the operator's own input (never from a write response); delete/restore with confirmation; history list with per-snapshot reveal.
- [ ] **Step 4: Verify** — `npm test`, `npm run build`, full pytest suite.
- [ ] **Step 5: ocr gate + commit** — `feat: console items screen with gated reveal and history`.

### Task 4: Keys, Audit, Settings screens

**Files:**
- Create: `console/src/screens/Keys.tsx`, `console/src/screens/Audit.tsx`, `console/src/screens/Settings.tsx`
- Modify: `console/src/App.tsx` (routes `/keys`, `/audit`, `/settings`)
- Test: `console/test/keys.test.ts`

**Interfaces:**
- Consumes: `api`, `stepUp`, `KeyRow`, `TokenRow`, `AuditRow`.
- Produces:
  - `mintKeyBody(form) -> {label, mode, scopes, expires_at?}` — splits a comma/space separated scope string into an array, rejects an empty label, and omits `expires_at` when blank.
  - `auditQuery(filters) -> string` — builds a query string with only the non-empty filters (`actor`, `action`, `item`, `from`, `to`) and `limit`.
  - `scopeSummary(key) -> string` — `"*"` when the key has the wildcard, `"no access"` when empty, otherwise the joined list.

- [ ] **Step 1: Write the failing tests:**

```js
test("mintKeyBody splits scopes and omits blank expiry", ...)
test("auditQuery only includes non-empty filters", ...)
test("scopeSummary handles wildcard and empty", ...)
```

- [ ] **Step 2: Verify failure** — `npm test`.
- [ ] **Step 3: Implement** — Keys: mint wizard (label/mode/scopes/expiry, step-up before submit), one-time token panel with a copy button and an explicit "this is the only time you will see it" warning, inventory with revoke (step-up). Audit: filter bar + cursor-paged table rendering actor/action/item/time/ok/detail, using the server's `next_cursor`. Settings: password change, TOTP setup (QR from the provisioning URI rendered as text + a `<canvas>`-free approach — show the URI and the secret, not an image), recovery codes shown once, passkeys list/register/remove, operator tokens mint/list/revoke, retention and rekey buttons with step-up and result counts.
- [ ] **Step 4: Verify** — `npm test`, `npm run build`, full pytest suite.
- [ ] **Step 5: ocr gate + commit** — `feat: console keys, audit, and settings screens`.

### Task 5: stdio MCP wrapper (`npx custos-mcp`)

**Files:**
- Create: `mcp/package.json`, `mcp/README.md`, `mcp/src/index.js`, `mcp/src/tools.js`, `mcp/src/http.js`, `mcp/test/tools.test.js`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: the agent REST plane (§6) only.
- Produces:
  - `mcp/src/tools.js`: `TOOLS` — the §7 table as data: `{name, description, inputSchema, build(args) -> {method, path, query?, body?}}` for all seven tools (`custos_list_items`, `custos_get_item`, `custos_search`, `custos_put_item`, `custos_patch_item`, `custos_delete_item`, `custos_env`).
  - `mcp/src/http.js`: `createClient({url, key, fetchImpl})` → `{ request(method, path, {query, body}): Promise<{ok, status, data, text}> }` — sets `Authorization: Bearer <key>`, `Accept: application/json`, never logs, and never includes the key in a thrown error.
  - `mcp/src/index.js`: reads `CUSTOS_URL` + `CUSTOS_AGENT_KEY` (or `--url`/`--key`), exits 2 with a one-line usage message when either is missing, registers all seven tools on `McpServer`, maps a successful REST response to a tool result (`content: [{type:"text", text}]`, `isError:false`) and a failure to `isError:true` with **only** the server's `{code, message}`.

- [ ] **Step 1: Write the failing tests** — `mcp/test/tools.test.js` (node:test):

```js
test("exports exactly the seven spec tools", ...)              // deepEqual on sorted names
test("put_item builds an upsert with optional if_match", ...)   // /api/items/<name>?upsert=1 + If-Match
test("env encodes the name and passes no allow_hazardous", ...) // no override on the agent plane
test("list/search forward cursor and limit", ...)               // query string built correctly
test("error mapping keeps only code and message", ...)          // key never in the message
```

- [ ] **Step 2: Verify failure** — `cd mcp && npm test` → cannot find module.
- [ ] **Step 3: Implement** — `tools.js` (pure data + builders), `http.js` (`fetch`, bearer, error normalization to `{code, message}` with status), `index.js` (SDK wiring, stdio transport, no logging), `README.md` (env vars, `npx` usage, the note that admin tools are deliberately absent).
- [ ] **Step 4: Verify against the dev stack** — start a key through the API, run the wrapper with `CUSTOS_URL`/`CUSTOS_AGENT_KEY`, and drive it with a tiny stdio client script inside the test (spawn `node src/index.js`, send `initialize` + `tools/list` + one `custos_env` call, assert the result). `npm test` green.
- [ ] **Step 5: ocr gate + commit** — `feat: stdio MCP wrapper exposing the seven agent tools`.

### Task 6: Container build + browser E2E gate

**Files:**
- Modify: `deploy/Dockerfile` (node stage builds `console/dist` and `mcp/`; runtime image copies dist and points `CUSTOS_CONSOLE_DIST` at it), `.dockerignore`
- Create: `scripts/e2e_console.sh`
- Test: `scripts/e2e_console.sh` itself is the gate

**Interfaces:**
- Consumes: everything above.
- Produces: `scripts/e2e_console.sh` — brings up the compose stack (same pattern as `scripts/e2e.sh`), then drives the **built console** in a real browser through the operator's browser driver: login → items list renders masked → reveal requires step-up and the value appears only after it → create/edit with If-Match → delete/restore → keys mint (token shown once) → audit shows the mint row → settings password change → reload and mutate (CSRF recovery) → device hand-off page strips the fragment. Exits non-zero on the first failed assertion, printing which check failed.

- [ ] **Step 1: Write the failing gate** — `scripts/e2e_console.sh` with the checks above in order, each printing `CHECK <n>: <name>` and failing loudly.
- [ ] **Step 2: Verify it fails** — run it against the current image (no console in the container) → the first console check fails.
- [ ] **Step 3: Implement the container changes** — multi-stage Dockerfile: stage `console-build` (`node:22-alpine`, `npm ci && npm run build`), stage `mcp-build` (`npm ci --omit=dev`), runtime stage copies `console/dist` to `/app/console/dist` and `mcp/` to `/app/mcp`, sets `CUSTOS_CONSOLE_DIST=/app/console/dist`. Keep the non-root uid, pinned uv, `ENTRYPOINT []`, and the HEALTHCHECK as they are.
- [ ] **Step 4: Run the gate** — `bash scripts/e2e_console.sh` → every check passes; then `bash scripts/e2e.sh` still passes (no regression in the API/MCP gate).
- [ ] **Step 5: ocr gate + commit** — `feat: console in the container with a browser E2E gate`.

---

## Self-review notes

- Spec coverage: §8 screens → Tasks 2–4; §3 hardening (CSP, cache classes, no CORS, plain-text rendering, no service worker) → Task 1 + Review Focus 1; §7 wrapper → Task 5; container/E2E → Task 6. Deploy topology and CLI are plan 5.
- Interfaces: `api.ts` names are used unchanged by Tasks 2–4; `TOOLS` is the single source for both the schema test and the server registration.
- Deliberately out of scope: passkey registration UI polish beyond list/register/remove (Task 4), QR image rendering for TOTP (URI + secret text instead of an image — no new dependency), and any admin-plane MCP tool (§7 forbids it).
- The console E2E uses the operator's browser driver at execution time; the plan pins the assertions, not the driver API.