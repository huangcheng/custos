# Custos ↔ sibling-pattern alignment (Janus, Portunus)

Date: 2026-11-18. Scope: compare the design of record
(`../specs/2026-11-17-custos-design.md`, rev 36) and the implemented code
against the proven patterns of the two sibling projects, per AGENTS.md
("copy the pattern, keep repos independent"). Every claim below was verified
against sibling source, not memory. This note records decisions; it does not
change the design — deliberate divergences stay pinned in the spec.

## Legend

- **Aligned** — Custos already follows the sibling pattern.
- **Fixed** — gap found in this pass; corrected in code (see commit).
- **Deliberate divergence** — Custos differs on purpose; rationale pinned.
- **Open** — trade-off worth an operator decision before the related plan.

## 1. Cryptography & key material

| Area | Sibling pattern | Custos | Verdict |
|---|---|---|---|
| AEAD | Portunus: AES-256-GCM, blob `nonce(12) ‖ ct+tag`, keyring `kN:b64`, strict base64, duplicate versions rejected, **max version wins** | Identical shape and selection rule (`custos/crypto.py`) | Aligned |
| AAD | Portunus binds `entry_id\|key_version`; Janus binds `key_id` inside a `JSEC` magic envelope | Custos binds row identity + live/history domain + version per spec §4; no magic envelope (Portunus style) | Aligned (stronger AAD, same philosophy) |
| Agent-key digest | Both siblings: HMAC-SHA256(pepper, secret), never plaintext at rest; constant-time compare; unknown-id dummy-digest path (Portunus) | Same contract, digest over the base64url text as presented (spec §4) | Aligned |
| Pepper source | Portunus: file-only, ≥32 bytes, size-bounded read, rotation = mass reissue; Janus: env, boot-fail when missing | Custos: env **or** file, both-set → startup failure, ≥32 bytes, no automated rotation (runbook re-mint) | Aligned (superset, fail-closed) |
| Rekey | **Neither sibling has a rekey endpoint** — both are write-new/read-old only | Custos adds batched rekey + verify (spec §6) because a credential vault must retire old key versions without re-entering every secret | Deliberate divergence — the feature Janus/Portunus lack; keep |
| Operator TOTP seal | Portunus: Fernet from keyring, decrypt tries all versions | Custos: §4 operator-domain AES-GCM, version-aware decrypt | Aligned in effect (rotation-safe), Custos keeps one AEAD everywhere |
| Recovery-code digest | Portunus: HMAC under **keyring key material**, domain-separated, verify tries all key versions → survives key rotation | Custos: HMAC under **pepper** → survives keyring rotation (incl. rekey) but dies on pepper rotation, which spec §4 already declares mass-reissue | Deliberate divergence — Custos separates the two rotation domains; pepper rotation is already a maintenance-window re-mint event |

## 2. Operator auth

| Area | Sibling pattern | Custos | Verdict |
|---|---|---|---|
| Password hashing | Portunus: argon2id `PasswordHasher` defaults (t=3, m=65536, p=4), offloaded via `asyncio.to_thread` | Same explicit params + `to_thread` (`custos/operator/account.py`) | Aligned |
| Sessions | Portunus: opaque `token_urlsafe(32)`, store SHA-256, per-session CSRF, `HttpOnly; Secure; SameSite=Strict`, absolute 30 d only | Same storage/CSRF pattern; `SameSite=Lax`; idle 12 h + absolute 7 d; purpose-scoped sessions | Deliberate divergence — Lax keeps top-level navigation into the console logged-in (device hand-off UX); CSRF header + Origin check carry the mutation defense. Shorter TTLs suit a credential vault |
| CSRF | Portunus: `x-csrf-token` on all unsafe methods, `compare_digest`, token re-readable when authenticated | Same header/compare; re-read via `GET /api/auth/status` with live cookie | Aligned |
| Origin | Portunus: absent Origin allowed; present must match normalized allowlist | Same rule (`check_origin`) | Aligned |
| Login shape | Portunus: two-step — password → 401 `totp_required` + challenge → second endpoint | Custos: single request `{username, password, totp?/recovery_code?}`; `auth/status.totp_required` drives the console form | Deliberate divergence — no in-memory challenge state, one ledger row per failed request, simpler CLI; spec §5 pins it |
| Step-up scope | Portunus: password-only, in-memory 300 s token, gates **account-security routes only**; key mint/reveal need session only | Custos: DB-backed single-use 300 s presenter-bound token; gates reveal/purge/mint/retention/rekey per the §6 authority matrix | Deliberate divergence — the vault's blast radius is the secrets themselves, so step-up covers credential reads and destructive ops, not just account settings. DB storage survives restarts and works with the `co-` bearer plane |
| Lockout | Portunus: per-IP only, 5/15 min, oldest-failure anchor, **fail-open on ledger read error** | Custos: per-IP 10/15 min **plus** per-account 30/30 min non-extending; suppressions escape hatch; **fail-closed (503) if the ledger write fails** | Deliberate divergence — a vault must not fail open on its brute-force ledger; per-account window bounds distributed guessing. Numbers/anchors pinned in spec §5 |
| Auth-event durability | Portunus: best-effort audit ("auth must not 500") | Custos: failure rows commit in an independent transaction; ledger write failure → 503, never success | Deliberate divergence (availability traded for audit integrity, spec §3/§11) |
| TOTP replay | Portunus: single `totp_last_step`, guarded UPDATE | Custos: per-site counters (login/stepup/confirm), same guarded-UPDATE mechanic | Aligned mechanic; per-site split is a pinned refinement |
| Recovery codes | Portunus: 10 codes, 31-char alphabet, dash-grouped, guarded consume | Custos: 10 codes, canonical Crockford 32-symbol alphabet with I/L/O mapping, guarded consume, soft-consume on regen | Aligned (Custos normalization is a bijection — no collision risk) |
| Passkeys | Portunus: hand-rolled WebAuthn, UV `preferred`, clone check `stored>0 && new<=stored` | Custos: library-verified assertions, clone check `stored>0 && new>0 && new<=stored` (counter-0 authenticators keep working) | Aligned; Custos rule is the WebAuthn-correct refinement, spec §5 |
| Setup | Portunus: first-caller-wins unless env bootstrap password set | Custos: one-shot ≥128-bit setup code (0600 file or env), single-row guard, tighter rate buckets | Deliberate divergence — a vault cannot leave an open race window on first boot |
| Client IP | Portunus: XFF only from trusted CIDRs, right-to-left walk | Identical rule + `/0` rejection + dual peer/client recording in the ledger | Aligned (superset) |
| Turnstile | Portunus: `success is True`, hostname allowlist (empty fails closed), token ≤2048, `trust_env=False`, non-2xx → False | Custos matched all of these **after this pass** (was: truthiness check, no status check, no length cap, proxy env honored). Timeout stays 5 s (spec-pinned) vs Portunus 10 s | **Fixed** (3 gaps); timeout divergence deliberate — fail-closed login should not hang 10 s |

## 3. Planes, retention, telemetry

| Area | Sibling pattern | Custos | Verdict |
|---|---|---|---|
| Admin auth | Janus: static stats token, loopback-only when unset; no operator plane | Custos: full session plane + expiring `co-` operator tokens with the §6 authority matrix | Deliberate divergence — Janus has no vault to administer |
| Revocation bite | Portunus: in-process authz snapshot, monotonic generation, in-flight fails closed | Custos: DB check on **every** request incl. each MCP call (no cached auth) | Aligned in guarantee (next-request bite); Custos pays a lookup instead of snapshot machinery — single-worker simplicity |
| Retention | Portunus: in-process hourly loop; Janus: hourly gen_server sweep | Custos: **operator command only**, no workers (spec §2/§6), min 7 d, 20-snapshot floor | Deliberate divergence — destructive pruning of a credential history stays an explicit, audited, step-up-gated act |
| Telemetry | Portunus: TracerProvider always installed, export opt-in, never args/results/query strings, instrumentation failure non-fatal | Same contract (`custos/telemetry.py`, `url.query` stripped) | Aligned |
| Audit | Portunus: metadata-only events, closed detail shapes | Custos: closed action enum + closed detail keys, values never present | Aligned (stricter) |

## 4. Open trade-offs (operator decision, no code change yet)

1. **`SameSite=Lax` vs `Strict`.** Portunus proves Strict works for a
   same-origin console. Custos chose Lax for the device hand-off navigation
   path; CSRF + Origin already block cross-site mutations. Switching to
   Strict costs only the "arrive logged-in via external link" convenience.
   Recommendation: keep Lax (spec-pinned, browser E2E green).
2. **Recovery-code digest domain.** Keyring-keyed (Portunus) would let codes
   survive a pepper rotation, but pepper rotation already forces key/token
   re-mint; re-issuing ≤10 codes in the same window is cheap. Recommendation:
   keep pepper-keyed (current, spec-pinned).
3. **Auth-ledger fail-open.** Portunus keeps login available when the audit
   insert fails; Custos 503s. For a single-operator vault the 503 is the
   safer default and is an §11 invariant. Recommendation: keep fail-closed.

None of the three requires a spec edit if the recommendations stand.

## 5. Changes made in this pass

- `custos/operator/turnstile.py`: require `success is True`; reject non-200
  siteverify responses; cap widget token at 2048 chars before any network
  call; `trust_env=False` on the owned client.
- `tests/test_turnstile.py`: 3 new contract tests (truthy-success rejection,
  non-2xx rejection, overlong-token rejection without siteverify call).
- Verification: `uv run python -m pytest -q` → 366 passed;
  `uv run ruff check .` and `uv run mypy` clean on touched files.