# Custos — agent instructions

Custos is a self-hosted credential vault: named multi-field items, AES-256-GCM
encryption at rest, scoped agent keys, audit log, REST + MCP. Single operator.
Design of record: `docs/superpowers/specs/2026-11-17-custos-design.md` — read it
before changing behavior; update it when a decision changes.

## Security rules (non-negotiable)

- Never commit or echo secrets: API keys, tokens, passwords, TOTP seeds, pepper
  or keyring material, session cookies. Redact before output (`sk-…`, long hex,
  base64 blobs). This includes reading config or env to diagnose an issue.
- Never put real credentials in tests, fixtures, examples, docs, or scripts.
  Use obviously fake values (`cu-test.…`, `k1:<32 zero bytes>` style fixtures).
- Secret values and full tokens must never reach logs, audit rows, error
  messages, or telemetry attributes (design §11 invariants).
- No personal or environment-specific data in any committed artifact: no names,
  hostnames, private URLs, absolute home paths. Use env vars, `~`, or
  placeholders (`<repo-root>`). Machine-specific values belong in generated
  config that is gitignored.
- Do not document internal workflows, infrastructure topology, or deployment
  targets in this repo. Deployment docs describe the generic shape (container +
  reverse proxy + TLS), never real hosts or domains.
- `.env`, keyring files, pepper files, local databases, and generated config are
  gitignored from the first commit. Check `git status` for leaks before staging.

## Stack (pinned by the design)

| Piece | Stack |
|---|---|
| Backend | Python ≥3.12, FastAPI, SQLAlchemy 2 async ORM (PostgreSQL via asyncpg), Alembic, OpenTelemetry |
| Console | React + Vite, shared DESIGN.md visual system (to be added at repo root) |
| MCP wrapper | TypeScript, official MCP SDK, stdio, npx-able |
| CLI | Rust single static binary (clap, reqwest/rustls, serde, tokio) |

- All database access goes through the ORM/session layer; no raw SQL in route
  code (Alembic migrations excepted).
- Crypto, agent keys, operator auth (password/TOTP/passkeys/recovery/Turnstile/
  step-up), and telemetry follow the sibling project Portunus's proven patterns
  — copy the pattern, keep repos independent (no cross-repo imports).
- Do not add dependencies beyond the design without saying why.

## Commits are gated, mechanically

Every commit (agent or human) runs `ocr review --audience agent` first. Read the
findings — do not trust the exit code, and do not chain
`ocr review … && git commit`. Resolve findings or record an explicit
false-positive reason in the commit body. If `ocr` is missing or broken, say so
and stop — never commit around the gate.

Review intermediates (ocr reports, diffs, scratch output) go to `/tmp`, never
into the repo tree — not even gitignored. If a local `ocr` wrapper/config is
needed, keep it uncommitted (`*.local`) like the audit runner; the repo
contains only the rule, not the gate machinery.

English commit messages: imperative subject, body explains why, plus the paths
that prove verification. One logical change per commit.

## Spec audit gate (multi-model consensus)

Every spec under `docs/superpowers/specs/` must pass a flash-model audit before
it is considered approved. The gate runner is **machine-local and uncommitted**
(`scripts/spec-audit.sh`, gitignored — keep it out of the repo history):

    scripts/spec-audit.sh docs/superpowers/specs/<spec>.md

- The script runs `pi -p --no-session --no-tools --model <m>` for each reviewer
  model in a **local, uncommitted roster** (`scripts/spec-audit.models.local`,
  gitignored; `SPEC_AUDIT_MODELS` env overrides). The committed script and docs
  reference only the roster file — never provider names, model ids, or
  endpoints. Reviewer models should be fast/cheap (flash-class) picks.
- Each model reviews the spec for contradictions, undefined behavior, security
  holes, and untestable claims, and must end with a verdict line
  `VERDICT: APPROVE` or `VERDICT: REVISE` plus numbered findings.
- Fix the findings in the spec, rerun the whole roster, repeat until **every**
  model approves in the same round. Cap at 5 rounds; if models still disagree,
  stop and bring the remaining objections to the operator — never silently
  drop a dissenting model from the roster.
- Audit transcripts and other review intermediates never stay in the repo.
  Save them under `/tmp/custos-audits/<spec-stem>/` (round-N per model); the
  commit references the audit run (date, rounds, unanimous verdict), not the
  transcripts.

## Verification

- E2E is the proof: `scripts/e2e.sh` (API + real MCP path) and
  `scripts/e2e_console.sh` (real browser through the console) once they exist.
  Run them before claiming a feature works.
- Unit tests pin parsers, crypto edge cases, scope matching, TOTP replay,
  lockout math — they never stand in for E2E.
- After edits run the available lint/typecheck (`ruff`, `mypy`/`pyright`,
  `cargo clippy`, `tsc`) for the touched piece.
- If it was not run, say it was not run.

## Process

- Follow the superpowers skills flow: brainstorm → design doc → plan →
  implement. Specs live in `docs/superpowers/specs/`, plans alongside.
- Preserve the design's invariants (§11) when refactoring; a change that breaks
  one is a design change, not a cleanup.
- Keep this repo public-safe: it must be publishable as-is at any commit.