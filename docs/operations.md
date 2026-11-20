# Operations

The runbook for running a Custos instance. The design pins the *unit* of each
operation and what must never be lost; cadence and tooling are the operator's.

Everything here assumes host access to the deployment. There is no automated
pruning and no background worker by design: retention, rekey, and rotation are
operator actions.

## What you must back up

Three things, and they are not interchangeable:

| Artifact | Why |
|---|---|
| `pg_dump` of the database | items, plain values, history, audit, password hash, sessions |
| the **keyring** file | decrypts every `secret` field and the TOTP secret |
| the **pepper** file | verifies every agent key, operator token, and recovery code |

A dump without the matching keyring restores metadata and not one secret. Keep
**every keyring version** the dump might reference: a dump taken mid-rekey needs
the old version too. Store the backup off-box, encrypted, restricted exactly
like the keyring.

Suggested: a nightly `pg_dump` plus an off-box copy of the current keyring and
pepper, on the same schedule. The dump is sensitive — it holds cleartext
metadata, plain field values, the audit log, and the password hash.

## Restore

1. Load the dump into a fresh database.
2. Restore the pepper and **a keyring containing every version the dump
   references**. The startup check (§4) refuses to serve if any referenced
   version is missing — that refusal is the safety net, not an obstacle.
3. Start the app and read one known item to confirm.
4. **Reset credentials.** An older dump resurrects revoked keys and tokens,
   consumed recovery codes, and old sessions. After any restore:
   - revoke every agent key and operator token minted after the dump (or
     rotate the pepper, which invalidates all of them at once),
   - invalidate all sessions,
   - re-issue recovery codes,
   - record the reset in the audit log (`custos account` writes as
     `local_process` / `"local"`).

If a key version is genuinely lost: start with
`CUSTOS_ALLOW_MISSING_KEY_VERSION=1`, run `custos rekey --audit` to see which
items are affected, then `force-drop` them (after a fresh `pg_dump` — it is
irreversible) or accept degraded reads.

## Keyring rotation

Add a new key version, restart, rekey, verify, then retire the old one.

```bash
# 1. append k<n+1> to the keyring file (keep the old entries), restart the app
# 2. re-seal every row under the newest version
custos rekey                 # loops batches until remaining == 0
# 3. the removal gate is the audit, not the loop exit
custos rekey --audit         # must show no rows under an old version
# 4. prove there is no corruption under the NEWEST version
custos rekey --verify
```

`custos rekey` exits non-zero if any batch reported `skipped > 0`, which means
undecryptable rows: restore the missing key version or `force-drop` the
affected items, then rerun. Only remove old versions after a full pass with
`skipped: 0` and a clean audit. Removing a version still in use is caught at
the next startup.

## Pepper rotation (manual)

Rotating the pepper **invalidates every agent key, operator token, and recovery
code at once** — it does not re-hash anything, because the digests are
one-way. Plan it as a maintenance window:

1. Rotate the pepper and restart.
2. Re-mint every agent key and operator token.
3. Re-issue recovery codes.

Note the ordering trap: regeneration needs a step-up the dead recovery codes
cannot satisfy. End the window with either `custos account reset-mfa` +
`reset-password`, or a TOTP-functional operator regenerating from Settings.
The TOTP secret is keyring-sealed, so pepper rotation does **not** affect it —
do not disable and re-enable TOTP.

## Retention

Retention runs **only when you run it** (suggested monthly, interactively —
it is session + step-up only, so there is no unattended path):

```bash
custos retention
```

It prunes history older than `CUSTOS_RETENTION_DAYS` (floor 7) while always
keeping the 20 most recent snapshots per field, plus old audit rows, auth
events, dead sessions, consumed step-ups, expired device codes, and stale
lockout markers. It never touches live sessions, recovery codes, or items.

If no session can be obtained at all, `custos account retention` runs the same
prune directly against the database with `local_process` attribution.

## Break-glass ordering

The order matters; each step leaves the account in a specific state.

| Situation | Command | What it leaves behind |
|---|---|---|
| locked out | `custos account unlock` | clears the lockout markers; nothing else changes |
| lost password | `custos account reset-password` | new password; all sessions and tokens revoked, recovery codes consumed |
| lost / attacker-controlled MFA | `custos account reset-mfa` | TOTP off, passkeys removed, codes consumed, tokens and sessions dead |

After `reset-mfa` the account is **password-only** — immediately follow with
`custos account reset-password` for a fresh password, then re-enable TOTP and
mint fresh recovery codes from the console. The account is weakened until you
do.

Break-glass talks to PostgreSQL directly, so it needs a DSN: `CUSTOS_DATABASE_URL`
in your shell, or `--database-url-file` pointing at a 0600 file. There is no
`--database-url` flag — the DSN carries a password and must not appear in `ps`.

## Reverse proxy

Put Custos behind your own TLS-terminating reverse proxy. Two things to set:

- `CUSTOS_TRUSTED_PROXIES` to the proxy's actual CIDR. On a same-host proxy this
  is `127.0.0.1/32` (or `::1/128`) — **even with a loopback bind**. Without it,
  every client shares the proxy's IP and the lockout becomes a global
  self-DoS.
- `CUSTOS_ALLOWED_ORIGINS` (and `CUSTOS_WEBAUTHN_RP_ID` if you use passkeys) to
  the public browser origin, not the bind host.

## Turnstile outage

Login fails closed when Turnstile cannot be verified. The escape is to unset
`CUSTOS_TURNSTILE_SECRET`, `_SITEKEY`, **and** `_HOSTNAMES` together in a
maintenance window (they are a both-or-neither set), then restore them when
Cloudflare is healthy again.

## Checking a deployment

```bash
curl -fsS "$CUSTOS_URL/healthz"                # liveness
curl -fsS "$CUSTOS_URL/api/auth/status"        # setup_required / totp_required
custos rekey --audit                           # any rows under an old key version?
custos audit --action auth.failure             # recent credential failures
```

## Upgrading

1. Take a fresh `pg_dump` and a keyring/pepper copy.
2. Pull the new image and restart — migrations run at startup.
3. Read `custos audit --action retention` and `--action rekey` if the release
   notes mention either.
4. Confirm one known item reads correctly through both the console and an
   agent key.
