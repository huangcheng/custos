//! Break-glass helpers (§4/§9): DSN handling and Argon2id hashing that must be
//! byte-compatible with the server's `argon2-cffi` verifier.

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::CliError;

/// The server builds its DSN for asyncpg; the CLI's `tokio-postgres` wants a
/// plain libpq URL.
pub fn strip_driver(dsn: &str) -> String {
    dsn.replace("postgresql+asyncpg://", "postgresql://")
        .replace("postgres+asyncpg://", "postgres://")
}

/// Pinned parameters (spec §4): argon2id v0x13, m=65536 KiB, t=3, p=4,
/// salt 16 random bytes, hash 32 bytes — the server's exact set.
pub fn hash_password(plain: &str) -> Result<String, CliError> {
    let params = Params::new(65_536, 3, 4, Some(32))
        .map_err(|e| CliError::Config(format!("argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    argon
        .hash_password(plain.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| CliError::Config(format!("argon2 hashing failed: {e}")))
}

/// DSN from `--database-url-file` (0600) or `CUSTOS_DATABASE_URL`. The DSN
/// carries a password, so it is never an argv flag (§9).
pub fn dsn_from_env_or_file(file: Option<&str>) -> Result<String, CliError> {
    let raw = match file {
        Some(path) => {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path)?;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(CliError::Config(format!(
                    "{path} must not be group/other readable (chmod 600)"
                )));
            }
            std::fs::read_to_string(path)?.trim().to_string()
        }
        None => std::env::var("CUSTOS_DATABASE_URL").map_err(|_| {
            CliError::Config("set CUSTOS_DATABASE_URL or pass --database-url-file (0600)".into())
        })?,
    };
    if raw.is_empty() {
        return Err(CliError::Config("the database URL is empty".into()));
    }
    Ok(strip_driver(&raw))
}

async fn connect(dsn: &str) -> Result<tokio_postgres::Client, CliError> {
    let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
        .await
        .map_err(|e| CliError::Config(format!("cannot connect to the database: {e}")))?;
    // Drive the connection on the runtime; it ends with the client.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

/// `suppressed_until_events_ts` is a `timestamptz`: tokio-postgres needs a real
/// timestamp, so use `now()` on the server side instead of binding a string.
const NOW_MARKER_SQL: &str = "now()";

/// Generic over the executor so both a `Client` and a `Transaction` work.
async fn audit<E>(executor: &E, action: &str, detail: serde_json::Value) -> Result<(), CliError>
where
    E: tokio_postgres::GenericClient + Sync,
{
    executor
        .execute(
            "INSERT INTO audit (actor_kind, actor_id, actor_label, action, ok, detail) \
             VALUES ('local_process', 'local', 'break-glass', $1, true, $2)",
            &[&action, &detail],
        )
        .await
        .map_err(|e| CliError::Config(format!("audit write failed: {e}")))?;
    Ok(())
}

/// `custos account unlock` — a suppression marker for the account and either
/// one IP or the `ip:*` wildcard. Rows are never deleted (§5).
pub async fn unlock(dsn: &str, ip: Option<&str>) -> Result<(), CliError> {
    let mut client = connect(dsn).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let scopes: Vec<String> = match ip {
        Some(addr) => vec!["account".into(), format!("ip:{addr}")],
        None => vec!["account".into(), "ip:*".into()],
    };
    for scope in &scopes {
        // `id` is a UUID primary key with no server-side default in the ORM
        // model, so a raw INSERT must generate it (pgcrypto/13+ builtin).
        let sql = format!(
            "INSERT INTO lockout_suppressions (id, scope, suppressed_until_events_ts) \
             VALUES (gen_random_uuid(), $1, {NOW_MARKER_SQL})"
        );
        tx.execute(&sql, &[scope])
            .await
            .map_err(|e| CliError::Config(format!("cannot insert the {scope} marker: {e}")))?;
    }
    audit(
        &tx,
        "account.unlock",
        serde_json::json!({ "break_glass": true }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    println!("unlocked ({})", scopes.join(", "));
    Ok(())
}

/// `custos account reset-password` — new Argon2id hash, all sessions/step-ups
/// gone, operator tokens revoked, recovery codes consumed (§9).
pub async fn reset_password(dsn: &str) -> Result<(), CliError> {
    let plain = crate::commands::prompt_secret("new password: ")?;
    if plain.chars().count() < 12 {
        return Err(CliError::Config(
            "the password must be at least 12 characters".into(),
        ));
    }
    let confirm = crate::commands::prompt_secret("repeat the password: ")?;
    if plain != confirm {
        return Err(CliError::Config("the passwords do not match".into()));
    }
    let phc = hash_password(&plain)?;

    let mut client = connect(dsn).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let updated = tx
        .execute(
            "UPDATE operator_account SET password_hash = $1 WHERE id = 1",
            &[&phc],
        )
        .await
        .map_err(|e| CliError::Config(format!("cannot update the password: {e}")))?;
    if updated != 1 {
        return Err(CliError::Config(
            "no operator account exists; complete setup first".into(),
        ));
    }
    tx.execute("DELETE FROM step_up_tokens", &[])
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let sessions = tx
        .execute(
            "UPDATE operator_sessions SET revoked_at = now() WHERE revoked_at IS NULL",
            &[],
        )
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let tokens = tx
        .execute(
            "UPDATE operator_tokens SET revoked_at = now() WHERE revoked_at IS NULL",
            &[],
        )
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let consumed = tx
        .execute(
            "UPDATE recovery_codes SET consumed_at = now() WHERE consumed_at IS NULL",
            &[],
        )
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    audit(
        &tx,
        "operator.password_change",
        serde_json::json!({
            "break_glass": true, "codes_consumed": consumed,
            "tokens_revoked": tokens, "sessions_invalidated": sessions,
        }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    println!(
        "password reset; all sessions and tokens revoked, {consumed} recovery code(s) consumed"
    );
    Ok(())
}

/// `custos account reset-mfa` — TOTP off, passkeys gone, codes consumed,
/// tokens revoked, sessions dead. Exactly three audit rows (§9).
pub async fn reset_mfa(dsn: &str) -> Result<(), CliError> {
    let mut client = connect(dsn).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let updated = tx
        .execute(
            "UPDATE operator_account SET totp_enabled = false, totp_secret = NULL, \
             totp_key_version = NULL WHERE id = 1",
            &[],
        )
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    if updated != 1 {
        return Err(CliError::Config(
            "no operator account exists; complete setup first".into(),
        ));
    }
    let passkeys = tx
        .execute("DELETE FROM passkey_credentials", &[])
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let consumed = tx
        .execute(
            "UPDATE recovery_codes SET consumed_at = now() WHERE consumed_at IS NULL",
            &[],
        )
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    tx.execute("DELETE FROM step_up_tokens", &[])
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let sessions = tx
        .execute(
            "UPDATE operator_sessions SET revoked_at = now() WHERE revoked_at IS NULL",
            &[],
        )
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    let tokens = tx
        .execute(
            "UPDATE operator_tokens SET revoked_at = now() WHERE revoked_at IS NULL",
            &[],
        )
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;

    audit(
        &tx,
        "operator.totp_change",
        serde_json::json!({
            "break_glass": true,
            "tokens_revoked": tokens, "sessions_invalidated": sessions,
        }),
    )
    .await?;
    audit(
        &tx,
        "operator.passkey_change",
        serde_json::json!({ "break_glass": true, "count": passkeys }),
    )
    .await?;
    audit(
        &tx,
        "operator.recovery_regen",
        serde_json::json!({ "break_glass": true, "codes_consumed": consumed }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    println!(
        "MFA reset. Sign in with the password alone, then reset the password and re-enable TOTP."
    );
    Ok(())
}

/// `custos account retention` — the emergency prune with no session (§9).
///
/// This is the LAST-RESORT path when no session can be obtained, and it prunes
/// the SAME set the server's `POST /api/admin/retention` does
/// (`custos/retention.py::run_retention` — KEEP IN LOCKSTEP):
/// `field_history` (BOTH older than the window AND outside the 20-newest
/// floor), `audit`, `auth_events`, dead `operator_sessions` (revoked OR
/// absolute-expired OR idle-expired, mirroring `resolve_session`), their bound
/// plus consumed/expired `step_up_tokens`, `device_codes`, `webauthn_challenges`
/// (dependents FIRST — the session FKs are NO ACTION), and stale
/// `lockout_suppressions`. `CUSTOS_RETENTION_DAYS` (default 365, floor 7) sets
/// the window. One transaction; the audit row commits with the prune.
pub async fn retention(dsn: &str) -> Result<(), CliError> {
    let days: i32 = match std::env::var("CUSTOS_RETENTION_DAYS") {
        Ok(raw) => raw
            .trim()
            .parse()
            .map_err(|_| CliError::Config("CUSTOS_RETENTION_DAYS must be an integer".into()))?,
        Err(_) => 365,
    };
    if days < 7 {
        return Err(CliError::Config(
            "the retention window must be at least 7 days".into(),
        ));
    }
    // irreversible direct-DB prune: state the window BEFORE deleting (the
    // shell env may differ from the server process's configured window)
    println!("pruning with a {days}-day window (CUSTOS_RETENTION_DAYS; server default 365)");
    let mut client = connect(dsn).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;

    // history: rank over ALL snapshots per (item_id, name); prune only rows
    // BOTH older than the cutoff AND outside the 20-newest floor
    // (HISTORY_BUDGET in custos/items.py).
    let history = tx
        .execute(
            "DELETE FROM field_history WHERE id IN ( \
               SELECT id FROM ( \
                 SELECT id, superseded_at, row_number() OVER ( \
                   PARTITION BY item_id, name \
                   ORDER BY superseded_at DESC, id DESC) AS rn \
                 FROM field_history) r \
               WHERE r.rn > 20 AND r.superseded_at < now() - make_interval(days => $1))",
            &[&days],
        )
        .await
        .map_err(|e| CliError::Config(format!("prune field_history: {e}")))?;
    let audit_n = tx
        .execute(
            "DELETE FROM audit WHERE ts < now() - make_interval(days => $1)",
            &[&days],
        )
        .await
        .map_err(|e| CliError::Config(format!("prune audit: {e}")))?;
    let events = tx
        .execute(
            "DELETE FROM auth_events WHERE ts < now() - make_interval(days => $1)",
            &[&days],
        )
        .await
        .map_err(|e| CliError::Config(format!("prune auth_events: {e}")))?;

    // dead sessions mirror resolve_session EXACTLY (idle rule: last_seen +
    // idle_ttl <= now; idle 0 → absolute check only). Lock the candidates so
    // concurrent refreshes/revokes cannot disagree with the dependent deletes.
    let dead_rows = tx
        .query(
            "SELECT id::text FROM operator_sessions WHERE revoked_at IS NOT NULL \
             OR absolute_expires_at <= now() \
             OR (idle_ttl_seconds > 0 AND last_seen_at + make_interval(secs => idle_ttl_seconds) <= now()) \
             FOR UPDATE",
            &[],
        )
        .await
        .map_err(|e| CliError::Config(format!("select dead sessions: {e}")))?;
    let dead: Vec<String> = dead_rows.iter().map(|r| r.get(0)).collect();

    // dependents FIRST (session FKs are NO ACTION), then the sessions.
    // ids bind as text[] and cast in SQL (no uuid feature in tokio-postgres).
    let step_ups = tx
        .execute(
            "DELETE FROM step_up_tokens WHERE consumed_at IS NOT NULL \
             OR expires_at <= now() OR session_id = ANY($1::text[]::uuid[])",
            &[&dead],
        )
        .await
        .map_err(|e| CliError::Config(format!("prune step_up_tokens: {e}")))?;
    let devices = tx
        .execute(
            "DELETE FROM device_codes WHERE consumed_at IS NOT NULL \
             OR expires_at <= now() OR approved_by_session = ANY($1::text[]::uuid[])",
            &[&dead],
        )
        .await
        .map_err(|e| CliError::Config(format!("prune device_codes: {e}")))?;
    let challenges = tx
        .execute(
            "DELETE FROM webauthn_challenges WHERE consumed_at IS NOT NULL \
             OR expires_at <= now() OR session_id = ANY($1::text[]::uuid[])",
            &[&dead],
        )
        .await
        .map_err(|e| CliError::Config(format!("prune webauthn_challenges: {e}")))?;
    let sessions = tx
        .execute(
            "DELETE FROM operator_sessions WHERE id = ANY($1::text[]::uuid[])",
            &[&dead],
        )
        .await
        .map_err(|e| CliError::Config(format!("prune operator_sessions: {e}")))?;
    let suppressions = tx
        .execute(
            "DELETE FROM lockout_suppressions \
             WHERE suppressed_until_events_ts < now() - make_interval(days => $1)",
            &[&days],
        )
        .await
        .map_err(|e| CliError::Config(format!("prune lockout_suppressions: {e}")))?;

    let total =
        history + audit_n + events + step_ups + devices + challenges + sessions + suppressions;
    audit(
        &tx,
        "retention",
        serde_json::json!({ "break_glass": true, "pruned": total }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| CliError::Config(e.to_string()))?;
    println!(
        "pruned {total} row(s) over {days} day(s): {history} history, {audit_n} audit, \
         {events} auth_events, {step_ups} step_up_tokens, {devices} device_codes, \
         {challenges} webauthn_challenges, {sessions} sessions, {suppressions} lockout_suppressions"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_asyncpg_marker() {
        assert_eq!(
            strip_driver("postgresql+asyncpg://u:p@h:5432/db"),
            "postgresql://u:p@h:5432/db"
        );
        assert_eq!(strip_driver("postgresql://u@h/db"), "postgresql://u@h/db");
    }

    #[test]
    fn phc_matches_the_server_parameters() {
        let phc = hash_password("cu-test-password-12ch").expect("hash");
        assert!(
            phc.starts_with("$argon2id$v=19$"),
            "argon2id v0x13 (19): {phc}"
        );
        assert!(phc.contains("m=65536,t=3,p=4"), "pinned params: {phc}");
    }
}
