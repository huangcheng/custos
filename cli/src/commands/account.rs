//! Login and break-glass (§9). Break-glass talks to PostgreSQL directly: host
//! shell access is the authorization.

use clap::Subcommand;

use crate::api::{Client, Credentials, RouteClass};
use crate::session::{self, Session};
use crate::{breakglass, CliError};

#[derive(Subcommand)]
pub enum AccountCommand {
    /// Clear lockout suppressions (local database access).
    Unlock {
        /// Restrict the marker to one IP instead of the ip:* wildcard.
        #[arg(long)]
        ip: Option<String>,
    },
    /// Set a new operator password (local database access).
    ResetPassword,
    /// Disable TOTP, drop passkeys, consume recovery codes, revoke tokens.
    ResetMfa,
    /// Prune expired rows without a session (the emergency retention path).
    Retention,
}

pub async fn run(cmd: &AccountCommand, dsn_file: Option<&str>) -> Result<(), CliError> {
    // Resolve the DSN once, here, so every verb honours --database-url-file.
    let dsn = breakglass::dsn_from_env_or_file(dsn_file)?;
    match cmd {
        AccountCommand::Unlock { ip } => breakglass::unlock(&dsn, ip.as_deref()).await,
        AccountCommand::ResetPassword => breakglass::reset_password(&dsn).await,
        AccountCommand::ResetMfa => breakglass::reset_mfa(&dsn).await,
        AccountCommand::Retention => breakglass::retention(&dsn).await,
    }
}

/// `custos login`: direct password+TOTP when Turnstile is unset, otherwise the
/// device hand-off (§9). The CLI never attempts direct login against a
/// Turnstile-gated server.
pub async fn login(url: Option<&str>) -> Result<(), CliError> {
    let base_url = url
        .map(str::to_string)
        .or_else(|| std::env::var("CUSTOS_URL").ok())
        .ok_or_else(|| CliError::Config("set CUSTOS_URL (or pass --url)".into()))?;

    // status is public: decide the flow before asking for a password
    let status_client = Client::new(&base_url, Credentials::EnvToken(String::new()))?;
    let status = status_client
        .get(RouteClass::TokenPermitted, "/api/auth/status")
        .await?;
    let turnstile = status
        .get("turnstile_sitekey")
        .and_then(serde_json::Value::as_str)
        .is_some();
    if turnstile {
        return Err(CliError::Config(
            "this server uses Turnstile; sign in from the console at /device to complete \
             `custos login` (direct login is not attempted)"
                .into(),
        ));
    }

    let username = prompt("username: ")?;
    let password = rpassword::prompt_password("password: ")
        .map_err(|e| CliError::Io(format!("cannot read the password: {e}")))?;

    let mut body = serde_json::json!({ "username": username, "password": password });
    let totp_required = status
        .get("totp_required")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if totp_required {
        body["totp"] = serde_json::Value::String(prompt("authenticator code: ")?);
    }

    let anonymous = Client::new(&base_url, Credentials::EnvToken(String::new()))?;
    let out = anonymous
        .post(
            RouteClass::TokenPermitted,
            "/api/auth/login",
            Some(body),
            None,
        )
        .await?;
    let csrf = out
        .get("csrf_token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError::Config("login returned no csrf_token".into()))?
        .to_string();

    // The cookie arrives in Set-Cookie; the client keeps it explicitly.
    let cookie = anonymous
        .last_cookie()
        .ok_or_else(|| CliError::Config("login set no session cookie".into()))?;

    let session = Session {
        base_url,
        cookie,
        csrf,
        // The server also enforces a 12h IDLE TTL; we record the earlier of
        // the two so an idle-dead session prompts a fresh login instead of
        // failing with a bare 401 later.
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(12),
    };
    session::save(&session)?;
    println!("signed in");
    Ok(())
}

fn prompt(what: &str) -> Result<String, CliError> {
    use std::io::{BufRead, Write};
    print!("{what}");
    std::io::stdout()
        .flush()
        .map_err(|e| CliError::Io(e.to_string()))?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Io(e.to_string()))?;
    Ok(line.trim().to_string())
}

#[allow(dead_code)]
fn _pinned(_: &str) -> Result<String, CliError> {
    breakglass::hash_password("x")
}
