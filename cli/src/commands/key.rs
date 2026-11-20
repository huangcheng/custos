//! `custos key` — agent keys. Mint/revoke are session + step-up only (§6).

use clap::Subcommand;
use serde_json::{json, Value};

use crate::api::{Client, Credentials, RouteClass};
use crate::CliError;

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Mint an agent key (session + step-up).
    Mint {
        #[arg(long)]
        label: String,
        #[arg(long, value_parser = ["read", "read-write"])]
        mode: String,
        /// Repeatable scope pattern, e.g. --scope 'stock-*'.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
    },
    /// List keys.
    Ls,
    /// Revoke a key (session + step-up).
    Revoke { key_id: String },
}

pub async fn run(client: &Client, cmd: KeyCommand, as_json: bool) -> Result<(), CliError> {
    match cmd {
        KeyCommand::Mint {
            label,
            mode,
            scopes,
            expires,
        } => {
            let token = prompt_step_up(client).await?;
            let mut body = json!({ "label": label, "mode": mode, "scopes": scopes });
            if let Some(expires) = expires {
                body["expires_at"] = Value::String(expires);
            }
            let out = client
                .post(
                    RouteClass::SessionOnly,
                    "/api/admin/keys",
                    Some(body),
                    Some(&token),
                )
                .await?;
            // The token is shown exactly once: print it, and only it, on stdout.
            match out.get("token").and_then(Value::as_str) {
                Some(token) => {
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    } else {
                        println!("{token}");
                        eprintln!("(this is the only time the token is shown)");
                    }
                }
                None => return Err(CliError::Config("server returned no token".into())),
            }
        }
        KeyCommand::Ls => {
            let out = client
                .get(RouteClass::TokenPermitted, "/api/admin/keys")
                .await?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }
            if let Some(keys) = out.get("keys").and_then(Value::as_array) {
                for key in keys {
                    println!(
                        "{}\t{}\t{}\t{}",
                        key.get("key_id").and_then(Value::as_str).unwrap_or("?"),
                        key.get("label").and_then(Value::as_str).unwrap_or("?"),
                        key.get("mode").and_then(Value::as_str).unwrap_or("?"),
                        key.get("revoked_at")
                            .and_then(Value::as_str)
                            .map(|_| "revoked")
                            .unwrap_or("active"),
                    );
                }
            }
        }
        KeyCommand::Revoke { key_id } => {
            let token = prompt_step_up(client).await?;
            client
                .delete(
                    RouteClass::SessionOnly,
                    &format!("/api/admin/keys/{}", Client::seg(&key_id)),
                    Some(&token),
                )
                .await?;
            println!("revoked {key_id}");
        }
    }
    Ok(())
}

/// One step-up token per gated call (§5: single-use). Password, then TOTP (or a
/// recovery code). Requires a session: an env token cannot step up.
pub async fn prompt_step_up(client: &Client) -> Result<String, CliError> {
    if matches!(client.credentials(), Credentials::EnvToken(_)) {
        return Err(CliError::Auth(
            "step-up needs an interactive session; run `custos login` \
             (CUSTOS_OPERATOR_TOKEN cannot satisfy a step-up)"
                .into(),
        ));
    }
    let password = super::prompt_secret("step-up password: ")?;
    let mut body = serde_json::json!({ "password": password });

    // TOTP is required only when the account has it enabled.
    if let Ok(status) = client
        .get(RouteClass::TokenPermitted, "/api/auth/status")
        .await
    {
        if status
            .get("totp_required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            body["totp"] = Value::String(super::prompt_line(
                "authenticator code (or - for a recovery code): ",
            )?);
            if body["totp"] == Value::String("-".into()) {
                body.as_object_mut().unwrap().remove("totp");
                body["recovery_code"] = Value::String(super::prompt_line("recovery code: ")?);
            }
        }
    }

    // `/api/auth/step-up` is session-authenticated: SessionOnly here means
    // "needs the cookie", which is exactly right.
    let out = client
        .post(
            RouteClass::SessionOnly,
            "/api/auth/step-up",
            Some(body),
            None,
        )
        .await?;
    out.get("step_up_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| CliError::Config("step-up returned no token".into()))
}
