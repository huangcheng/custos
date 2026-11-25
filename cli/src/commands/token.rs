//! `custos token` — operator tokens. Minting is interactive-login only (§5).

use clap::Subcommand;
use serde_json::{json, Value};

use crate::api::{Client, RouteClass};
use crate::CliError;

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Mint an operator token (session only — rev 39; expiry is mandatory).
    Mint {
        #[arg(long)]
        label: String,
        #[arg(long)]
        expires: String,
        #[arg(long)]
        allow_sensitive: bool,
    },
    /// List tokens.
    Ls,
    /// Revoke a token (session + step-up).
    Revoke { key_id: String },
    /// Re-reveal a minted token's full value (session only — rev 39, no step-up).
    Reveal { key_id: String },
}

pub async fn run(client: &Client, cmd: TokenCommand, as_json: bool) -> Result<(), CliError> {
    match cmd {
        TokenCommand::Mint {
            label,
            expires,
            allow_sensitive,
        } => {
            // rev 39: mint trusts the login — no step-up prompt
            let body = json!({
                "label": label,
                "expires_at": expires,
                "allow_sensitive": allow_sensitive,
            });
            let out = client
                .post(
                    RouteClass::SessionOnly,
                    "/api/admin/tokens",
                    Some(body),
                    None,
                )
                .await?;
            match out.get("token").and_then(Value::as_str) {
                Some(token) => {
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    } else {
                        println!("{token}");
                        let kid = out
                            .get("key_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("<key_id>");
                        eprintln!(
                            "(key_id {kid}; re-reveal later with `custos token reveal {kid}`)"
                        );
                    }
                }
                None => return Err(CliError::Config("server returned no token".into())),
            }
        }
        TokenCommand::Ls => {
            let out = client
                .get(RouteClass::TokenPermitted, "/api/admin/tokens")
                .await?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        TokenCommand::Revoke { key_id } => {
            let step_up = super::key::prompt_step_up(client).await?;
            client
                .delete(
                    RouteClass::SessionOnly,
                    &format!("/api/admin/tokens/{}", Client::seg(&key_id)),
                    Some(&step_up),
                )
                .await?;
            println!("revoked {key_id}");
        }
        TokenCommand::Reveal { key_id } => {
            // rev 39: reveal trusts the login — no step-up prompt
            let out = client
                .get(
                    RouteClass::SessionOnly,
                    &format!("/api/admin/tokens/{}/reveal", Client::seg(&key_id)),
                )
                .await?;
            match out.get("token").and_then(Value::as_str) {
                Some(secret) => {
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    } else {
                        println!("{secret}");
                    }
                }
                None => return Err(CliError::Config("server returned no token".into())),
            }
        }
    }
    Ok(())
}
