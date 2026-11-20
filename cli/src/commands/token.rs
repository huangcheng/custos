//! `custos token` — operator tokens. Minting is interactive-login only (§5).

use clap::Subcommand;
use serde_json::{json, Value};

use crate::api::{Client, RouteClass};
use crate::CliError;

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Mint an operator token (session + step-up; expiry is mandatory).
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
}

pub async fn run(client: &Client, cmd: TokenCommand, as_json: bool) -> Result<(), CliError> {
    match cmd {
        TokenCommand::Mint {
            label,
            expires,
            allow_sensitive,
        } => {
            let step_up = super::key::prompt_step_up(client).await?;
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
                    Some(&step_up),
                )
                .await?;
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
    }
    Ok(())
}
