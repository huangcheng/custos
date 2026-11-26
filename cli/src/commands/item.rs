//! `custos item` — the agent-plane item surface plus the admin lifecycle verbs.

use clap::Subcommand;
use reqwest::Method;
use serde_json::{json, Value};

use crate::api::{Client, RouteClass};
use crate::CliError;

#[derive(Subcommand)]
pub enum ItemCommand {
    /// List items visible to your credential (metadata only).
    List {
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Read one item (secrets masked unless --reveal).
    Get {
        name: String,
        /// Reveal secret values (session only — rev 41, no step-up).
        #[arg(long)]
        reveal: bool,
    },
    /// Create or replace an item. Fields come from stdin or --fields-file.
    Set {
        name: String,
        /// Read the fields JSON array from this file (must be 0600).
        #[arg(long)]
        fields_file: Option<String>,
        /// Notes to store. PUT replaces them wholesale, so omitting this
        /// preserves the current value by fetching it first.
        #[arg(long)]
        notes: Option<String>,
    },
    /// Soft-delete an item.
    Rm { name: String },
    /// Undelete a soft-deleted item.
    Restore { name: String },
    /// Hard-delete an item and its history (session + step-up only).
    Purge { name: String },
    /// Delete only unreadable rows of one item (session + step-up only).
    ForceDrop { name: String },
    /// Snapshot metadata for one item.
    History { name: String },
}

pub async fn run(client: &Client, cmd: ItemCommand, as_json: bool) -> Result<(), CliError> {
    match cmd {
        ItemCommand::List { cursor } => {
            // operator-facing: the admin list, never the agent plane (which
            // only accepts cu- keys)
            let mut path = "/api/admin/items?limit=50".to_string();
            if let Some(cursor) = cursor {
                // an opaque cursor may contain '+' or '&': encode it
                path.push_str(&format!("&cursor={}", urlencode(&cursor)));
            }
            let body = client.get(RouteClass::TokenPermitted, &path).await?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                print_rows(&body);
            }
        }
        ItemCommand::Get { name, reveal } => {
            let path = format!("/api/admin/items/{}", Client::seg(&name));
            let body = if reveal {
                // rev 41: the session alone reveals — no step-up prompt
                client
                    .request(
                        Method::GET,
                        RouteClass::SessionOnly,
                        &format!("{path}/reveal"),
                        None,
                        None,
                    )
                    .await?
            } else {
                client.get(RouteClass::TokenPermitted, &path).await?
            };
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        ItemCommand::Set {
            name,
            fields_file,
            notes,
        } => {
            let fields = read_fields(fields_file.as_deref())?;
            // PUT replaces notes wholesale: preserve the current value unless
            // the operator supplied one.
            let notes = match notes {
                Some(notes) => notes,
                None => client
                    .get(
                        RouteClass::SessionOnly,
                        &format!("/api/admin/items/{}", Client::seg(&name)),
                    )
                    .await
                    .ok()
                    .and_then(|current| {
                        current
                            .get("notes")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .unwrap_or_default(),
            };
            let body = json!({ "notes": notes, "fields": fields });
            // "create or replace": the admin PUT has no upsert flag, so create
            // when the name is absent and replace when it exists.
            let item_path = format!("/api/admin/items/{}", Client::seg(&name));
            let exists = match client.get(RouteClass::TokenPermitted, &item_path).await {
                Ok(_) => true,
                Err(CliError::Server { status: 404, .. }) => false,
                Err(err) => {
                    return Err(CliError::Config(format!(
                        "cannot tell whether {name} exists ({err}); refusing to guess \
                         between create and replace"
                    )))
                }
            };
            let out = if exists {
                client
                    .put(RouteClass::TokenPermitted, &item_path, Some(body))
                    .await?
            } else {
                let mut create = body;
                create["name"] = json!(name);
                client
                    .post(
                        RouteClass::TokenPermitted,
                        "/api/admin/items",
                        Some(create),
                        None,
                    )
                    .await?
            };
            print_revision(&out);
        }
        ItemCommand::Rm { name } => {
            client
                .delete(
                    RouteClass::TokenPermitted,
                    &format!("/api/admin/items/{}", Client::seg(&name)),
                    None,
                )
                .await?;
            println!("deleted {name}");
        }
        ItemCommand::Restore { name } => {
            let token = crate::commands::key::prompt_step_up(client).await?;
            client
                .post(
                    RouteClass::SessionOnly,
                    &format!("/api/admin/items/{}/restore", Client::seg(&name)),
                    None,
                    Some(&token),
                )
                .await?;
            println!("restored {name}");
        }
        ItemCommand::Purge { name } => {
            let token = crate::commands::key::prompt_step_up(client).await?;
            client
                .delete(
                    RouteClass::SessionOnly,
                    &format!("/api/admin/items/{}/purge", Client::seg(&name)),
                    Some(&token),
                )
                .await?;
            println!("purged {name}");
        }
        ItemCommand::ForceDrop { name } => {
            let token = crate::commands::key::prompt_step_up(client).await?;
            let out = client
                .post(
                    RouteClass::SessionOnly,
                    &format!("/api/admin/items/{}/force-drop", Client::seg(&name)),
                    None,
                    Some(&token),
                )
                .await?;
            println!(
                "dropped {} unreadable row(s)",
                out.get("dropped_unreadable")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            );
        }
        ItemCommand::History { name } => {
            let body = client
                .get(
                    RouteClass::TokenPermitted,
                    &format!("/api/admin/items/{}/history", Client::seg(&name)),
                )
                .await?;
            print_rows(&body);
        }
    }
    Ok(())
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn print_rows(body: &Value) {
    if let Some(rows) = body.get("items").and_then(Value::as_array) {
        for row in rows {
            let name = row.get("name").and_then(Value::as_str).unwrap_or("?");
            let revision = row.get("revision").and_then(Value::as_i64).unwrap_or(0);
            let fields = row
                .get("fields")
                .and_then(Value::as_array)
                .map(|f| f.len())
                .unwrap_or(0);
            println!("{name}\tfields={fields}\trevision={revision}");
        }
    } else {
        println!("{}", serde_json::to_string_pretty(body).unwrap_or_default());
    }
}

fn print_revision(out: &Value) {
    let revision = out.get("revision").and_then(Value::as_i64).unwrap_or(0);
    println!("revision {revision}");
}

/// `item set` never takes a secret on the command line (§9). Fields come from
/// stdin or a 0600 file.
fn read_fields(path: Option<&str>) -> Result<Value, CliError> {
    use std::io::Read;

    let raw = match path {
        Some(file) => {
            let meta = std::fs::metadata(file)?;
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(CliError::Config(format!(
                    "--fields-file {file} must not be group/other readable (chmod 600)"
                )));
            }
            std::fs::read_to_string(file)?
        }
        None => {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                return Err(CliError::Config(
                    "pipe the fields JSON on stdin or pass --fields-file (secrets never go in argv)".into(),
                ));
            }
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };
    let value: Value = serde_json::from_str(&raw)?;
    match &value {
        Value::Array(_) => Ok(value),
        Value::Object(map) => map.get("fields").cloned().ok_or_else(|| {
            CliError::Config("fields JSON must be an array or {fields: [...]}".into())
        }),
        _ => Err(CliError::Config("fields JSON must be an array".into())),
    }
}
