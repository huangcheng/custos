//! `custos audit` — read the audit log with the filters the server supports.

use serde_json::Value;

use crate::api::{Client, RouteClass};
use crate::CliError;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &Client,
    as_json: bool,
    actor: Option<String>,
    item: Option<String>,
    action: Option<String>,
    from: Option<String>,
    to: Option<String>,
) -> Result<(), CliError> {
    let mut query = String::from("limit=50");
    for (key, value) in [
        ("actor", actor),
        ("item", item),
        ("action", action),
        ("from", from),
        ("to", to),
    ] {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            query.push_str(&format!("&{key}={}", urlencode(&value)));
        }
    }
    let out = client
        .get(
            RouteClass::TokenPermitted,
            &format!("/api/admin/audit?{query}"),
        )
        .await?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    if let Some(rows) = out.get("items").and_then(Value::as_array) {
        for row in rows {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                row.get("ts").and_then(Value::as_str).unwrap_or("?"),
                row.get("action").and_then(Value::as_str).unwrap_or("?"),
                row.get("actor_label")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                row.get("item_name").and_then(Value::as_str).unwrap_or("-"),
                if row.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                    "ok"
                } else {
                    "fail"
                },
            );
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
