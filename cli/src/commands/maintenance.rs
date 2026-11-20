//! `custos rekey` and `custos retention` — the operator's maintenance verbs.

use serde_json::{json, Value};

use crate::api::{Client, RouteClass};
use crate::CliError;

/// Rekey loops batches until `remaining == 0`, exits non-zero when any batch
/// skipped rows (§13: a skipped row means an undecryptable row, which must not
/// read as success), then runs one final audit and reports leftovers.
pub async fn rekey(client: &Client, verify: bool, audit_only: bool) -> Result<(), CliError> {
    if audit_only {
        let out = client
            .get(RouteClass::TokenPermitted, "/api/admin/rekey/audit")
            .await?;
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let endpoint = if verify {
        "/api/admin/rekey/verify"
    } else {
        "/api/admin/rekey"
    };
    let mut step_up = super::key::prompt_step_up(client).await?;
    let mut cursor: Option<String> = None;
    let mut skipped_total = 0u64;
    let mut batches = 0u32;

    loop {
        batches += 1;
        if batches > 10_000 {
            return Err(CliError::Config(
                "rekey did not terminate after 10000 batches".into(),
            ));
        }
        let mut body = json!({});
        if let Some(cursor) = &cursor {
            body["cursor"] = Value::String(cursor.clone());
        }
        let out = client
            .post(
                RouteClass::SessionOnly,
                endpoint,
                Some(body),
                Some(&step_up),
            )
            .await?;
        if let Some(run_token) = out.get("run_token").and_then(Value::as_str) {
            step_up = run_token.to_string();
        }
        let remaining = out.get("remaining").and_then(Value::as_u64).unwrap_or(0);
        skipped_total += out.get("skipped").and_then(Value::as_u64).unwrap_or(0);
        if remaining == 0 {
            break;
        }
        match out.get("cursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_string()),
            None => {
                return Err(CliError::Config(
                    "server reported remaining work but no cursor".into(),
                ))
            }
        }
    }

    // §13: the removal gate is the audit, not the loop exit.
    let audit = client
        .get(RouteClass::TokenPermitted, "/api/admin/rekey/audit")
        .await?;
    println!("{}", serde_json::to_string_pretty(&audit)?);
    if skipped_total > 0 {
        return Err(CliError::Config(format!(
            "{skipped_total} row(s) were skipped as unreadable; \
             restore the missing key version or force-drop the affected items, then rerun"
        )));
    }
    Ok(())
}

pub async fn retention(client: &Client) -> Result<(), CliError> {
    let step_up = super::key::prompt_step_up(client).await?;
    let out = client
        .post(
            RouteClass::SessionOnly,
            "/api/admin/retention",
            None,
            Some(&step_up),
        )
        .await?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
