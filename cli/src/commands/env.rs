//! `custos env` — print an item as shell exports (§9).
//!
//! The plain admin env read needs only the session (rev 41). Only the
//! `--allow-hazardous-names` override still consumes a step-up, so the CLI
//! prompts for that flag alone — a plain `custos env` stays scriptable.
//!
//! The server owns the escaping and the hazard rules and renders the lines, so
//! this command must relay the response BYTE-FOR-BYTE. Any local line splitting
//! or whitespace trimming would silently alter a secret — a value may legitimately
//! contain CR, LF, or doubled newlines.

use std::io::Write;

use crate::api::{Client, RouteClass};
use crate::CliError;

pub async fn run(client: &Client, name: &str, allow_hazardous: bool) -> Result<(), CliError> {
    let mut path = format!("/api/admin/items/{}/env", Client::seg(name));
    if allow_hazardous {
        path.push_str("?allow_hazardous=1");
    }
    // rev 41: only the hazardous override needs a step-up
    let step_up = if allow_hazardous {
        Some(super::key::prompt_step_up(client).await?)
    } else {
        None
    };
    // The admin env route answers text/plain.
    let body = client
        .request_text(
            reqwest::Method::GET,
            RouteClass::SessionOnly,
            &path,
            step_up.as_deref(),
        )
        .await?;

    // Write the body exactly as received, in one call: no splitting, no
    // trimming, no per-line printing.
    let mut out = std::io::stdout().lock();
    out.write_all(body.as_bytes())
        .map_err(|e| CliError::Io(format!("cannot write the export: {e}")))?;
    out.flush()
        .map_err(|e| CliError::Io(format!("cannot flush the export: {e}")))?;

    // The refusal count is a diagnostic only; it must not change the output.
    let refused = body
        .split('\n')
        .filter(|line| line.starts_with("# refused hazardous name:"))
        .count();
    if refused > 0 {
        eprintln!(
            "warning: the server refused {refused} hazardous name(s); \
             pass --allow-hazardous-names to export them (needs step-up)"
        );
    }
    Ok(())
}
