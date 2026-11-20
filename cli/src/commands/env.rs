//! `custos env` — print an item as shell exports (§9).
//!
//! The admin env endpoint is `require_sensitive`: it consumes a step-up on
//! EVERY call (with or without `allow_hazardous`), so the CLI always asks for
//! one. A refusal on stderr is a warning, not a failure.

use crate::api::{Client, RouteClass};
use crate::CliError;

pub async fn run(client: &Client, name: &str, allow_hazardous: bool) -> Result<(), CliError> {
    let mut path = format!("/api/admin/items/{}/env", Client::seg(name));
    if allow_hazardous {
        path.push_str("?allow_hazardous=1");
    }
    let step_up = super::key::prompt_step_up(client).await?;
    // The admin env route answers text/plain.
    let text = client
        .request_text(
            reqwest::Method::GET,
            RouteClass::SessionOnly,
            &path,
            Some(&step_up),
        )
        .await?;

    let mut refused = 0usize;
    for line in text.lines() {
        if line.starts_with("# refused hazardous name:") {
            refused += 1;
        }
        println!("{line}");
    }
    if refused > 0 {
        eprintln!(
            "warning: the server refused {refused} hazardous name(s); \
             pass --allow-hazardous-names to export them (needs step-up)"
        );
    }
    Ok(())
}
