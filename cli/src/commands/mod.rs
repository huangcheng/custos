//! One module per command family.

pub mod account;
pub mod audit;
pub mod env;
pub mod item;
pub mod key;
pub mod maintenance;
pub mod token;

use std::io::{BufRead, IsTerminal, Write};

use crate::CliError;

/// Read a secret without echo. On a terminal: a hidden prompt (§9). Without
/// one (a pipe, a test, a runbook pipe): read the line from stdin, so scripts
/// and the E2E gate can drive the CLI. Never an argv flag either way.
pub fn prompt_secret(what: &str) -> Result<String, CliError> {
    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password(what)
            .map_err(|e| CliError::Io(format!("cannot read the {what}: {e}")));
    }
    eprint!("{what}");
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Io(format!("cannot read the {what}: {e}")))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Read a non-secret value (a username, a TOTP code).
pub fn prompt_line(what: &str) -> Result<String, CliError> {
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
