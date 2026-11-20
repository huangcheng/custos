use thiserror::Error;

/// Every failure the CLI can report. `Display` never carries a secret: the
/// messages name the code and the fix, never the credential.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Auth(String),

    /// The server's own `{code, message}` — surfaced verbatim (§9: an expired
    /// token fails with the server's 401, no silent fallback).
    #[error("{code}: {message}")]
    Server {
        status: u16,
        code: String,
        message: String,
    },

    /// A secret was passed where it must never be (argv).
    #[error("{0}")]
    SecretInArgv(String),

    #[error("{0}")]
    Network(String),

    #[error("{0}")]
    Io(String),
}

impl CliError {
    /// Exit codes: 2 = usage/config, 3 = auth, 1 = everything else.
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Config(_) | CliError::SecretInArgv(_) => 2,
            CliError::Auth(_) => 3,
            CliError::Server { status, .. } if *status == 401 || *status == 403 => 3,
            _ => 1,
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        CliError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(err: serde_json::Error) -> Self {
        CliError::Config(format!("invalid JSON: {err}"))
    }
}
