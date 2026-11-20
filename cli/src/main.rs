use std::process::ExitCode;

use clap::{Parser, Subcommand};

use custos_cli::{api::Client, commands, session, CliError};

#[derive(Parser)]
#[command(
    name = "custos",
    about = "Operator CLI for a Custos credential vault",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    /// Base URL of the Custos server (default: $CUSTOS_URL).
    #[arg(long, global = true, env = "CUSTOS_URL")]
    url: Option<String>,

    /// Print machine-readable JSON instead of a table.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in and store a session (device hand-off when Turnstile is on).
    Login,
    /// Forget the stored session.
    Logout,
    /// Items: list, get, set, rm, restore, purge, force-drop, history.
    Item {
        #[command(subcommand)]
        cmd: commands::item::ItemCommand,
    },
    /// Print an item as `export NAME='value'` lines.
    Env {
        name: String,
        /// Ask the admin endpoint to export hazardous names (needs step-up).
        #[arg(long)]
        allow_hazardous_names: bool,
    },
    /// Agent keys.
    Key {
        #[command(subcommand)]
        cmd: commands::key::KeyCommand,
    },
    /// Operator tokens.
    Token {
        #[command(subcommand)]
        cmd: commands::token::TokenCommand,
    },
    /// Read the audit log.
    Audit {
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        item: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
    /// Re-seal every row under the newest key version.
    Rekey {
        /// Trial-decrypt every row instead of re-sealing.
        #[arg(long)]
        verify: bool,
        /// Only print the per-version audit.
        #[arg(long)]
        audit: bool,
    },
    /// Prune history/ledger rows older than the retention window.
    Retention,
    /// Break-glass: direct database access for a locked-out operator.
    Account {
        /// Read the DSN from this 0600 file instead of CUSTOS_DATABASE_URL.
        #[arg(long, global = false)]
        database_url_file: Option<String>,
        #[command(subcommand)]
        cmd: commands::account::AccountCommand,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("custos: cannot start the runtime: {err}");
            return ExitCode::from(1);
        }
    };
    let code = match runtime.block_on(run(cli)) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("custos: {err}");
            err.exit_code()
        }
    };
    ExitCode::from(code as u8)
}

async fn run(cli: Cli) -> Result<(), CliError> {
    // Break-glass and login never need an HTTP client.
    match &cli.command {
        Command::Login => return commands::account::login(cli.url.as_deref()).await,
        Command::Logout => {
            session::clear()?;
            println!("signed out");
            return Ok(());
        }
        Command::Account {
            database_url_file,
            cmd,
        } => return commands::account::run(cmd, database_url_file.as_deref()).await,
        _ => {}
    }

    let client = build_client(cli.url.as_deref())?;
    match cli.command {
        Command::Item { cmd } => commands::item::run(&client, cmd, cli.json).await,
        Command::Env {
            name,
            allow_hazardous_names,
        } => commands::env::run(&client, &name, allow_hazardous_names).await,
        Command::Key { cmd } => commands::key::run(&client, cmd, cli.json).await,
        Command::Token { cmd } => commands::token::run(&client, cmd, cli.json).await,
        Command::Audit {
            actor,
            item,
            action,
            from,
            to,
        } => commands::audit::run(&client, cli.json, actor, item, action, from, to).await,
        Command::Rekey { verify, audit } => {
            commands::maintenance::rekey(&client, verify, audit).await
        }
        Command::Retention => commands::maintenance::retention(&client).await,
        Command::Login | Command::Logout | Command::Account { .. } => unreachable!(),
    }
}

/// Pick the credential: an env token wins for token-permitted routes, the
/// session serves session-only routes. `api::Client` enforces the split.
fn build_client(url: Option<&str>) -> Result<Client, CliError> {
    let base_url = url
        .map(str::to_string)
        .or_else(|| std::env::var("CUSTOS_URL").ok())
        .ok_or_else(|| {
            CliError::Config("set CUSTOS_URL (or pass --url) to reach the server".into())
        })?;

    if let Ok(token) = std::env::var("CUSTOS_OPERATOR_TOKEN") {
        if !token.is_empty() {
            return Client::new(base_url, custos_cli::api::Credentials::EnvToken(token));
        }
    }
    match session::load()? {
        Some(session) if !session.is_expired() => Ok(Client::new(
            base_url,
            custos_cli::api::Credentials::Session(session),
        )?),
        Some(_) => Err(CliError::Auth(
            "the stored session has expired; run `custos login`".into(),
        )),
        None => Err(CliError::Auth(
            "no credentials: run `custos login`, or set CUSTOS_OPERATOR_TOKEN".into(),
        )),
    }
}
