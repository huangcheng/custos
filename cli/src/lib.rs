//! Custos operator CLI.
//!
//! Two planes, one binary (§9): the agent REST plane for item commands, and the
//! admin plane for keys/tokens/audit/maintenance. `custos account` is the only
//! path that talks to PostgreSQL directly (break-glass, host shell = authz).

pub mod api;
pub mod breakglass;
pub mod commands;
pub mod env_export;
pub mod error;
pub mod session;

pub use error::CliError;
