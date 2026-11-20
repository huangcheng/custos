//! Session storage (§9): `$XDG_CONFIG_HOME/custos/session.json`, file 0600,
//! directory 0700. The env token is never written here.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::CliError;

const APP_DIR: &str = "custos";
const FILE: &str = "session.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub base_url: String,
    pub cookie: String,
    pub csrf: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        self.expires_at <= OffsetDateTime::now_utc()
    }
}

pub fn config_dir() -> Result<PathBuf, CliError> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(dirs::config_dir)
        .ok_or_else(|| {
            CliError::Config("cannot determine a config directory; set XDG_CONFIG_HOME".into())
        })?;
    Ok(base.join(APP_DIR))
}

pub fn session_path() -> Result<PathBuf, CliError> {
    Ok(config_dir()?.join(FILE))
}

/// Write the session. The directory is created 0700 and the file 0600 at
/// CREATE time — never `chmod` after the secret has hit the disk.
pub fn save(session: &Session) -> Result<PathBuf, CliError> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)?;
    // create_dir_all honours the umask; set the mode explicitly afterwards for
    // the directory only (it holds no secret yet).
    let mut dir_perms = fs::metadata(&dir)?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut dir_perms, 0o700);
    fs::set_permissions(&dir, dir_perms)?;

    let path = dir.join(FILE);
    // A FIXED temp name is a plant/race target inside the 0700 dir: derive a
    // unique one. Creates with O_EXCL so an existing path is never reused.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".{FILE}.{nonce}.tmp"));
    let body = serde_json::to_vec_pretty(session)?;
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        use std::io::Write;
        let mut file = opts.open(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    // atomic replace: a torn write must never leave a half session behind
    fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn load() -> Result<Option<Session>, CliError> {
    let path = session_path()?;
    match fs::metadata(&path) {
        Ok(meta) => {
            // The file carries the session cookie AND the CSRF token: a wider
            // mode (old version, copied backup, loose umask) must not be
            // consumed silently.
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(CliError::Config(format!(
                    "{} is mode {mode:o}; it must be 0600 — run `custos logout` and log in again",
                    path.display()
                )));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CliError::Io(err.to_string())),
    }
    let bytes = fs::read(&path)?;
    let session: Session = serde_json::from_slice(&bytes)
        .map_err(|e| CliError::Config(format!("session file is unreadable: {e}")))?;
    Ok(Some(session))
}

pub fn clear() -> Result<(), CliError> {
    let path = session_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CliError::Io(err.to_string())),
    }
}
