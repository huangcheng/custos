//! Session storage contract (§9): 0600 file, 0700 dir, honour XDG_CONFIG_HOME,
//! and an env token is never persisted.

use std::os::unix::fs::PermissionsExt;

use custos_cli::session::{self, Session};
use tempfile::TempDir;

fn with_xdg() -> (TempDir, std::sync::MutexGuard<'static, ()>) {
    // Tests share process env: serialize them.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().expect("tempdir");
    std::env::set_var("XDG_CONFIG_HOME", dir.path());
    (dir, guard)
}

fn sample() -> Session {
    Session {
        base_url: "http://127.0.0.1:8300".into(),
        cookie: "cu-test-session-cookie".into(),
        csrf: "cu-test-csrf".into(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    }
}

#[test]
fn save_creates_a_0600_file_in_a_0700_dir() {
    let (dir, _guard) = with_xdg();
    let path = session::save(&sample()).expect("save");
    assert!(
        path.starts_with(dir.path()),
        "honours XDG_CONFIG_HOME: {path:?}"
    );

    let dir_mode = std::fs::metadata(path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "session directory must be 0700");

    let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600, "session file must be 0600");
}

#[test]
fn load_round_trips_and_reports_expiry() {
    let (_dir, _guard) = with_xdg();
    let mut fresh = sample();
    fresh.expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
    session::save(&fresh).expect("save");
    let loaded = session::load().expect("load").expect("some");
    assert_eq!(loaded.cookie, fresh.cookie);
    assert!(!loaded.is_expired(), "a live session is not expired");

    let mut stale = sample();
    stale.expires_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    session::save(&stale).expect("save");
    assert!(session::load().unwrap().unwrap().is_expired());
}

#[test]
fn clear_removes_the_file_but_not_the_dir() {
    let (_dir, _guard) = with_xdg();
    let path = session::save(&sample()).expect("save");
    session::clear().expect("clear");
    assert!(!path.exists(), "session file removed");
    assert!(path.parent().unwrap().exists(), "config dir kept");
    assert!(session::load().expect("load").is_none());
}

#[test]
fn no_session_yet_is_none_not_an_error() {
    let (_dir, _guard) = with_xdg();
    assert!(session::load().expect("load").is_none());
}

#[test]
fn an_env_token_is_never_persisted() {
    let (dir, _guard) = with_xdg();
    // Set an env token and confirm save() writes only session material.
    std::env::set_var(
        "CUSTOS_OPERATOR_TOKEN",
        "co-aaaaaaaaaaaa.THIS_MUST_NOT_BE_WRITTEN",
    );
    session::save(&sample()).expect("save");
    for entry in std::fs::read_dir(dir.path().join("custos")).unwrap() {
        let raw = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(
            !raw.contains("THIS_MUST_NOT_BE_WRITTEN"),
            "the env token must never reach disk"
        );
    }
    std::env::remove_var("CUSTOS_OPERATOR_TOKEN");
}
