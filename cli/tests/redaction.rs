//! Secrets must never appear in Debug output, and the env relay must not
//! rewrite a value.

use custos_cli::api::Credentials;
use custos_cli::session::Session;

fn sample_session() -> Session {
    Session {
        base_url: "http://127.0.0.1:8300".into(),
        cookie: "cu-test-COOKIE-SECRET".into(),
        csrf: "cu-test-CSRF-SECRET".into(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    }
}

#[test]
fn session_debug_redacts_the_cookie_and_csrf() {
    let text = format!("{:?}", sample_session());
    assert!(!text.contains("COOKIE-SECRET"), "cookie leaked: {text}");
    assert!(!text.contains("CSRF-SECRET"), "csrf leaked: {text}");
    assert!(text.contains("redacted"), "{text}");
    // the non-secret part stays useful for diagnostics
    assert!(text.contains("127.0.0.1:8300"), "{text}");
}

#[test]
fn credentials_debug_redacts_the_env_token() {
    let text = format!(
        "{:?}",
        Credentials::EnvToken("co-aaaaaaaaaaaa.TOKEN-SECRET-VALUE".into())
    );
    assert!(!text.contains("TOKEN-SECRET-VALUE"), "token leaked: {text}");
    assert!(text.contains("redacted"), "{text}");
    // and a session-bearing credential must not leak either
    let text = format!("{:?}", Credentials::Session(sample_session()));
    assert!(!text.contains("COOKIE-SECRET"), "{text}");
    assert!(!text.contains("CSRF-SECRET"), "{text}");
}
