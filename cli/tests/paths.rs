//! URL safety: a name or id can never normalize into a different route, and a
//! session is bound to the server that minted it.

use custos_cli::api::{Client, Credentials, RouteClass};

#[test]
fn segment_encoding_neutralizes_dot_segments_and_delimiters() {
    assert!(!Client::seg("..").contains('/'));
    assert_eq!(Client::seg("."), "%2E");
    assert_eq!(Client::seg(".."), "%2E%2E");
    assert_eq!(Client::seg("a/b"), "a%2Fb");
    assert_eq!(Client::seg("a?x=1&y=2"), "a%3Fx%3D1%26y%3D2");
    // ordinary names pass through untouched
    assert_eq!(Client::seg("stock-eu.1_2"), "stock-eu.1_2");
}

async fn session_client(session_base: &str, target: &str) -> Result<(), String> {
    let session = custos_cli::session::Session {
        base_url: session_base.into(),
        cookie: "cu-test-cookie".into(),
        csrf: "cu-test-csrf".into(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    };
    let client = Client::new(target, Credentials::Session(session)).map_err(|e| e.to_string())?;
    client
        .get(RouteClass::SessionOnly, "/api/admin/keys")
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn a_session_is_never_sent_to_a_different_server() {
    // target differs from the minting server: refused before any request
    let err = session_client("http://a.example", "http://b.example")
        .await
        .expect_err("must refuse");
    assert!(err.contains("belongs to"), "got: {err}");
}

#[tokio::test]
async fn a_session_only_route_refuses_an_env_token_without_a_request() {
    let client = Client::new(
        "http://127.0.0.1:9",
        Credentials::EnvToken("co-test".into()),
    )
    .expect("client");
    let err = client
        .get(RouteClass::SessionOnly, "/api/admin/keys")
        .await
        .expect_err("must refuse");
    let text = err.to_string();
    assert!(text.contains("interactive session"), "got: {text}");
}
