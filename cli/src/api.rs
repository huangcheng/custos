//! HTTP client with the §9 credential rules.
//!
//! - `RouteClass::TokenPermitted` may use `CUSTOS_OPERATOR_TOKEN` or a session.
//! - `RouteClass::SessionOnly` (mint/revoke, purge, force-drop, retention,
//!   account management) requires the session file; an env-only caller gets a
//!   clear error instead of a request the server would 403.
//! - The two credentials are NEVER sent on one request.

use std::sync::{Arc, Mutex};

use reqwest::{Client as Http, Method};
use serde_json::Value;

use crate::session::Session;
use crate::CliError;

#[derive(Clone)]
pub enum Credentials {
    EnvToken(String),
    Session(Session),
}

impl std::fmt::Debug for Credentials {
    /// The env token is a live credential: never print it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::EnvToken(_) => f.write_str("EnvToken(<redacted>)"),
            Credentials::Session(session) => write!(f, "Session({session:?})"),
        }
    }
}

impl Credentials {
    pub fn describe(&self) -> &'static str {
        match self {
            Credentials::EnvToken(_) => "CUSTOS_OPERATOR_TOKEN",
            Credentials::Session(_) => "the session file",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    TokenPermitted,
    SessionOnly,
}

pub struct Client {
    http: Http,
    base_url: String,
    creds: Credentials,
    /// The session cookie from the last response (login captures it here).
    last_cookie: Arc<Mutex<Option<String>>>,
}

impl Client {
    pub fn new(base_url: impl Into<String>, creds: Credentials) -> Result<Self, CliError> {
        let base_url = base_url.into();
        let base_url = base_url.trim_end_matches('/').to_string();
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(CliError::Config(format!(
                "base URL must be http(s): {base_url}"
            )));
        }
        let http = Http::builder()
            .user_agent(concat!("custos-cli/", env!("CARGO_PKG_VERSION")))
            // an unreachable or stalled server must fail, not hang
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| CliError::Network(e.to_string()))?;
        Ok(Self {
            http,
            base_url,
            creds,
            last_cookie: Arc::new(Mutex::new(None)),
        })
    }

    pub fn credentials(&self) -> &Credentials {
        &self.creds
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The `custos_session` value the server most recently set.
    pub fn last_cookie(&self) -> Option<String> {
        self.last_cookie.lock().ok().and_then(|slot| slot.clone())
    }

    /// The step-up token is single-use; callers fetch one per gated call.
    pub async fn request(
        &self,
        method: Method,
        class: RouteClass,
        path: &str,
        body: Option<Value>,
        step_up: Option<&str>,
    ) -> Result<Value, CliError> {
        self.request_with_accept(method, class, path, body, step_up, "application/json")
            .await
    }

    /// Some endpoints answer `text/plain` (the env exports).
    pub async fn request_text(
        &self,
        method: Method,
        class: RouteClass,
        path: &str,
        step_up: Option<&str>,
    ) -> Result<String, CliError> {
        let http = self
            .request_raw(method, class, path, None, step_up, "text/plain")
            .await?;
        Ok(http)
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_with_accept(
        &self,
        method: Method,
        class: RouteClass,
        path: &str,
        body: Option<Value>,
        step_up: Option<&str>,
        accept: &str,
    ) -> Result<Value, CliError> {
        // The stored session is bound to the server that minted it: sending its
        // cookie to a different --url would hand a session to another host.
        if let Credentials::Session(session) = &self.creds {
            if session.base_url.trim_end_matches('/') != self.base_url {
                return Err(CliError::Config(format!(
                    "the stored session belongs to {} but --url is {}; run `custos login` \
                     against this server (or `custos logout`)",
                    session.base_url, self.base_url
                )));
            }
        }
        let text = self
            .request_raw(method, class, path, body, step_up, accept)
            .await?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text)
            .map_err(|e| CliError::Config(format!("unexpected response: {e}")))
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_raw(
        &self,
        method: Method,
        class: RouteClass,
        path: &str,
        body: Option<Value>,
        step_up: Option<&str>,
        accept: &str,
    ) -> Result<String, CliError> {
        let (bearer, csrf) = match (&self.creds, class) {
            (Credentials::EnvToken(token), RouteClass::TokenPermitted) => {
                (Some(token.as_str()), None)
            }
            (Credentials::Session(session), _) => (None, Some(session.csrf.as_str())),
            (Credentials::EnvToken(_), RouteClass::SessionOnly) => {
                return Err(CliError::Auth(
                    "this operation needs an interactive session; run `custos login` \
                     (CUSTOS_OPERATOR_TOKEN cannot mint or revoke credentials, purge, \
                     force-drop, or run retention)"
                        .into(),
                ))
            }
        };

        let mut req = self
            .http
            .request(method, format!("{}{}", self.base_url, path));
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        if let Credentials::Session(session) = &self.creds {
            req = req.header(
                reqwest::header::COOKIE,
                format!("custos_session={}", session.cookie),
            );
            if let Some(csrf) = csrf {
                req = req.header("x-csrf-token", csrf);
            }
        }
        if let Some(token) = step_up {
            req = req.header("x-step-up-token", token);
        }
        req = req.header(reqwest::header::ACCEPT, accept);
        if let Some(body) = body {
            req = req.json(&body);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| CliError::Network(e.to_string()))?;
        // capture the session cookie before the body is consumed
        for header in resp.headers().get_all(reqwest::header::SET_COOKIE) {
            if let Ok(raw) = header.to_str() {
                if let Some(rest) = raw.strip_prefix("custos_session=") {
                    let value = rest.split(';').next().unwrap_or("").to_string();
                    if !value.is_empty() {
                        if let Ok(mut slot) = self.last_cookie.lock() {
                            *slot = Some(value);
                        }
                    }
                }
            }
        }
        let status = resp.status();
        // A body-read failure is NOT an empty body: an interrupted 2xx must not
        // read as success.
        let text = resp
            .text()
            .await
            .map_err(|e| CliError::Network(format!("response read failed: {e}")))?;

        if status.is_success() {
            return Ok(text);
        }

        // The server's own envelope, verbatim (§9). Never echo the body of a
        // non-JSON failure: it could be a proxy page.
        if let Ok(envelope) = serde_json::from_str::<Value>(&text) {
            let code = envelope
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("error")
                .to_string();
            let message = envelope
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("request failed")
                .to_string();
            return Err(CliError::Server {
                status: status.as_u16(),
                code,
                message,
            });
        }
        Err(CliError::Server {
            status: status.as_u16(),
            code: "error".into(),
            message: format!("request failed with status {}", status.as_u16()),
        })
    }

    /// Percent-encode one path segment, so a name containing `/`, `..` or a
    /// query delimiter can never normalize to a different route.
    pub fn seg(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for byte in raw.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    // '.' is safe only when it is not a bare dot segment
                    out.push(byte as char)
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        // a bare "." / ".." would still collapse: escape the leading dot
        if out == "." || out == ".." {
            out = out.replace('.', "%2E");
        }
        out
    }

    pub async fn get(&self, class: RouteClass, path: &str) -> Result<Value, CliError> {
        self.request(Method::GET, class, path, None, None).await
    }

    pub async fn get_step_up(
        &self,
        class: RouteClass,
        path: &str,
        step_up: &str,
    ) -> Result<Value, CliError> {
        self.request(Method::GET, class, path, None, Some(step_up))
            .await
    }

    pub async fn post(
        &self,
        class: RouteClass,
        path: &str,
        body: Option<Value>,
        step_up: Option<&str>,
    ) -> Result<Value, CliError> {
        self.request(Method::POST, class, path, body, step_up).await
    }

    pub async fn put(
        &self,
        class: RouteClass,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, CliError> {
        self.request(Method::PUT, class, path, body, None).await
    }

    pub async fn patch(
        &self,
        class: RouteClass,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, CliError> {
        self.request(Method::PATCH, class, path, body, None).await
    }

    pub async fn delete(
        &self,
        class: RouteClass,
        path: &str,
        step_up: Option<&str>,
    ) -> Result<Value, CliError> {
        self.request(Method::DELETE, class, path, None, step_up)
            .await
    }
}
