//! The half of `wslib-appliance-server`'s harness that needs no appliance: a request
//! through a router, its body read back, a peer to dial, and a second factor
//! to sign in with.

use std::convert::Infallible;

/// A host to dial, for a product that dials out.
pub use crate::tls::outbound::peer::{Authority, TlsPeer, self_signed};

pub use wslib_auth_passkey::testing::SoftPasskey;

pub use crate::state::Logo;
pub use crate::tls::inspect::inspect_pem;

#[doc(hidden)]
pub const ENCODERS: usize = wslib_http_scaffold::EncoderCap::DEFAULT;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, header};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::{Stream, StreamExt};
use tower::ServiceExt;

use crate::{ApplianceState, ControlRouter, Logs, Unclaimed};

/// One request, built up and sent through a router.
pub struct Req {
    router: Router,
    local: Option<ControlRouter>,
    /// Made the subscriber for the request's duration, as a real one would be.
    logs: Option<Logs>,
    method: &'static str,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<(String, Vec<u8>)>,
}

impl Req {
    #[doc(hidden)]
    pub fn new(router: Router, method: &'static str, path: &str) -> Self {
        Self {
            router,
            local: None,
            logs: None,
            method,
            path: path.to_string(),
            headers: Vec::new(),
            body: None,
        }
    }

    #[doc(hidden)]
    pub fn harnessed(self, local: ControlRouter, logs: Logs) -> Self {
        Self {
            local: Some(local),
            logs: Some(logs),
            ..self
        }
    }

    /// Send this over a control socket whose ceiling is Admin: it carries the
    /// socket's identity whatever else it asserts, so a
    /// [`SessionAdmin`](crate::SessionAdmin) route answers 403, never 401.
    pub fn local(mut self) -> Self {
        self.router = self
            .local
            .take()
            .expect("this harness has a control socket")
            .with_local_authority(wslib_appliance_types::Role::Admin);
        self
    }

    /// Without this a request has no peer address.
    pub fn from_peer(mut self, peer: std::net::SocketAddr) -> Self {
        self.router = self
            .router
            .layer(axum::Extension(axum::extract::ConnectInfo(peer)));
        self
    }

    /// Arrive on an app socket from the console, asserting `who`.
    pub fn from_console(self, who: &wslib_appliance_types::console::ConsoleIdentity) -> Self {
        self.on_app_socket().header(
            wslib_appliance_types::console::IDENTITY_HEADER,
            &who.to_string(),
        )
    }

    #[doc(hidden)]
    pub fn on_app_socket(mut self) -> Self {
        self.router = crate::console::arriving_from(self.router, 0, 0);
        self
    }

    #[doc(hidden)]
    pub fn on_hooks_socket(mut self) -> Self {
        self.router = crate::hooks::marked(self.router);
        self
    }

    pub fn cookie(self, token: &str) -> Self {
        let cookie = format!("{}={token}", crate::extract::SESSION_COOKIE);
        self.header(header::COOKIE.as_str(), &cookie)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn json(mut self, value: serde_json::Value) -> Self {
        self.body = Some((
            "application/json".to_string(),
            value.to_string().into_bytes(),
        ));
        self
    }

    pub fn body(mut self, content_type: &str, bytes: Vec<u8>) -> Self {
        self.body = Some((content_type.to_string(), bytes));
        self
    }

    pub fn maybe_json(self, value: Option<serde_json::Value>) -> Self {
        match value {
            Some(value) => self.json(value),
            None => self,
        }
    }

    pub async fn send(self) -> Response {
        let mut request = Request::builder().method(self.method).uri(&self.path);
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        let request = match self.body {
            Some((content_type, body)) => request
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body)),
            None => request.body(Body::empty()),
        }
        .expect("a well-formed test request");

        let answered = self.router.oneshot(request);
        match self.logs {
            Some(logs) => {
                use tracing::instrument::WithSubscriber;
                answered.with_subscriber(logs.ring().subscriber()).await
            }
            None => answered.await,
        }
        .expect("a router is infallible")
    }
}

/// Bounded by the largest thing any route answers, a backup included.
#[doc(hidden)]
pub async fn body_bytes(response: Response) -> Bytes {
    axum::body::to_bytes(
        response.into_body(),
        wslib_appliance_types::backup::MAX_BUNDLE_LEN,
    )
    .await
    .expect("a body")
}

#[doc(hidden)]
pub fn varies(response: &Response) -> Vec<&[u8]> {
    response
        .headers()
        .get_all(header::VARY)
        .iter()
        .map(|value| value.as_bytes())
        .collect()
}

pub async fn body_text(response: Response) -> String {
    String::from_utf8(body_bytes(response).await.to_vec()).expect("a UTF-8 body")
}

pub async fn body_json(response: Response) -> serde_json::Value {
    let bytes = body_bytes(response).await;
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "expected JSON, got {e}: {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

/// Run `body` with a capture layer installed for the duration.
#[doc(hidden)]
pub fn captured(logs: &Logs, body: impl FnOnce()) {
    tracing::subscriber::with_default(logs.ring().subscriber(), body);
}

#[doc(hidden)]
pub async fn first_frame<S>(sse: Sse<S>) -> String
where
    S: Stream<Item = Result<Event, Infallible>> + Send + 'static,
{
    let mut body = sse.into_response().into_body().into_data_stream();
    let frame = body.next().await.expect("a frame").expect("bytes");
    String::from_utf8(frame.to_vec()).unwrap()
}

#[doc(hidden)]
pub fn unclaimed() -> Unclaimed {
    Unclaimed(())
}

#[doc(hidden)]
pub fn product(state: &ApplianceState) -> &str {
    &state.about.product
}

#[doc(hidden)]
pub fn harness_branding(app_name: &str) -> wslib_appliance_types::Branding {
    let mut branding = wslib_appliance_types::Branding::unbranded();
    branding.app_name = app_name.to_string();
    branding.manufacturer = "A Manufacturer".to_string();
    branding.tokens = wslib_appliance_types::branding::ThemeTokens::new(
        [("--app-accent".to_string(), "#1b3f94".to_string())].into(),
    )
    .expect("a legal theme");
    branding
}

/// Waits for the bridge to write the row; panics if none lands within a second.
#[doc(hidden)]
pub async fn audit_row(
    store: &wslib_appliance_store::Store,
    message: &str,
) -> wslib_appliance_types::AuditRecord {
    let found = async {
        loop {
            let page = store.audit(100, None).await.expect("read the audit log");
            if let Some(row) = page.items.into_iter().find(|row| row.message == message) {
                return row;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), found)
        .await
        .unwrap_or_else(|_| panic!("no audit row {message:?} landed within a second"))
}

/// A [`Bootstrap`](wslib_appliance_config::Bootstrap) resolved by the real resolver
/// against an empty `config.toml` in `dir`; it opens nothing and sets nothing else.
pub fn bootstrap_in(dir: &std::path::Path) -> wslib_appliance_config::Bootstrap {
    let config = dir.join("config.toml");
    if !config.exists() {
        std::fs::write(&config, "").expect("a configuration file in the test's own directory");
    }
    wslib_appliance_config::Resolver::new("appliance-test", "APPLIANCE_TEST_ONLY")
        .resolve(&wslib_appliance_config::ApplianceArgs {
            config: Some(config),
            ..Default::default()
        })
        .expect("an empty configuration file resolves")
}

/// Each warning starts with a capital or a digit and ends with a full stop.
pub fn assert_sentences<'a>(warnings: impl IntoIterator<Item = &'a str>) {
    for warning in warnings {
        assert!(
            warning.starts_with(|c: char| c.is_uppercase() || c.is_ascii_digit())
                && warning.ends_with('.'),
            "not a sentence: {warning:?}"
        );
    }
}

#[cfg(unix)]
pub fn group_of(path: &std::path::Path) -> String {
    use std::os::unix::fs::MetadataExt;
    let gid = std::fs::metadata(path).expect("metadata").gid();
    // SAFETY: the name is copied out before anything else can look a group up.
    let entry = unsafe { libc::getgrgid(gid) };
    assert!(!entry.is_null(), "gid {gid} has a name");
    unsafe { std::ffi::CStr::from_ptr((*entry).gr_name) }
        .to_str()
        .expect("a UTF-8 group name")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "not a sentence")]
    fn a_warning_without_its_full_stop_is_not_a_sentence() {
        assert_sentences(["Restored.", "the rest was kept"]);
    }
}
