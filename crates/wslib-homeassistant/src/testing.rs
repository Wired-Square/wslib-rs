//! Requests as Home Assistant's ingress proxy sends them, for an app's tests.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request};

use crate::ingress::{DISPLAY_NAME, SUPERVISOR, USER_ID, USER_NAME};

/// `request` as if its connection came from the Supervisor.
pub fn trusted<B>(mut request: Request<B>) -> Request<B> {
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(SUPERVISOR, 40000)));
    request
}

/// The `X-Remote-User-*` headers the proxy names a user with.
#[derive(Clone, Debug)]
pub struct RemoteUser {
    id: String,
    name: Option<String>,
    display_name: Option<String>,
}

impl RemoteUser {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
            display_name: None,
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// `request` carrying these headers; panics on a value no header can hold.
    pub fn on<B>(self, mut request: Request<B>) -> Request<B> {
        let headers = request.headers_mut();
        for (name, value) in [
            (USER_ID, Some(self.id)),
            (USER_NAME, self.name),
            (DISPLAY_NAME, self.display_name),
        ] {
            if let Some(value) = value {
                let value = HeaderValue::try_from(value).expect("a header value");
                headers.insert(name, value);
            }
        }
        request
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::ingress::{Caller, Peers, gate};

    #[tokio::test]
    async fn a_trusted_request_naming_a_user_passes_the_gate_as_that_caller() {
        let app = gate(
            Router::new().route(
                "/who",
                get(async |caller: Option<Caller>| format!("{caller:?}")),
            ),
            &Peers::home_assistant(),
        );
        let request = || Request::get("/who").body(Body::empty()).unwrap();

        let refused = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);

        let named = RemoteUser::new("a1").name("admin").display_name("Admin");
        let response = app.oneshot(named.on(trusted(request()))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body,
            r#"Some(Caller { id: "a1", name: "admin", display_name: Some("Admin") })"#
        );
    }
}
