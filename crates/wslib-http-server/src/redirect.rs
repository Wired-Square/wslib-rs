use std::io;

use axum::Router;
use axum::extract::State;
use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum_server::{Handle, Server};
use tokio::sync::watch;

use crate::{Listener, head_within, until_stopped};

/// Answer every request on `listener` with a 307 to the same host, path and
/// query on the TLS port `https_port` holds at the time, until `stop` completes
/// and it has drained.
pub async fn serve_redirect(
    listener: Listener,
    https_port: watch::Receiver<u16>,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    let bounds = listener.bounds;
    tracing::info!(address = %listener.local_addr(), "redirecting to https");
    let handle = Handle::new();
    // Cleartext h2 would let an unauthenticated peer hold streams open on a
    // listener with nothing to stream; an axum-server `map` after this would
    // clear `http1_only`.
    let mut server = Server::from_listener(listener)
        .http1_only()
        .handle(handle.clone());
    head_within(server.http_builder(), bounds.head).keep_alive(false);
    let serving = server.serve(redirect_router(https_port).into_make_service());
    until_stopped(serving, handle, stop, bounds.grace).await
}

/// The redirect as a router, for serving or testing in-process.
pub fn redirect_router(https_port: watch::Receiver<u16>) -> Router {
    Router::new().fallback(to_https).with_state(https_port)
}

// 307 because 301 and 302 may turn a POST into a GET, and browsers do; not 308,
// which is cached by default with the port in it, and the port can move.
async fn to_https(
    State(https_port): State<watch::Receiver<u16>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(host_without_port)
    else {
        return (StatusCode::BAD_REQUEST, "no usable Host header").into_response();
    };
    let authority = match *https_port.borrow() {
        443 => host,
        port => format!("{host}:{port}"),
    };
    let target = format!(
        "https://{authority}{}",
        uri.path_and_query().map_or("/", |p| p.as_str())
    );
    match HeaderValue::try_from(target) {
        Ok(location) => (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "unusable Host header").into_response(),
    }
}

fn host_without_port(raw: &str) -> Option<String> {
    let authority: Authority = raw.parse().ok()?;
    Some(authority.host())
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn redirected(port: u16, host: Option<&str>, path: &str) -> Response {
        let mut request = Request::post(path);
        if let Some(host) = host {
            request = request.header(header::HOST, host);
        }
        redirect_router(watch::channel(port).1)
            .oneshot(request.body(Body::empty()).expect("a request"))
            .await
            .expect("infallible")
    }

    fn location(response: &Response) -> &str {
        response.headers()[header::LOCATION]
            .to_str()
            .expect("ascii")
    }

    #[tokio::test]
    async fn a_request_is_sent_to_the_tls_port_with_its_path_and_query() {
        let response = redirected(8443, Some("box.local:80"), "/api/x?next=/settings").await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            location(&response),
            "https://box.local:8443/api/x?next=/settings"
        );
    }

    #[tokio::test]
    async fn the_standard_port_is_not_spelled_out() {
        let response = redirected(443, Some("box.local"), "/").await;
        assert_eq!(location(&response), "https://box.local/");
    }

    #[tokio::test]
    async fn an_ipv6_literal_keeps_its_brackets() {
        let response = redirected(8443, Some("[2001:db8::1]:8080"), "/").await;
        assert_eq!(location(&response), "https://[2001:db8::1]:8443/");
    }

    #[tokio::test]
    async fn a_request_with_no_usable_host_is_refused() {
        for host in [None, Some(":8080"), Some("[")] {
            let response = redirected(8443, host, "/").await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{host:?}");
        }
    }
}
