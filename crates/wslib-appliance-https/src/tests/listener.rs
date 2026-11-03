//! What the TLS listener puts on the wire, beyond `serve`'s own tests.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::{StatusCode, header};
use axum::routing::get;

use crate::testing::{Harness, body_bytes, body_text};
use crate::tests::{WITHIN, dial_tls, over_h2};

/// A handler reads the TLS peer's address as `ConnectInfo<SocketAddr>`, over
/// the listener and through the harness's stand-in for it.
#[tokio::test]
async fn a_handler_is_told_the_address_its_request_came_from() {
    async fn peer(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
        peer.ip().to_string()
    }
    let app = Harness::builder()
        .api(Router::new().route("/peer", get(peer)))
        .build()
        .await;
    let address = app.serve_tls().await;
    let request = axum::http::Request::get("https://box/api/peer")
        .body(())
        .expect("a request");
    let answered = over_h2(&app, address, request).await;
    assert_eq!(answered.status(), StatusCode::OK);
    let mut body = answered.into_body();
    let said = body.data().await.expect("a frame").expect("bytes");
    assert_eq!(&said[..], b"127.0.0.1");

    let from: SocketAddr = "[fd7a:115c:a1e0::9]:50000".parse().unwrap();
    let response = app.get("/api/peer").from_peer(from).send().await;
    assert_eq!(body_bytes(response).await, "fd7a:115c:a1e0::9");
}

/// An installed pair reaches the listener already serving, h2 and all, and
/// a connection open on the old one is closed.
#[tokio::test]
async fn an_installed_pair_is_served_to_the_next_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let app = Harness::new().await;
    let address = app.serve_tls().await;
    dial_tls(app.dir(), address, Some(b"h2")).await;
    let mut open = dial_tls(app.dir(), address, Some(b"http/1.1")).await;
    open.write_all(b"GET /api/branding HTTP/1.1\r\nHost: box\r\n\r\n")
        .await
        .expect("a request");
    let mut status = [0; 12];
    tokio::time::timeout(WITHIN, open.read_exact(&mut status))
        .await
        .expect("an answer inside the timeout")
        .expect("an answer");

    let elsewhere = tempfile::TempDir::new().expect("a directory");
    let pair = wslib_appliance_core::backend::minted_in(&elsewhere)
        .await
        .pair()
        .await
        .expect("read");
    app.state()
        .tls
        .install_pem(&pair.cert_pem, &pair.key_pem, None)
        .await
        .expect("installs");

    dial_tls(elsewhere.path(), address, Some(b"h2")).await;
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(WITHIN, open.read_to_end(&mut rest))
        .await
        .expect("the connection open before the install is closed");
}

#[tokio::test]
async fn a_304_carries_no_content_length_over_either_protocol() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let app = Harness::new().await;
    let address = app.serve_tls().await;

    let mut h1 = dial_tls(app.dir(), address, Some(b"http/1.1")).await;
    let mut answer = Vec::new();
    tokio::time::timeout(WITHIN, async {
        h1.write_all(
            b"GET /api/branding HTTP/1.1\r\nHost: box\r\nIf-None-Match: *\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("a request");
        h1.read_to_end(&mut answer).await.expect("an answer");
    })
    .await
    .expect("an answer inside the timeout");
    let answer = String::from_utf8_lossy(&answer).to_ascii_lowercase();
    assert!(answer.starts_with("http/1.1 304"), "{answer}");
    assert!(!answer.contains("content-length"), "{answer}");

    let request = axum::http::Request::get("https://box/api/branding")
        .header(header::IF_NONE_MATCH, "*")
        .body(())
        .expect("a request");
    let answered = over_h2(&app, address, request).await;
    assert_eq!(answered.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        answered.headers().get(header::CONTENT_LENGTH),
        None,
        "{:?}",
        answered.headers()
    );
}

#[tokio::test]
async fn a_root_page_answers_a_signed_in_browser_at_the_root_alone() {
    async fn page(crate::Viewer(who): crate::Viewer) -> String {
        format!("hello {}", who.actor())
    }
    let app = Harness::builder()
        .root(
            Router::new()
                .route("/", get(page))
                .route("/elsewhere", get(|| async { "shadowed" })),
        )
        .build()
        .await;
    let viewer = app
        .signed_in("viewer", wslib_appliance_types::Role::Viewer)
        .await;

    let response = app.get("/").cookie(&viewer).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, "hello viewer");
    assert_eq!(app.get("/").send().await.status(), StatusCode::UNAUTHORIZED);
    for path in ["/elsewhere", "/api/nope"] {
        let response = app.get(path).cookie(&viewer).send().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}
