//! `Server::serve_ingress`: the trusted peers, the proxy's asserted caller, and
//! everything an ingress app does not have.

use std::net::{Ipv4Addr, SocketAddr};

use axum::http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wslib_appliance_store::Store;
use wslib_appliance_types::{Branding, Role};

use crate::testing::{Harness, HarnessBuilder, Req, body_json, body_text};

use crate::{Ingress, ServeError, Server, logs};

const PROXY: &str = "172.30.32.2:40000";

/// Admin on first sight for `admin`, and nobody else.
fn ingress(bind: &str) -> Ingress {
    Ingress::new(bind.parse().unwrap(), |name| {
        (name == "admin").then_some(Role::Admin)
    })
}

fn through_ingress() -> HarnessBuilder {
    Harness::builder().ingress(ingress("0.0.0.0:8099"))
}

fn as_admin(request: Req) -> Req {
    request
        .from_peer(PROXY.parse().unwrap())
        .header("x-remote-user-id", "a1")
        .header("x-remote-user-name", "admin")
}

#[tokio::test]
async fn every_built_in_route_has_its_ingress_stance() {
    let app = through_ingress().build().await;
    for (method, path, status) in [
        ("GET", "/healthz", StatusCode::OK),
        ("GET", "/api/branding", StatusCode::OK),
        ("GET", "/api/audit", StatusCode::OK),
        ("GET", "/api/about", StatusCode::OK),
        ("GET", "/api/logs", StatusCode::OK),
        ("GET", "/api/tls/pins", StatusCode::OK),
        ("GET", "/api/session", StatusCode::OK),
        ("POST", "/api/session", StatusCode::METHOD_NOT_ALLOWED),
        ("PUT", "/api/session/password", StatusCode::NOT_FOUND),
        ("POST", "/api/onboarding", StatusCode::NOT_FOUND),
        ("GET", "/api/users", StatusCode::NOT_FOUND),
    ] {
        let response = as_admin(app.request(method, path)).send().await;
        assert_eq!(response.status(), status, "{method} {path}");
    }
    let unproxied = app.get("/api/branding").send().await;
    assert_eq!(unproxied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn healthz_answers_an_untrusted_peer_and_nothing_else_does() {
    let app = through_ingress().build().await;
    let elsewhere: SocketAddr = "172.30.32.3:40000".parse().unwrap();
    for (path, status) in [
        ("/healthz", StatusCode::OK),
        ("/api/branding", StatusCode::FORBIDDEN),
        ("/api/session", StatusCode::FORBIDDEN),
        ("/", StatusCode::FORBIDDEN),
    ] {
        let response = app.get(path).from_peer(elsewhere).send().await;
        assert_eq!(response.status(), status, "{path}");
    }
}

#[tokio::test]
async fn a_root_page_answers_the_proxy_under_its_ingress_path_and_no_other_peer() {
    async fn page(crate::Viewer(who): crate::Viewer, base: crate::RequestBase) -> String {
        format!("{} under {}", who.actor(), base.0.as_str())
    }
    let app = through_ingress()
        .root(axum::Router::new().route("/", axum::routing::get(page)))
        .build()
        .await;

    let page = as_admin(app.get("/"))
        .header("x-ingress-path", "/api/hassio_ingress/abc")
        .send()
        .await;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(
        body_text(page).await,
        "admin under /api/hassio_ingress/abc/"
    );
    let elsewhere: SocketAddr = "172.30.32.3:40000".parse().unwrap();
    let refused = app.get("/").from_peer(elsewhere).send().await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let nameless = app.get("/").from_peer(PROXY.parse().unwrap()).send().await;
    assert_eq!(nameless.status(), StatusCode::UNAUTHORIZED);
}

struct Nobody;

impl crate::ResolveCaller for Nobody {
    async fn resolve(
        &self,
        _: &axum::http::request::Parts,
    ) -> Result<Option<crate::Principal>, crate::ApiError> {
        Ok(None)
    }
}

#[tokio::test]
async fn a_later_front_leaves_no_ingress_gate_behind() {
    let app = through_ingress().resolver(Nobody).build().await;
    let branding = app.get("/api/branding").send().await;
    assert_eq!(branding.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_base_path_is_unused_and_the_page_names_the_ingress_path() {
    let bundle = tempfile::tempdir().unwrap();
    std::fs::write(bundle.path().join("index.html"), "<head></head>").unwrap();
    let app = through_ingress()
        .base_path("/apps/x/".parse().unwrap())
        .ui(bundle.path())
        .build()
        .await;
    let me = as_admin(app.get("/api/session")).send().await;
    assert_eq!(
        body_json(me).await,
        serde_json::json!({ "id": "a1", "username": "admin", "role": "admin" })
    );
    let page = as_admin(app.get("/"))
        .header("x-ingress-path", "/api/hassio_ingress/abc")
        .send()
        .await;
    assert_eq!(
        body_text(page).await,
        "<head><base href=\"/api/hassio_ingress/abc/\"></head>"
    );
}

async fn server() -> Server {
    let store = Store::open_in_memory(None).await.expect("store");
    Server::new(store, Branding::unbranded(), Harness::VERSION, logs(&[]))
}

#[tokio::test]
async fn serving_answers_the_proxy_once_ready_and_ends_ok_at_the_stop() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address: SocketAddr = listener.local_addr().unwrap();
    let loopback = ingress("0.0.0.0:0").trusted_peers([Ipv4Addr::LOCALHOST.into()]);
    let (stop, manager) = wslib_service::testing::stop();
    let server = server().await;
    let stopped = server.shutdown();
    let serving = tokio::spawn(server.serve_ingress_on(listener, loopback, stop));
    tokio::time::timeout(super::WITHIN, manager.ready())
        .await
        .expect("ready once listening");

    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    stream
        .write_all(
            b"GET /api/session HTTP/1.1\r\nhost: addon\r\nx-remote-user-id: a1\r\n\
              x-remote-user-name: admin\r\nconnection: close\r\n\r\n",
        )
        .await
        .expect("write");
    let mut answer = String::new();
    tokio::time::timeout(super::WITHIN, stream.read_to_string(&mut answer))
        .await
        .expect("answered")
        .expect("read");
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(
        answer.ends_with(r#"{"id":"a1","username":"admin","role":"admin"}"#),
        "{answer}"
    );

    manager.stop();
    let served = tokio::time::timeout(super::WITHIN, serving)
        .await
        .expect("drained in time")
        .expect("joined");
    assert!(served.is_ok(), "{served:?}");
    assert!(stopped.is_cancelled());
}

#[tokio::test]
async fn an_address_in_use_fails_the_start_and_fires_the_handle() {
    let taken = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server = server().await;
    let stopped = server.shutdown();
    let address = taken.local_addr().unwrap().to_string();
    let refused = server
        .serve_ingress(ingress(&address), std::future::pending())
        .await;
    assert!(
        matches!(refused, Err(ServeError::Bind { .. })),
        "{refused:?}"
    );
    assert!(stopped.is_cancelled());
}
