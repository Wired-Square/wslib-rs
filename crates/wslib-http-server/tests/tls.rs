mod support;

use std::net::SocketAddr;

use axum::Router;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use rustls::pki_types::CertificateDer;
use support::{Pair, dial_tls, exchange, listener};
use wslib_http_server::{
    Bounds, CancellationToken, Tls, serve_https, server_config_from_pem,
    server_config_from_pem_files,
};

fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "hello" }))
        .route("/empty", get(|| async { StatusCode::NO_CONTENT }))
}

async fn serving(tls: Tls) -> SocketAddr {
    let listener = listener(Bounds::SERVING).await;
    let address = listener.local_addr();
    tokio::spawn(serve_https(listener, app(), tls, CancellationToken::new()));
    address
}

fn negotiated(stream: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> Option<&[u8]> {
    stream.get_ref().1.alpn_protocol()
}

fn presented(
    stream: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> CertificateDer<'static> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .expect("a certificate")[0]
        .clone()
}

#[tokio::test]
async fn h2_is_chosen_by_alpn_and_answers() {
    let pair = Pair::new();
    let address = serving(Tls::new(pair.server_config())).await;
    let stream = dial_tls(address, &pair.cert, &[b"h2", b"http/1.1"]).await;
    assert_eq!(negotiated(&stream), Some(&b"h2"[..]));

    let (mut client, connection) = h2::client::handshake(stream).await.expect("h2");
    tokio::spawn(connection);
    let request = Request::get("https://localhost/empty")
        .body(())
        .expect("a request");
    let (response, _) = client.send_request(request, true).expect("sent");
    let response = response.await.expect("a response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        !response.headers().contains_key(header::CONTENT_LENGTH),
        "RFC 9110 §8.6: {:?}",
        response.headers()
    );
}

#[tokio::test]
async fn http1_is_served_to_a_client_that_offers_only_it() {
    let pair = Pair::new();
    let address = serving(Tls::new(pair.server_config())).await;
    let mut stream = dial_tls(address, &pair.cert, &[b"http/1.1"]).await;
    assert_eq!(negotiated(&stream), Some(&b"http/1.1"[..]));
    let answer = exchange(&mut stream, "/").await.expect("an answer");
    assert!(
        answer.starts_with("HTTP/1.1 200") && answer.ends_with("hello"),
        "{answer}"
    );
}

#[tokio::test]
async fn a_config_naming_its_own_alpn_keeps_it() {
    let pair = Pair::new();
    let mut config = (*pair.server_config()).clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let address = serving(Tls::new(config.into())).await;
    let stream = dial_tls(address, &pair.cert, &[b"h2", b"http/1.1"]).await;
    assert_eq!(negotiated(&stream), Some(&b"http/1.1"[..]));
}

#[tokio::test]
async fn a_reload_is_presented_to_the_next_connection() {
    let (first, second) = (Pair::new(), Pair::new());
    let tls = Tls::new(first.server_config());
    let address = serving(tls.clone()).await;
    let before = dial_tls(address, &first.cert, &[b"h2"]).await;

    tls.reload(second.server_config());
    let after = dial_tls(address, &second.cert, &[b"h2"]).await;
    assert_eq!(presented(&before), first.cert);
    assert_eq!(presented(&after), second.cert);
    assert_eq!(
        negotiated(&after),
        Some(&b"h2"[..]),
        "ALPN is set on a reload too"
    );
}

#[test]
fn the_pem_helper_reads_files() {
    let pair = Pair::new();
    let dir = std::env::temp_dir().join(format!("wslib-http-server-pem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, &pair.cert_pem).expect("write");
    std::fs::write(&key, &pair.key_pem).expect("write");

    let read = server_config_from_pem_files(support::provider(), &cert, &key);
    let missing = server_config_from_pem_files(support::provider(), &dir.join("absent.pem"), &key);
    std::fs::remove_dir_all(&dir).expect("cleaned up");

    read.expect("a server config");
    let missing = missing.expect_err("no file");
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    assert!(missing.to_string().contains("absent.pem"), "{missing}");
}

#[test]
fn the_pem_helper_refuses_what_is_not_a_pair() {
    let (pair, other) = (Pair::new(), Pair::new());
    let refused = |cert: &str, key: &str| {
        server_config_from_pem(support::provider(), cert.as_bytes(), key.as_bytes())
            .expect_err("refused")
            .kind()
    };
    assert_eq!(refused("", &pair.key_pem), std::io::ErrorKind::InvalidData);
    assert_eq!(refused(&pair.cert_pem, ""), std::io::ErrorKind::InvalidData);
    assert_eq!(
        refused(&pair.cert_pem, &other.key_pem),
        std::io::ErrorKind::InvalidData
    );
}
