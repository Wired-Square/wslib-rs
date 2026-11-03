mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use support::{BRIEF, PATIENT, Pair, dial, dial_tls, exchange, listener, provider};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use wslib_http_server::{
    Bounds, PeerCertificates, Tls, serve_https, server_config_from_pem,
    server_config_from_pem_files,
};

fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "hello" }))
        .route("/empty", get(|| async { StatusCode::NO_CONTENT }))
        .route("/peer", get(peer_leaf))
}

async fn peer_leaf(Extension(peer): Extension<PeerCertificates>) -> String {
    peer.end_entity()
        .map_or_else(|| "none".into(), |leaf| hex(leaf))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn serving(tls: Tls) -> SocketAddr {
    let listener = listener(Bounds::SERVING).await;
    let address = listener.local_addr();
    tokio::spawn(serve_https(listener, app(), tls, std::future::pending()));
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

/// As an owner that builds with axum-server's `from_pem`, which sets h2 and
/// http/1.1, and reloads with a config that sets no ALPN. `from_pem` reads the
/// process default, which rustls installs from this test binary's one provider.
#[tokio::test]
async fn a_shared_config_reloaded_by_its_owner_reaches_the_listener() {
    let (first, second) = (Pair::new(), Pair::new());
    let owned = RustlsConfig::from_pem(first.cert_pem.clone().into(), first.key_pem.clone().into())
        .await
        .expect("a config");
    let address = serving(Tls::from(owned.clone())).await;
    let before = dial_tls(address, &first.cert, &[b"h2", b"http/1.1"]).await;
    assert_eq!(negotiated(&before), Some(&b"h2"[..]));

    owned.reload_from_config(second.server_config());
    let after = dial_tls(address, &second.cert, &[b"h2", b"http/1.1"]).await;
    assert_eq!(presented(&before), first.cert);
    assert_eq!(presented(&after), second.cert);
    assert_eq!(
        negotiated(&after),
        None,
        "the owner's reload sets no ALPN, and the listener does not patch it"
    );
}

/// A client's certificate and key, and the authority that signed it.
struct Client {
    authority: CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl Client {
    fn new() -> Self {
        let authority_key = KeyPair::generate().expect("a key");
        let mut authority = CertificateParams::default();
        authority.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let authority_cert = authority.self_signed(&authority_key).expect("signs");
        let issuer = Issuer::new(authority, authority_key);

        let key = KeyPair::generate().expect("a key");
        let mut leaf = CertificateParams::default();
        leaf.distinguished_name.push(DnType::CommonName, "Session");
        let cert = leaf.signed_by(&key, &issuer).expect("signs");
        Self {
            authority: authority_cert.der().clone(),
            cert: cert.der().clone(),
            key: PrivateKeyDer::try_from(key.serialize_der()).expect("a key"),
        }
    }

    fn requiring_me(&self, pair: &Pair) -> Arc<rustls::ServerConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(self.authority.clone()).expect("a root");
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .expect("a verifier");
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(pair.server_config().cert_resolver.clone());
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

#[tokio::test]
async fn a_handler_sees_the_certificate_a_client_presented() {
    let (pair, client) = (Pair::new(), Client::new());
    let address = serving(Tls::new(client.requiring_me(&pair))).await;

    let mut roots = RootCertStore::empty();
    roots.add(pair.cert.clone()).expect("a root");
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![client.cert.clone()], client.key.clone_key())
        .expect("a client certificate");
    let mut stream = TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from("localhost").expect("a name"),
            dial(address).await,
        )
        .await
        .expect("handshake");

    let answer = exchange(&mut stream, "/peer").await.expect("an answer");
    assert!(answer.ends_with(&hex(&client.cert)), "{answer}");
}

#[tokio::test]
async fn a_handler_sees_no_certificate_from_a_client_that_presented_none() {
    let pair = Pair::new();
    let address = serving(Tls::new(pair.server_config())).await;
    let mut stream = dial_tls(address, &pair.cert, &[b"http/1.1"]).await;
    let answer = exchange(&mut stream, "/peer").await.expect("an answer");
    assert!(answer.ends_with("none"), "{answer}");
}

/// A route that answers once released, telling the test when it has begun.
fn holding(begun: Arc<Notify>, released: Arc<Notify>) -> Router {
    app().route(
        "/held",
        get(move || async move {
            begun.notify_one();
            released.notified().await;
            "released"
        }),
    )
}

async fn h2_over(
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> (h2::client::SendRequest<Bytes>, JoinHandle<()>) {
    let (client, connection) = h2::client::handshake(stream).await.expect("h2");
    (
        client,
        tokio::spawn(async {
            connection.await.ok();
        }),
    )
}

async fn ended(connection: JoinHandle<()>) -> bool {
    timeout(PATIENT, connection).await.is_ok()
}

fn get_request(path: &str) -> Request<()> {
    Request::get(format!("https://localhost{path}"))
        .body(())
        .expect("a request")
}

async fn body(response: h2::client::ResponseFuture) -> String {
    let mut body = response.await.expect("a response").into_body();
    let mut read = Vec::new();
    while let Some(chunk) = body.data().await {
        read.extend_from_slice(&chunk.expect("a chunk"));
    }
    String::from_utf8(read).expect("text")
}

#[tokio::test]
async fn a_renew_drains_open_connections_and_serves_new_ones_the_new_pair() {
    let (first, second) = (Pair::new(), Pair::new());
    let (begun, released) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let tls = Tls::new(first.server_config());
    let listener = listener(Bounds::SERVING).await;
    let address = listener.local_addr();
    let router = holding(begun.clone(), released.clone());
    tokio::spawn(serve_https(
        listener,
        router,
        tls.clone(),
        std::future::pending(),
    ));

    let (_idle, idle_ended) = h2_over(dial_tls(address, &first.cert, &[b"h2"]).await).await;
    let (mut busy, busy_ended) = h2_over(dial_tls(address, &first.cert, &[b"h2"]).await).await;
    let (in_flight, _) = busy.send_request(get_request("/held"), true).expect("sent");
    timeout(PATIENT, begun.notified()).await.expect("begun");

    tls.reload(second.server_config());
    tls.renew();
    assert!(ended(idle_ended).await, "an idle connection is sent away");

    let stream = dial_tls(address, &second.cert, &[b"h2"]).await;
    assert_eq!(presented(&stream), second.cert);
    let (mut fresh, _) = h2_over(stream).await;
    let (answer, _) = fresh.send_request(get_request("/"), true).expect("sent");
    assert_eq!(
        timeout(PATIENT, body(answer)).await.expect("answered"),
        "hello"
    );

    released.notify_one();
    assert_eq!(
        timeout(PATIENT, body(in_flight)).await.expect("finished"),
        "released"
    );
    assert!(
        ended(busy_ended).await,
        "a busy connection is closed once its request is done"
    );
}

#[tokio::test]
async fn a_connection_still_busy_at_the_grace_period_after_a_renew_is_closed() {
    let pair = Pair::new();
    let (begun, never) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let tls = Tls::new(pair.server_config());
    let listener = listener(Bounds {
        grace: BRIEF,
        ..Bounds::SERVING
    })
    .await;
    let address = listener.local_addr();
    let stop = CancellationToken::new();
    let serving = tokio::spawn(serve_https(
        listener,
        holding(begun.clone(), never),
        tls.clone(),
        stop.clone().cancelled_owned(),
    ));

    let (mut busy, busy_ended) = h2_over(dial_tls(address, &pair.cert, &[b"h2"]).await).await;
    let (_held, _) = busy.send_request(get_request("/held"), true).expect("sent");
    timeout(PATIENT, begun.notified()).await.expect("begun");
    tls.renew();
    assert!(ended(busy_ended).await, "closed at the grace period");

    let mut stream = dial_tls(address, &pair.cert, &[b"http/1.1"]).await;
    let answer = exchange(&mut stream, "/").await.expect("still accepting");
    assert!(answer.ends_with("hello"), "{answer}");

    stop.cancel();
    timeout(PATIENT, serving)
        .await
        .expect("stops")
        .expect("joined")
        .expect("served");
}
