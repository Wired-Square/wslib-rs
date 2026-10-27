//! What only an assembled appliance with sessions can show, driven through the
//! harness.

mod extract;
mod factors;
mod foreign_cookie;
mod listener;
mod reauth;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::http::{Request, Response};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::ApplianceState;
use crate::testing::Harness;

/// How long a test waits on the listener before calling it stuck.
pub(crate) const WITHIN: Duration = Duration::from_secs(5);

/// Each rung at `/rung/<role>`, and SessionAdmin at `/rung/session-admin`.
pub(crate) fn rungs() -> Router<ApplianceState> {
    use crate::{Admin, HostAdmin, Operator, SessionAdmin, Viewer};
    use axum::routing::get;

    Router::new()
        .route("/rung/viewer", get(|_: Viewer| async {}))
        .route("/rung/operator", get(|_: Operator| async {}))
        .route("/rung/admin", get(|_: Admin| async {}))
        .route("/rung/hostadmin", get(|_: HostAdmin| async {}))
        .route("/rung/session-admin", get(|_: SessionAdmin| async {}))
}

/// A TLS connection to the listener at `address`, trusting the `cert.pem` in
/// `dir` and, given `alpn`, offering only that protocol.
pub(crate) async fn dial_tls(
    dir: &Path,
    address: SocketAddr,
    alpn: Option<&[u8]>,
) -> TlsStream<TcpStream> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};

    let pem = std::fs::read_to_string(dir.join("cert.pem")).expect("the certificate");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pem.as_bytes()).expect("one certificate"))
        .expect("a root");
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = alpn.map(<[u8]>::to_vec).into_iter().collect();
    let peer = tokio::time::timeout(WITHIN, async {
        let tcp = TcpStream::connect(address).await.expect("tcp");
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(client))
            .connect(ServerName::try_from("127.0.0.1").expect("a name"), tcp)
            .await
            .expect("tls")
    })
    .await
    .expect("a handshake inside the timeout");
    if alpn.is_some() {
        assert_eq!(peer.get_ref().1.alpn_protocol(), alpn);
    }
    peer
}

/// `request`'s answer over h2 from `app`'s listener at `address`.
pub(crate) async fn over_h2(
    app: &Harness,
    address: SocketAddr,
    request: Request<()>,
) -> Response<h2::RecvStream> {
    tokio::time::timeout(WITHIN, async {
        let (mut h2, connection) =
            h2::client::handshake(dial_tls(app.dir(), address, Some(b"h2")).await)
                .await
                .expect("an h2 handshake");
        tokio::spawn(connection);
        let (answered, _) = h2.send_request(request, true).expect("sent");
        answered.await.expect("an answer")
    })
    .await
    .expect("an h2 answer inside the timeout")
}
