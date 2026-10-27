#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use wslib_http_server::{Bounds, Listener};

/// Short enough to wait out on the real clock; a paused clock jumps past a
/// server's timeout before the server has armed it.
pub const BRIEF: Duration = Duration::from_millis(200);

pub const PATIENT: Duration = Duration::from_secs(5);

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub struct Pair {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert: CertificateDer<'static>,
}

impl Pair {
    pub fn new() -> Self {
        let minted = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("mint");
        Self {
            cert_pem: minted.cert.pem(),
            key_pem: minted.signing_key.serialize_pem(),
            cert: minted.cert.der().clone(),
        }
    }

    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        wslib_http_server::server_config_from_pem(
            provider(),
            self.cert_pem.as_bytes(),
            self.key_pem.as_bytes(),
        )
        .expect("a server config")
    }
}

pub async fn listener(bounds: Bounds) -> Listener {
    Listener::bind((Ipv4Addr::LOCALHOST, 0).into(), bounds)
        .await
        .expect("bind")
}

pub async fn dial(address: SocketAddr) -> TcpStream {
    TcpStream::connect(address).await.expect("connect")
}

/// A TLS connection trusting only `cert`, offering `alpn`.
pub async fn dial_tls(
    address: SocketAddr,
    cert: &CertificateDer<'static>,
    alpn: &[&[u8]],
) -> TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("a root");
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from("localhost").expect("a name"),
            dial(address).await,
        )
        .await
        .expect("handshake")
}

/// One http/1.1 request, and everything the server sent before closing.
pub async fn exchange(
    peer: &mut (impl AsyncRead + AsyncWrite + Unpin),
    path: &str,
) -> Option<String> {
    peer.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .ok()?;
    let mut answer = Vec::new();
    tokio::time::timeout(PATIENT, peer.read_to_end(&mut answer))
        .await
        .ok()?
        .ok()?;
    Some(String::from_utf8_lossy(&answer).into_owned())
}

/// Whether the server answers a request on `peer` within `within`.
pub async fn answered(peer: &mut (impl AsyncRead + AsyncWrite + Unpin), within: Duration) -> bool {
    if peer
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .is_err()
    {
        return false;
    }
    let mut status = [0u8; 12];
    matches!(
        tokio::time::timeout(within, peer.read_exact(&mut status)).await,
        Ok(Ok(_))
    )
}

/// Whether the server closes `peer` within `within`.
pub async fn closed(peer: &mut (impl AsyncRead + Unpin), within: Duration) -> bool {
    let mut rest = Vec::new();
    matches!(
        tokio::time::timeout(within, peer.read_to_end(&mut rest)).await,
        Ok(Ok(_)) | Ok(Err(_))
    )
}
