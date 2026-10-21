//! Loopback peers for tests: an authority that signs, a self-signed pair, and
//! a TLS listener presenting one. Each takes the provider to sign and serve with.

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyIdMethod, KeyUsagePurpose, SerialNumber,
};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use wslib_crypto::{KeyAlgorithm, Signer, random_serial};
use wslib_crypto_x509::SubjectAltName;

/// A certificate chain, leaf first, and its key.
#[derive(Debug)]
pub struct Pair {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// A certificate authority, for signing a peer's certificate.
pub struct Authority {
    pub certificate: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, Signer>,
}

impl Authority {
    pub fn new(provider: Arc<CryptoProvider>, name: &str) -> Self {
        let (signer, _) = generate(provider);
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        identify(&mut params, &signer);
        let certificate = params.self_signed(&signer).expect("signs").der().clone();
        Self {
            certificate,
            issuer: rcgen::Issuer::new(params, signer),
        }
    }

    /// A leaf for `names`, DNS names or addresses, signed by this authority.
    pub fn sign(&self, names: &[&str]) -> Pair {
        self.sign_with(names, |_| {})
    }

    pub(crate) fn sign_with(
        &self,
        names: &[&str],
        build: impl FnOnce(&mut CertificateParams),
    ) -> Pair {
        let (signer, key) = generate(self.issuer.key().provider().clone());
        let names = names.iter().map(ToString::to_string).collect::<Vec<_>>();
        let mut params = CertificateParams::new(names).expect("names");
        identify(&mut params, &signer);
        build(&mut params);
        let certificate = params.signed_by(&signer, &self.issuer).expect("signs");
        Pair {
            chain: vec![certificate.der().clone()],
            key,
        }
    }
}

/// A pair signed by nobody for `names`, as `wslib_crypto_x509::mint` makes it.
pub fn self_signed(provider: Arc<CryptoProvider>, names: &[&str]) -> Pair {
    let (signer, key) = generate(provider);
    let names: Vec<SubjectAltName> = names
        .iter()
        .map(|name| name.parse().expect("a name"))
        .collect();
    Pair {
        chain: vec![wslib_crypto_x509::mint(&signer, &names).expect("mints")],
        key,
    }
}

fn generate(provider: Arc<CryptoProvider>) -> (Signer, PrivateKeyDer<'static>) {
    let key = PrivateKeyDer::from(KeyAlgorithm::EcP256.generate().expect("generates"));
    (Signer::new(provider, &key).expect("loads"), key)
}

fn identify(params: &mut CertificateParams, signer: &Signer) {
    let serial = random_serial(signer.provider()).expect("random");
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.key_identifier_method = KeyIdMethod::PreSpecified(signer.key_identifier().to_vec());
}

/// A TLS listener on loopback presenting one pair, answering every request
/// with an empty 204 until it is dropped.
pub struct TlsPeer {
    pub addr: SocketAddr,
    accepting: tokio::task::JoinHandle<()>,
}

impl TlsPeer {
    pub async fn presenting(provider: Arc<CryptoProvider>, pair: &Pair) -> Self {
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS 1.2 or 1.3")
            .with_no_client_auth()
            .with_single_cert(pair.chain.clone(), pair.key.clone_key())
            .expect("a pair");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepting = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(socket).await else {
                        return;
                    };
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { addr, accepting }
    }

    /// Where to point [`Outbound::inspect`](crate::Outbound::inspect).
    pub fn target(&self) -> String {
        format!("https://{}", self.addr)
    }

    /// One handshake as `127.0.0.1` through `config`, and one request over it, answered.
    pub async fn handshake(&self, config: &Arc<ClientConfig>) -> std::io::Result<()> {
        let tcp = TcpStream::connect(self.addr).await?;
        let name = ServerName::try_from("127.0.0.1").expect("an address");
        let mut stream = TlsConnector::from(config.clone())
            .connect(name, tcp)
            .await?;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await?;
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await?;
        match answer.starts_with(b"HTTP/1.1 204") {
            true => Ok(()),
            false => Err(std::io::Error::other(format!(
                "answered {:?}",
                String::from_utf8_lossy(&answer)
            ))),
        }
    }
}

impl Drop for TlsPeer {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}
