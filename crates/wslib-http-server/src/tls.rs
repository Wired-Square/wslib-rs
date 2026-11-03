use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use axum::Extension;
use axum::middleware::AddExtension;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;

/// The TLS listener's configuration, reloadable in place; clones share it.
#[derive(Clone, Debug)]
pub struct Tls {
    config: RustlsConfig,
    renewals: watch::Sender<()>,
}

impl Tls {
    /// Serve `config`, offering h2 and http/1.1 by ALPN unless it names its own.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self::from(RustlsConfig::from_config(with_alpn(config)))
    }

    /// Serve `config` to every connection from now on; open ones keep theirs
    /// until a [`renew`](Self::renew).
    pub fn reload(&self, config: Arc<ServerConfig>) {
        self.config.reload_from_config(with_alpn(config));
    }

    /// Close every open connection gracefully, so its peer reconnects on the
    /// configuration served now; each has the listener's grace period to
    /// finish the requests it has begun. New connections are still accepted.
    pub fn renew(&self) {
        self.renewals.send_replace(());
    }

    pub(crate) fn config(&self) -> RustlsConfig {
        self.config.clone()
    }

    pub(crate) fn renewals(&self) -> watch::Receiver<()> {
        self.renewals.subscribe()
    }
}

/// Serve a config whose owner reloads it; its ALPN is the owner's to set.
impl From<RustlsConfig> for Tls {
    fn from(config: RustlsConfig) -> Self {
        Self {
            config,
            renewals: watch::Sender::new(()),
        }
    }
}

fn with_alpn(mut config: Arc<ServerConfig>) -> Arc<ServerConfig> {
    if config.alpn_protocols.is_empty() {
        Arc::make_mut(&mut config).alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    config
}

/// The certificates a TLS client presented, leaf first, as verified by the
/// configuration's client verifier: an extension on each of its requests,
/// empty when it presented none.
#[derive(Clone, Debug, Default)]
pub struct PeerCertificates(Arc<[CertificateDer<'static>]>);

impl PeerCertificates {
    pub fn end_entity(&self) -> Option<&CertificateDer<'static>> {
        self.0.first()
    }

    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.0
    }
}

/// An acceptor whose connections' services add the [`PeerCertificates`] to each request.
#[derive(Clone)]
pub(crate) struct Identifying<A>(pub(crate) A);

impl<I, S, A, T> Accept<I, S> for Identifying<A>
where
    A: Accept<I, S, Stream = TlsStream<T>>,
    A::Future: Send + 'static,
{
    type Stream = TlsStream<T>;
    type Service = AddExtension<A::Service, PeerCertificates>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accepting = self.0.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = accepting.await?;
            let peer = PeerCertificates(
                stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .unwrap_or_default()
                    .into(),
            );
            Ok((stream, tower::Layer::layer(&Extension(peer), service)))
        })
    }
}

/// A server configuration from a PEM certificate chain and private key, on
/// `provider`.
pub fn server_config_from_pem(
    provider: Arc<CryptoProvider>,
    cert_chain: &[u8],
    key: &[u8],
) -> io::Result<Arc<ServerConfig>> {
    let chain = CertificateDer::pem_slice_iter(cert_chain)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(format!("reading the certificate chain: {e}")))?;
    if chain.is_empty() {
        return Err(invalid("the certificate chain holds no certificate".into()));
    }
    let key = PrivateKeyDer::from_pem_slice(key)
        .map_err(|e| invalid(format!("reading the private key: {e}")))?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|builder| builder.with_no_client_auth().with_single_cert(chain, key))
        .map_err(|e| invalid(e.to_string()))?;
    Ok(Arc::new(config))
}

/// [`server_config_from_pem`] from files.
pub fn server_config_from_pem_files(
    provider: Arc<CryptoProvider>,
    cert_chain: &Path,
    key: &Path,
) -> io::Result<Arc<ServerConfig>> {
    let read = |path: &Path| {
        std::fs::read(path)
            .map_err(|e| io::Error::new(e.kind(), format!("reading {}: {e}", path.display())))
    };
    server_config_from_pem(provider, &read(cert_chain)?, &read(key)?)
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
