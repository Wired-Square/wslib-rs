use std::io;
use std::path::Path;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The TLS listener's configuration, reloadable in place; clones share it.
#[derive(Clone, Debug)]
pub struct Tls(RustlsConfig);

impl Tls {
    /// Serve `config`, offering h2 and http/1.1 by ALPN unless it names its own.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self(RustlsConfig::from_config(with_alpn(config)))
    }

    /// Serve `config` to every connection from now on; open ones keep theirs.
    pub fn reload(&self, config: Arc<ServerConfig>) {
        self.0.reload_from_config(with_alpn(config));
    }

    pub(crate) fn config(&self) -> RustlsConfig {
        self.0.clone()
    }
}

/// Serve a config whose owner reloads it; its ALPN is the owner's to set.
impl From<RustlsConfig> for Tls {
    fn from(config: RustlsConfig) -> Self {
        Self(config)
    }
}

fn with_alpn(mut config: Arc<ServerConfig>) -> Arc<ServerConfig> {
    if config.alpn_protocols.is_empty() {
        Arc::make_mut(&mut config).alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    config
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
