use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use std::{fs, io};

use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_x509::pem::{self, CERTIFICATE, PRIVATE_KEY};
use wslib_crypto_x509::{CertificateView, Report, SubjectAltName};
use wslib_file_atomic::{CommitError, Options, RecordIdentity, Refused, Transaction};
use wslib_secret::Secret;

use crate::trust::authority;
use crate::{AnchorError, KeyFingerprint};

const DISPLACED: &str = "unusable";
const PROBE: &str = ".wslib-tls-write-probe";

/// Where the serving pair is kept, and whose files they are.
#[derive(Clone, Debug)]
pub struct Location {
    cert: PathBuf,
    key: PathBuf,
    named: bool,
}

impl Location {
    /// The app's own default location: an unusable pair here is moved aside and replaced.
    pub fn managed(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            cert: cert.into(),
            key: key.into(),
            named: false,
        }
    }

    /// Files an operator named: an unusable pair here is refused, never moved.
    pub fn named(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            named: true,
            ..Self::managed(cert, key)
        }
    }

    pub fn cert(&self) -> &Path {
        &self.cert
    }

    pub fn key(&self) -> &Path {
        &self.key
    }

    pub fn is_named(&self) -> bool {
        self.named
    }

    /// Where an interrupted write of the pair leaves its record: `<key file>.txn` beside the key.
    pub fn record(&self) -> PathBuf {
        wslib_file_atomic::beside(&self.key, "txn")
    }

    /// Finishes an interrupted write of the pair, refusing a record naming
    /// other files or one not this process's own; at a named location also
    /// one in a directory others may write, or on Windows any record, as
    /// [`ServingError::RecordRefused`].
    pub fn recover(&self) -> Result<(), ServingError> {
        recover(self, None)
    }

    /// The pair on disk, for a backup taken with nothing serving, after
    /// [`recover`](Self::recover); `None` when neither file is there.
    ///
    /// Whether the pair loads is not asked.
    pub fn read_pair(&self) -> Result<Option<ServingPair>, ServingError> {
        self.recover()?;
        self.read_present()
    }

    /// The pair on disk as [`read_pair`](Self::read_pair) reads it, writing
    /// nothing: [`ServingError::Interrupted`] while a write's record is there.
    ///
    /// The record is looked for once, before the read and without following a
    /// symlink, so a dangling one counts as interrupted; a commit racing the
    /// read can hand back the halves of two writes.
    pub fn read_pair_untouched(&self) -> Result<Option<ServingPair>, ServingError> {
        let record = self.record();
        match fs::symlink_metadata(&record) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.read_present(),
            Err(source) => Err(ServingError::Undetermined {
                path: record,
                source,
            }),
            Ok(_) => Err(ServingError::Interrupted { record }),
        }
    }

    fn read_present(&self) -> Result<Option<ServingPair>, ServingError> {
        match present(self)? {
            Present::Both => read_pair(self).map(Some),
            Present::Neither => Ok(None),
            Present::Half(half) => Err(half),
        }
    }
}

/// A serving pair as PEM text: the certificate chain, leaf first, and its private key.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServingPair {
    pub cert_pem: String,
    pub key_pem: Secret,
}

/// What [`Serving::install_pem`] put in place.
#[derive(Debug)]
#[non_exhaustive]
pub struct Installed {
    /// For the listener's reload.
    pub config: Arc<ServerConfig>,
    /// What is odd about the certificate; none of it refused the install.
    pub report: Report,
}

/// The certificate and key an app serves its own listener with, on the caller's provider.
#[derive(Debug)]
pub struct Serving {
    provider: Arc<CryptoProvider>,
    location: Location,
    configs: watch::Sender<Arc<ServerConfig>>,
    key: watch::Sender<KeyFingerprint>,
    alpn: Vec<Vec<u8>>,
    clients: Arc<dyn ClientCertVerifier>,
    cannot_replace: Option<(PathBuf, io::ErrorKind)>,
    /// Taken for each install, holding the record a failed commit left.
    installing: tokio::sync::Mutex<Option<RecordIdentity>>,
}

impl Serving {
    /// Loads the pair at `location`, or mints a self-signed one for the
    /// `names` asked for then, with a new `algorithm` key, as the crate doc says.
    ///
    /// Blocks: it reads and writes files, and RSA generation takes seconds.
    pub fn load_or_mint(
        provider: Arc<CryptoProvider>,
        location: Location,
        names: impl FnOnce() -> Vec<SubjectAltName>,
        algorithm: KeyAlgorithm,
    ) -> Result<Self, ServingError> {
        if let Err(failed) = recover(&location, None) {
            if location.named {
                return Err(named(location, failed));
            }
            tracing::warn!(
                key = %location.key.display(),
                because = %failed,
                "setting an interrupted write of the serving pair aside"
            );
            set_aside_interrupted(&location)?;
        }

        let unusable = match present(&location)? {
            Present::Both => match load(&provider, &location) {
                Ok(served) => return Ok(Self::new(provider, location, served)),
                Err(unusable) => unusable,
            },
            Present::Neither => return Self::mint(provider, location, &names(), algorithm),
            Present::Half(half) => half,
        };
        if location.named {
            return Err(named(location, unusable));
        }
        tracing::warn!(
            cert = %location.cert.display(),
            because = %unusable,
            "moving the serving pair aside and minting a fresh one"
        );
        displace(&location.cert)?;
        displace(&location.key)?;
        Self::mint(provider, location, &names(), algorithm)
    }

    fn new(provider: Arc<CryptoProvider>, location: Location, served: Served) -> Self {
        // Once, at startup: a directory that becomes unwritable later fails the write itself.
        let cannot_replace = writable(&location).err();
        Self {
            provider,
            location,
            configs: watch::Sender::new(served.config),
            key: watch::Sender::new(served.key),
            alpn: Vec::new(),
            clients: WebPkiClientVerifier::no_client_auth(),
            cannot_replace,
            installing: tokio::sync::Mutex::new(None),
        }
    }

    fn mint(
        provider: Arc<CryptoProvider>,
        location: Location,
        names: &[SubjectAltName],
        algorithm: KeyAlgorithm,
    ) -> Result<Self, ServingError> {
        tracing::info!(cert = %location.cert.display(), ?names, "minting a serving pair");
        let (pair, served) = mint_pair(&provider, names, algorithm)?;
        commit_pair(&location, &pair).map_err(|(error, _)| error)?;
        Ok(Self::new(provider, location, served))
    }

    /// Serves `protocols` as ALPN in every configuration from here on, the one
    /// being served included; none until then.
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn = protocols;
        self.configs.send_replace(self.dressed(self.config()));
        self
    }

    /// Requires every client to present a certificate one of `authorities`
    /// signed, in every configuration from here on, the one being served included.
    pub fn with_client_auth(
        mut self,
        authorities: &[CertificateDer<'_>],
    ) -> Result<Self, AnchorError> {
        let mut roots = RootCertStore::empty();
        for certificate in authorities {
            roots.roots.push(authority(certificate)?.1);
        }
        self.clients =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|_| AnchorError::NoneGiven)?;
        self.configs.send_replace(self.dressed(self.config()));
        Ok(self)
    }

    fn dressed(&self, config: Arc<ServerConfig>) -> Arc<ServerConfig> {
        let mut dressed = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("the pair's own configuration was built on this provider")
            .with_client_cert_verifier(self.clients.clone())
            .with_cert_resolver(config.cert_resolver.clone());
        dressed.alpn_protocols = self.alpn.clone();
        Arc::new(dressed)
    }

    /// The configuration being served, built on the caller's provider with the
    /// ALPN of [`with_alpn`](Self::with_alpn) and the client authentication of
    /// [`with_client_auth`](Self::with_client_auth).
    pub fn config(&self) -> Arc<ServerConfig> {
        self.configs.borrow().clone()
    }

    /// Each configuration a write puts in place, in the order written; the one
    /// being served is marked seen.
    ///
    /// A listener following it reloads some time after the write returns, not
    /// before; one that must serve the next connection with it reloads from
    /// the write's own configuration or [`config`](Self::config) instead.
    pub fn watch(&self) -> watch::Receiver<Arc<ServerConfig>> {
        self.configs.subscribe()
    }

    /// The SHA-256 of the served key's SubjectPublicKeyInfo, to pin; it holds
    /// while a chain over the same key replaces the certificate.
    pub fn key_fingerprint(&self) -> KeyFingerprint {
        *self.key.borrow()
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Whether [`install_pem`](Self::install_pem) could write the pair, as
    /// probed at startup: both directories must take a new file.
    pub fn replaceable(&self) -> Result<(), ServingError> {
        match &self.cannot_replace {
            Some((directory, kind)) => Err(ServingError::Unwritable {
                directory: directory.clone(),
                kind: *kind,
            }),
            None => Ok(()),
        }
    }

    /// Replaces the pair with one an operator holds, and returns the
    /// configuration to reload the listener with.
    ///
    /// Everything that can refuse the pair runs before a file is touched, the
    /// configuration included; installs are taken one at a time. `host` is the
    /// name the operator reached the app by and `now` the time, for the report.
    ///
    /// A restore installs its backup's pair here too, so the files have one writer.
    pub async fn install_pem(
        &self,
        cert_pem: &str,
        key_pem: &Secret,
        host: Option<&str>,
        now: SystemTime,
    ) -> Result<Installed, ServingError> {
        let pair = ServingPair {
            cert_pem: pem::normalise(cert_pem).map_err(ServingError::Certificate)?,
            key_pem: Secret::new(pem::normalise(key_pem.expose()).map_err(ServingError::Key)?),
        };
        let (chain, key, view) = parse(&self.provider, &pair)?;
        let report = wslib_crypto_x509::examine(view, host, now);
        let served = server_config(&self.provider, chain, key)?;
        let config = self.commit(pair, served).await?;
        Ok(Installed { config, report })
    }

    /// Replaces the pair with a fresh self-signed one for `names`, written as
    /// [`install_pem`](Self::install_pem) writes, and returns the configuration
    /// to reload the listener with.
    pub async fn regenerate(
        &self,
        names: &[SubjectAltName],
        algorithm: KeyAlgorithm,
    ) -> Result<Arc<ServerConfig>, ServingError> {
        let (provider, names) = (self.provider.clone(), names.to_vec());
        let (pair, served) = blocking(move || mint_pair(&provider, &names, algorithm)).await?;
        self.commit(pair, served).await
    }

    async fn commit(
        &self,
        pair: ServingPair,
        served: Served,
    ) -> Result<Arc<ServerConfig>, ServingError> {
        let config = self.dressed(served.config);
        let mut left = self.installing.lock().await;
        self.replaceable()?;
        self.after_recovery(&mut left, move |location| {
            match commit_pair(location, &pair) {
                Ok(()) => (Ok(()), None),
                Err((error, identity)) => (Err(error), identity),
            }
        })
        .await?;
        self.configs.send_replace(config.clone());
        self.key.send_replace(served.key);
        Ok(config)
    }

    /// The pair on disk, for a backup, after finishing an interrupted write;
    /// never one install's key beside another's certificate.
    pub async fn pair(&self) -> Result<ServingPair, ServingError> {
        let mut left = self.installing.lock().await;
        self.after_recovery(&mut left, |location| (read_pair(location), None))
            .await
    }

    /// Off the runtime, `then` once the record `left` is finished; a record
    /// not finished stays remembered, and `then` names the one it leaves.
    async fn after_recovery<T: Send + 'static>(
        &self,
        left: &mut Option<RecordIdentity>,
        then: impl FnOnce(&Location) -> (Result<T, ServingError>, Option<RecordIdentity>)
        + Send
        + 'static,
    ) -> Result<T, ServingError> {
        let (location, remembered) = (self.location.clone(), left.take());
        let (done, still_left) = blocking(move || match recover(&location, remembered.as_ref()) {
            Ok(()) => then(&location),
            Err(error) => (Err(error), remembered),
        })
        .await;
        *left = still_left;
        done
    }
}

fn named(location: Location, source: ServingError) -> ServingError {
    ServingError::Named {
        cert: location.cert,
        key: location.key,
        source: Box::new(source),
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServingError {
    #[error("cannot tell whether {} is there: {source}", path.display())]
    Undetermined { path: PathBuf, source: io::Error },
    /// Never completed with a generated half, which would not match.
    #[error("{} is there and {} is not", present.display(), missing.display())]
    HalfPair { present: PathBuf, missing: PathBuf },
    #[error("reading {}: {source}", path.display())]
    Unreadable { path: PathBuf, source: io::Error },
    #[error("{} holds no certificate", path.display())]
    NoCertificate { path: PathBuf },
    #[error("the certificate: {0}")]
    Certificate(#[source] wslib_crypto_x509::Error),
    #[error("the private key: {0}")]
    Key(#[source] wslib_crypto_x509::Error),
    #[error("the private key: {0}")]
    KeyRefused(#[source] wslib_crypto::Error),
    #[error("the private key does not belong to the certificate")]
    Mismatched,
    #[error("rustls will not serve the pair: {0}")]
    Refused(#[source] rustls::Error),
    #[error(
        "{} and {} were named, so they are not moved aside and replaced: {source}",
        cert.display(),
        key.display()
    )]
    Named {
        cert: PathBuf,
        key: PathBuf,
        source: Box<ServingError>,
    },
    #[error("moving {} aside: {source}", path.display())]
    Displace { path: PathBuf, source: io::Error },
    #[error(
        "an interrupted write cannot be finished; check {}, then move it aside by hand: {source}",
        record.display()
    )]
    Recover { record: PathBuf, source: io::Error },
    #[error(
        "an interrupted write's record is refused; check {}, then move it aside by hand: {source}",
        record.display()
    )]
    RecordRefused { record: PathBuf, source: io::Error },
    #[error("generating a key: {0}")]
    Generate(#[source] wslib_crypto::Error),
    #[error("minting a certificate: {0}")]
    Mint(#[source] wslib_crypto_x509::Error),
    #[error("writing {}, so nothing was replaced: {source}", path.display())]
    #[non_exhaustive]
    Write { path: PathBuf, source: io::Error },
    #[error(
        "the new pair is committed but not in place, and the old one is still served; {}: {source}",
        unfinished_next_step(record, *named)
    )]
    #[non_exhaustive]
    Unfinished {
        record: PathBuf,
        named: bool,
        source: io::Error,
    },
    #[error(
        "{} holds an interrupted write of the pair, which a start or a recover finishes",
        record.display()
    )]
    Interrupted { record: PathBuf },
    #[error("cannot write to {}: {kind}", directory.display())]
    Unwritable {
        directory: PathBuf,
        kind: io::ErrorKind,
    },
}

impl ServingError {
    /// What follows, for an error whose message says: [`Unfinished`](Self::Unfinished)'s.
    pub fn next_step(&self) -> Option<String> {
        match self {
            Self::Unfinished { record, named, .. } => Some(unfinished_next_step(record, *named)),
            _ => None,
        }
    }
}

fn unfinished_next_step(record: &Path, named: bool) -> String {
    let record = record.display();
    if named {
        format!(
            "the next write or backup read finishes it from {record}; a start refuses to serve \
             until the pair's files are checked and {record} is moved aside by hand, unless it \
             can and may finish it"
        )
    } else {
        format!(
            "the next write, backup read or start finishes it from {record}, or a start that \
             cannot sets it aside and serves the pair on disk, making a fresh one only if that \
             will not load"
        )
    }
}

enum Present {
    Both,
    Neither,
    Half(ServingError),
}

/// `try_exists`, as a file that could not be looked at is not a missing one to mint over.
fn present(location: &Location) -> Result<Present, ServingError> {
    let there = |path: &Path| {
        path.try_exists()
            .map_err(|source| ServingError::Undetermined {
                path: path.to_path_buf(),
                source,
            })
    };
    let (cert, key) = (&location.cert, &location.key);
    Ok(match (there(cert)?, there(key)?) {
        (true, true) => Present::Both,
        (false, false) => Present::Neither,
        (true, false) => Present::Half(ServingError::HalfPair {
            present: cert.clone(),
            missing: key.clone(),
        }),
        (false, true) => Present::Half(ServingError::HalfPair {
            present: key.clone(),
            missing: cert.clone(),
        }),
    })
}

fn load(provider: &Arc<CryptoProvider>, location: &Location) -> Result<Served, ServingError> {
    let (chain, key, _) = parse(provider, &read_pair(location)?)?;
    server_config(provider, chain, key)
}

/// The certificate file filtered to its `CERTIFICATE` sections, so what a backup carries is what an install takes.
fn read_pair(location: &Location) -> Result<ServingPair, ServingError> {
    let read = |path: &Path| {
        fs::read_to_string(path).map_err(|source| ServingError::Unreadable {
            path: path.to_path_buf(),
            source,
        })
    };
    let cert_pem =
        pem::certificate_sections(&read(&location.cert)?).map_err(ServingError::Certificate)?;
    if cert_pem.is_empty() {
        return Err(ServingError::NoCertificate {
            path: location.cert.clone(),
        });
    }
    Ok(ServingPair {
        cert_pem,
        key_pem: Secret::new(read(&location.key)?),
    })
}

fn parse(
    provider: &CryptoProvider,
    pair: &ServingPair,
) -> Result<
    (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        CertificateView,
    ),
    ServingError,
> {
    let chain = pem::certificates(&pair.cert_pem).map_err(ServingError::Certificate)?;
    let key = pem::private_key(pair.key_pem.expose()).map_err(ServingError::Key)?;
    let view = wslib_crypto_x509::inspect(&chain[0]).map_err(ServingError::Certificate)?;
    if !wslib_crypto::key_matches(provider, &key, &view.spki).map_err(ServingError::KeyRefused)? {
        return Err(ServingError::Mismatched);
    }
    Ok((chain, key, view))
}

fn mint_pair(
    provider: &Arc<CryptoProvider>,
    names: &[SubjectAltName],
    algorithm: KeyAlgorithm,
) -> Result<(ServingPair, Served), ServingError> {
    let key = PrivateKeyDer::from(algorithm.generate().map_err(ServingError::Generate)?);
    let signer = Signer::new(provider.clone(), &key).map_err(ServingError::KeyRefused)?;
    let cert = wslib_crypto_x509::mint(&signer, names).map_err(ServingError::Mint)?;
    let pair = ServingPair {
        cert_pem: pem::encode(CERTIFICATE, &cert),
        key_pem: Secret::new(pem::encode(PRIVATE_KEY, key.secret_der())),
    };
    Ok((pair, server_config(provider, vec![cert], key)?))
}

struct Served {
    config: Arc<ServerConfig>,
    key: KeyFingerprint,
}

fn server_config(
    provider: &Arc<CryptoProvider>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Served, ServingError> {
    let fingerprint = KeyFingerprint::of(&chain[0]).map_err(ServingError::Certificate)?;
    let config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .and_then(|builder| builder.with_no_client_auth().with_single_cert(chain, key))
        .map_err(ServingError::Refused)?;
    Ok(Served {
        config: Arc::new(config),
        key: fingerprint,
    })
}

/// The record sits beside the key and is named for it, so two pairs in one directory never share one.
fn transaction(location: &Location) -> (&Path, String) {
    let name = location.key.file_name().unwrap_or_default();
    (
        directory_of(&location.key),
        name.to_string_lossy().into_owned(),
    )
}

/// The record a commit `left` is finished without the trust checks while it
/// is still that file and names only this pair.
fn recover(location: &Location, left: Option<&RecordIdentity>) -> Result<(), ServingError> {
    let (record_dir, record) = transaction(location);
    let targets = [location.cert.as_path(), &location.key];
    let failed = |source: io::Error| {
        let record = location.record();
        if source.get_ref().is_some_and(|inner| inner.is::<Refused>()) {
            ServingError::RecordRefused { record, source }
        } else {
            ServingError::Recover { record, source }
        }
    };
    if let Some(identity) = left
        && wslib_file_atomic::recover_identified(record_dir, &record, &targets, identity)
            .map_err(failed)?
            .is_some()
    {
        return Ok(());
    }
    if location.named {
        named_record_acted_on(location)?;
    }
    wslib_file_atomic::recover_expecting(record_dir, &record, &targets)
        .map(drop)
        .map_err(failed)
}

/// Only a record that is there is judged, so a named pair in a shared directory still starts.
fn named_record_acted_on(location: &Location) -> Result<(), ServingError> {
    let record = location.record();
    let failed = |source| ServingError::Recover {
        record: location.record(),
        source,
    };
    match fs::symlink_metadata(&record) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        there => there.map(drop).map_err(failed)?,
    }
    #[cfg(unix)]
    let why = {
        use std::os::unix::fs::MetadataExt;
        let record_dir = directory_of(&record);
        let directory = fs::metadata(record_dir).map_err(failed)?;
        // SAFETY: a plain syscall with no arguments.
        let euid = unsafe { libc::geteuid() };
        if [euid, 0].contains(&directory.uid()) && directory.mode() & 0o022 == 0 {
            return Ok(());
        }
        format!(
            "{} may be written by others, so {} is not acted on",
            record_dir.display(),
            record.display()
        )
    };
    #[cfg(windows)]
    let why = format!(
        "{} is at a named location, so it is left for the operator",
        record.display()
    );
    Err(ServingError::RecordRefused {
        record,
        source: io::Error::new(io::ErrorKind::PermissionDenied, why),
    })
}

/// The staged files go aside before the record, as a record lost first would
/// strand a staged key with nothing naming it.
fn set_aside_interrupted(location: &Location) -> Result<(), ServingError> {
    let suffix = format!("{}.txn", transaction(location).1);
    displace(&wslib_file_atomic::beside(&location.cert, &suffix))?;
    displace(&wslib_file_atomic::beside(&location.key, &suffix))?;
    displace(&location.record())
}

/// Both or neither, across a crash, once [`recover`] has run; the key is
/// renamed into place first. Both `0600`, staged and renamed over the
/// targets, so a symlink there is replaced and not followed. A commit left
/// for recovery hands back its record's identity.
fn commit_pair(
    location: &Location,
    pair: &ServingPair,
) -> Result<(), (ServingError, Option<RecordIdentity>)> {
    let (record_dir, name) = transaction(location);
    let record = location.record();
    let unwritten = |path: &Path, source| {
        let path = path.to_path_buf();
        (ServingError::Write { path, source }, None)
    };
    let mut txn = Transaction::begin(record_dir, &name).map_err(|e| unwritten(&record, e))?;
    txn.stage(
        &location.key,
        pair.key_pem.expose().as_bytes(),
        &Options::new(),
    )
    .map_err(|e| unwritten(&location.key, e))?;
    txn.stage(&location.cert, pair.cert_pem.as_bytes(), &Options::new())
        .map_err(|e| unwritten(&location.cert, e))?;
    txn.commit_identified()
        .map_err(|(error, identity)| match error {
            CommitError::Committed(source) => {
                let (record, named) = (record.clone(), location.named);
                (
                    ServingError::Unfinished {
                        record,
                        named,
                        source,
                    },
                    identity,
                )
            }
            CommitError::RolledBack(source) => unwritten(&record, source),
            other => unwritten(&record, other.into()),
        })
}

/// Off the runtime's workers; a panic there is carried on here.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work)
        .await
        .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))
}

/// Into the first free `.unusable`, `.unusable.1`, …, so an earlier incident's file is kept.
fn displace(path: &Path) -> Result<(), ServingError> {
    for n in 0u32.. {
        let suffix = match n {
            0 => DISPLACED.to_string(),
            n => format!("{DISPLACED}.{n}"),
        };
        let aside = wslib_file_atomic::beside(path, &suffix);
        match rename_no_replace(path, &aside) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(ServingError::Displace {
                    path: path.to_path_buf(),
                    source,
                });
            }
            Ok(()) => {
                tracing::warn!(from = %path.display(), to = %aside.display(), "kept the unusable file");
                return Ok(());
            }
        }
    }
    unreachable!("a free name among four billion")
}

#[cfg(unix)]
fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

#[cfg(unix)]
fn os_result(status: libc::c_int) -> io::Result<()> {
    match status {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(unix)]
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(test)]
    let renamed = if tests::NO_REPLACE_UNSUPPORTED.get() {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    } else {
        rename_exclusive(from, to)
    };
    #[cfg(not(test))]
    let renamed = rename_exclusive(from, to);
    // ENOTSUP is EOPNOTSUPP on Linux and its own code on macOS.
    let unsupported = [libc::EINVAL, libc::ENOSYS, libc::EOPNOTSUPP, libc::ENOTSUP];
    match renamed {
        Err(e)
            if e.raw_os_error()
                .is_some_and(|code| unsupported.contains(&code)) =>
        {
            rename_without_the_flag(from, to)
        }
        renamed => renamed,
    }
}

/// A link refuses an existing name. A directory cannot be linked, so it is
/// renamed only to a name found free, which loses at most an empty directory
/// made there in between.
#[cfg(unix)]
fn rename_without_the_flag(from: &Path, to: &Path) -> io::Result<()> {
    if !fs::symlink_metadata(from)?.is_dir() {
        fs::hard_link(from, to)?;
        return fs::remove_file(from);
    }
    match fs::symlink_metadata(to) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::rename(from, to),
        Err(e) => Err(e),
        Ok(_) => Err(io::ErrorKind::AlreadyExists.into()),
    }
}

/// The raw call: glibc before 2.28 has no wrapper, and the libc crate binds
/// musl's only from 0.2.187.
#[cfg(target_os = "linux")]
fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let (from, to) = (c_path(from)?, c_path(to)?);
    // SAFETY: both paths are NUL-terminated and outlive the call.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    os_result(status as libc::c_int)
}

#[cfg(target_vendor = "apple")]
fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let (from, to) = (c_path(from)?, c_path(to)?);
    // SAFETY: both paths are NUL-terminated and outlive the call.
    os_result(unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) })
}

#[cfg(all(unix, not(any(target_os = "linux", target_vendor = "apple"))))]
fn rename_exclusive(_: &Path, _: &Path) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

#[cfg(windows)]
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
    let wide = |path: &Path| -> Vec<u16> { path.as_os_str().encode_wide().chain([0]).collect() };
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both paths are NUL-terminated and outlive the call; no
    // `MOVEFILE_REPLACE_EXISTING`, so an existing name is refused.
    match unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

/// The directories are probed, as a replacement writes new files into them
/// and renames them over the old: a read-only file in a writable directory is
/// replaceable.
fn writable(location: &Location) -> Result<(), (PathBuf, io::ErrorKind)> {
    let (cert_dir, key_dir) = (directory_of(&location.cert), directory_of(&location.key));
    probe(cert_dir)?;
    if key_dir != cert_dir {
        probe(key_dir)?;
    }
    Ok(())
}

/// `Path::parent` answers `Some("")` for a bare file name, which names nothing.
fn directory_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// `create_new` refuses a symlink rather than following it.
fn probe(directory: &Path) -> Result<(), (PathBuf, io::ErrorKind)> {
    let probe = directory.join(PROBE);
    let _ = fs::remove_file(&probe);
    let made = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe);
    let _ = fs::remove_file(&probe);
    made.map(drop)
        .map_err(|e| (directory.to_path_buf(), e.kind()))
}

#[cfg(test)]
mod tests {
    use wslib_crypto::Fingerprint;
    use wslib_crypto_x509::Warning;

    use super::*;
    use rustls::ClientConfig;
    use rustls_pki_types::ServerName;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::testing::{Authority, Pair, TlsPeer, providers, self_signed};
    use crate::{Outbound, Trust};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("wslib-tls-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn managed(&self) -> Location {
            Location::managed(self.join("cert.pem"), self.join("key.pem"))
        }

        fn named(&self) -> Location {
            Location::named(self.join("cert.pem"), self.join("key.pem"))
        }

        fn listing(&self) -> Vec<String> {
            let mut names: Vec<_> = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn start(provider: &Arc<CryptoProvider>, location: Location) -> Result<Serving, ServingError> {
        start_naming(provider, location, || {
            Vec::from(["widget-01", "127.0.0.1"].map(|name| name.parse().unwrap()))
        })
    }

    fn start_naming(
        provider: &Arc<CryptoProvider>,
        location: Location,
        names: impl FnOnce() -> Vec<SubjectAltName>,
    ) -> Result<Serving, ServingError> {
        Serving::load_or_mint(provider.clone(), location, names, KeyAlgorithm::EcP256)
    }

    fn another_pair(provider: &Arc<CryptoProvider>) -> (String, String) {
        let pair = self_signed(provider.clone(), &["127.0.0.1"]);
        (
            pem::encode(CERTIFICATE, &pair.chain[0]),
            pem::encode(PRIVATE_KEY, pair.key.secret_der()),
        )
    }

    async fn install(serving: &Serving, cert: &str, key: &str) -> Result<Installed, ServingError> {
        let (key, host) = (Secret::new(key), Some("127.0.0.1"));
        serving
            .install_pem(cert, &key, host, SystemTime::now())
            .await
    }

    fn fingerprint(cert_pem: &str) -> Fingerprint {
        Fingerprint::of(&pem::certificates(cert_pem).unwrap()[0])
    }

    fn on_disk(path: &Path) -> Fingerprint {
        fingerprint(&fs::read_to_string(path).unwrap())
    }

    fn write(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
    }

    async fn served(provider: &Arc<CryptoProvider>, config: Arc<ServerConfig>) -> Fingerprint {
        let peer = TlsPeer::serving(config).await;
        let outbound = Outbound::new(provider.clone(), Trust::default()).unwrap();
        Fingerprint::of(&outbound.inspect(&peer.target()).await.unwrap().end_entity)
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn a_first_start_mints_a_private_pair_and_a_second_start_serves_it() {
        for (name, provider) in providers() {
            let dir = Scratch::new(&format!("first-{name}"));
            let first = start(&provider, dir.managed()).expect(name);
            assert_eq!(dir.listing(), ["cert.pem", "key.pem"], "{name}");
            #[cfg(unix)]
            assert_eq!(
                (mode(&dir.join("cert.pem")), mode(&dir.join("key.pem"))),
                (0o600, 0o600),
                "{name}"
            );
            let minted = on_disk(&dir.join("cert.pem"));
            assert_eq!(served(&provider, first.config()).await, minted, "{name}");

            let second = start(&provider, dir.managed()).expect(name);
            assert_eq!(on_disk(&dir.join("cert.pem")), minted, "{name}");
            assert_eq!(served(&provider, second.config()).await, minted, "{name}");
            assert!(second.replaceable().is_ok(), "{name}");
        }
    }

    #[tokio::test]
    async fn the_key_fingerprint_follows_the_served_key_through_restarts_and_writes() {
        for (name, provider) in providers() {
            let dir = Scratch::new(&format!("key-fingerprint-{name}"));
            let on_disk = || {
                let pem = fs::read_to_string(dir.join("cert.pem")).unwrap();
                KeyFingerprint::of(&pem::certificates(&pem).unwrap()[0]).unwrap()
            };
            let serving = start(&provider, dir.managed()).expect(name);
            let minted = on_disk();
            assert_eq!(serving.key_fingerprint(), minted, "{name}");
            assert_eq!(
                start(&provider, dir.managed())
                    .expect(name)
                    .key_fingerprint(),
                minted,
                "{name}"
            );

            let names = ["widget-02".parse().unwrap()];
            let _ = serving
                .regenerate(&names, KeyAlgorithm::EcP256)
                .await
                .expect(name);
            assert_ne!(on_disk(), minted, "{name}");
            assert_eq!(serving.key_fingerprint(), on_disk(), "{name}");

            let (cert, key) = another_pair(&provider);
            let _ = install(&serving, &cert, &key).await.expect(name);
            assert_eq!(serving.key_fingerprint(), on_disk(), "{name}");
        }
    }

    #[test]
    fn an_unusable_pair_at_the_managed_location_is_kept_aside_and_replaced() {
        for (name, provider) in providers() {
            let (cert, key) = another_pair(&provider);
            let (_, other_key) = another_pair(&provider);
            let half = vec![("cert.pem", cert.clone())];
            let garbage = vec![("cert.pem", "not PEM".into()), ("key.pem", key.clone())];
            let mismatched = vec![("cert.pem", cert.clone()), ("key.pem", other_key)];
            for files in [half, garbage, mismatched] {
                let dir = Scratch::new(&format!("managed-{name}"));
                for (file, contents) in &files {
                    write(&dir.join(file), contents);
                }
                start(&provider, dir.managed()).expect(name);

                for (file, contents) in &files {
                    let aside = fs::read_to_string(dir.join(&format!("{file}.unusable")));
                    assert_eq!(&aside.unwrap(), contents, "{name}: {file}");
                }
                assert_ne!(on_disk(&dir.join("cert.pem")), fingerprint(&cert), "{name}");
                start(&provider, dir.managed()).expect("the fresh pair loads");
            }
        }
    }

    #[test]
    fn an_unusable_pair_at_a_named_location_is_refused_and_left_alone() {
        for (name, provider) in providers() {
            let (cert, key) = another_pair(&provider);
            let (_, other_key) = another_pair(&provider);
            let half = vec![("key.pem", key.clone())];
            let garbage = vec![("cert.pem", cert.clone()), ("key.pem", "not PEM".into())];
            let mismatched = vec![("cert.pem", cert.clone()), ("key.pem", other_key)];
            for files in [half, garbage, mismatched] {
                let dir = Scratch::new(&format!("named-{name}"));
                for (file, contents) in &files {
                    write(&dir.join(file), contents);
                }
                let before = dir.listing();

                let e = start(&provider, dir.named()).expect_err(name);
                assert!(
                    matches!(
                        &e,
                        ServingError::Named { source, .. } if matches!(
                            **source,
                            ServingError::HalfPair { .. } | ServingError::Key(_) | ServingError::Mismatched
                        )
                    ),
                    "{name}: {e}"
                );
                assert_eq!(dir.listing(), before, "{name}");
                for (file, contents) in &files {
                    assert_eq!(&fs::read_to_string(dir.join(file)).unwrap(), contents);
                }
            }
        }
    }

    #[tokio::test]
    async fn an_installed_pair_is_staged_written_and_kept_across_a_restart() {
        for (name, provider) in providers() {
            let dir = Scratch::new(&format!("install-{name}"));
            let serving = start(&provider, dir.managed()).expect(name);
            let (cert, key) = another_pair(&provider);
            let crlf = cert.replace('\n', "\r\n");

            let installed = install(&serving, &crlf, &key).await.expect(name);
            assert_eq!(installed.report.warnings, [], "{name}");
            assert_eq!(
                served(&provider, installed.config).await,
                fingerprint(&cert)
            );
            assert_eq!(serving.pair().await.unwrap().cert_pem, cert, "{name}");
            assert_eq!(dir.listing(), ["cert.pem", "key.pem"], "{name}");
            #[cfg(unix)]
            assert_eq!(mode(&dir.join("key.pem")), 0o600, "{name}");

            let restarted = start(&provider, dir.managed()).expect(name);
            assert_eq!(
                served(&provider, restarted.config()).await,
                fingerprint(&cert)
            );
        }
    }

    #[tokio::test]
    async fn the_report_is_made_at_the_time_given() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("clock");
        let serving = start(provider, dir.managed()).unwrap();
        let (cert, key) = another_pair(provider);

        let installed = serving
            .install_pem(&cert, &Secret::new(key), None, SystemTime::UNIX_EPOCH)
            .await
            .unwrap();
        assert_eq!(installed.report.warnings, [Warning::NotYetValid]);
    }

    #[tokio::test]
    async fn a_regenerated_pair_is_written_served_and_kept_across_a_restart() {
        for (name, provider) in providers() {
            let dir = Scratch::new(&format!("regenerate-{name}"));
            let serving = start(&provider, dir.managed()).expect(name);
            let before = on_disk(&dir.join("cert.pem"));

            let names = ["widget-02", "127.0.0.1"].map(|name| name.parse().unwrap());
            let config = serving
                .regenerate(&names, KeyAlgorithm::EcP256)
                .await
                .expect(name);
            let regenerated = on_disk(&dir.join("cert.pem"));
            assert_ne!(regenerated, before, "{name}");
            assert_eq!(served(&provider, config).await, regenerated, "{name}");
            assert_eq!(
                served(&provider, serving.config()).await,
                regenerated,
                "{name}"
            );
            assert_eq!(dir.listing(), ["cert.pem", "key.pem"], "{name}");

            let restarted = start(&provider, dir.managed()).expect(name);
            assert_eq!(
                served(&provider, restarted.config()).await,
                regenerated,
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn a_pair_that_is_not_one_is_refused_before_disk() {
        for (name, provider) in providers() {
            let dir = Scratch::new(&format!("refused-{name}"));
            let serving = start(&provider, dir.managed()).expect(name);
            let before = serving.pair().await.unwrap();
            let (cert, key) = another_pair(&provider);
            let (_, other_key) = another_pair(&provider);

            let mismatched = install(&serving, &cert, &other_key).await;
            assert!(
                matches!(mismatched, Err(ServingError::Mismatched)),
                "{name}"
            );
            let combined = install(&serving, &format!("{cert}{key}"), &key).await;
            assert!(
                matches!(
                    combined,
                    Err(ServingError::Certificate(
                        wslib_crypto_x509::Error::Beside { .. }
                    ))
                ),
                "{name}"
            );

            let after = serving.pair().await.unwrap();
            assert_eq!(
                (after.cert_pem, after.key_pem.expose()),
                (before.cert_pem, before.key_pem.expose())
            );
            assert_eq!(dir.listing(), ["cert.pem", "key.pem"], "{name}");
        }
    }

    #[tokio::test]
    async fn a_named_pair_sharing_a_stem_is_minted_and_replaced_without_colliding() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("stem");
        let location = Location::named(dir.join("app.crt"), dir.join("app.key"));
        let serving = start(provider, location).unwrap();
        let (cert, key) = another_pair(provider);
        install(&serving, &cert, &key).await.unwrap();
        assert_eq!(dir.listing(), ["app.crt", "app.key"]);
        assert_eq!(on_disk(&dir.join("app.crt")), fingerprint(&cert));
    }

    #[test]
    fn the_pair_on_disk_is_read_whole_or_not_at_all() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("read");
        assert!(dir.managed().read_pair().unwrap().is_none());

        let (cert, key) = another_pair(provider);
        write(&dir.join("cert.pem"), &cert);
        assert!(matches!(
            dir.managed().read_pair(),
            Err(ServingError::HalfPair { .. })
        ));

        write(&dir.join("cert.pem"), &format!("{key}{cert}"));
        write(&dir.join("key.pem"), &key);
        let pair = dir.managed().read_pair().unwrap().unwrap();
        assert!(!format!("{pair:?}").contains("PRIVATE KEY"));
        assert_eq!((pair.cert_pem, pair.key_pem.expose()), (cert, key.as_str()));
    }

    #[test]
    fn a_write_interrupted_before_its_commit_is_rolled_back_at_startup() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("interrupted");
        start(provider, dir.managed()).unwrap();
        let kept = on_disk(&dir.join("cert.pem"));

        let (cert, key) = another_pair(provider);
        let mut crashed = Transaction::begin(&dir.0, "key.pem").unwrap();
        crashed
            .stage(&dir.join("key.pem"), key.as_bytes(), &Options::new())
            .unwrap();
        crashed
            .stage(&dir.join("cert.pem"), cert.as_bytes(), &Options::new())
            .unwrap();
        std::mem::forget(crashed);

        start(provider, dir.managed()).unwrap();
        assert_eq!(on_disk(&dir.join("cert.pem")), kept);
        assert_eq!(dir.listing(), ["cert.pem", "key.pem"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_certificate_is_replaced_rather_than_followed() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("symlink");
        let serving = start(provider, dir.managed()).unwrap();
        let elsewhere = dir.join("elsewhere.pem");
        fs::rename(dir.join("cert.pem"), &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join("cert.pem")).unwrap();
        let untouched = fs::read_to_string(&elsewhere).unwrap();

        let (cert, key) = another_pair(provider);
        install(&serving, &cert, &key).await.unwrap();
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), untouched);
        assert!(
            !fs::symlink_metadata(dir.join("cert.pem"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(on_disk(&dir.join("cert.pem")), fingerprint(&cert));
    }

    fn occupy(path: &Path) {
        let _ = fs::remove_file(path);
        fs::create_dir(path).unwrap();
        write(&path.join("inside"), "");
    }

    /// Installs a pair whose certificate cannot be renamed into place, so the
    /// commit is left for recovery, then clears the way.
    async fn left_for_recovery(
        provider: &Arc<CryptoProvider>,
        serving: &Serving,
        dir: &Scratch,
    ) -> String {
        let (cert, key) = another_pair(provider);
        occupy(&dir.join("cert.pem"));
        let failed = install(serving, &cert, &key).await.unwrap_err();
        let ServingError::Unfinished { record, named, .. } = &failed else {
            panic!("{failed}");
        };
        assert_eq!(
            (record, *named),
            (&serving.location().record(), serving.location().is_named())
        );
        let next = failed.next_step().unwrap();
        assert!(next.contains(&record.display().to_string()), "{next}");
        assert!(failed.to_string().contains(&next), "{failed}");
        fs::remove_dir_all(dir.join("cert.pem")).unwrap();
        cert
    }

    #[tokio::test]
    async fn a_commit_left_at_a_named_location_names_the_record_to_move_aside() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("left-named");
        start(provider, dir.managed()).unwrap();
        let serving = start(provider, dir.named()).unwrap();
        let (cert, key) = another_pair(provider);
        occupy(&dir.join("cert.pem"));
        let failed = install(&serving, &cert, &key).await.unwrap_err();
        let record = serving.location().record().display().to_string();
        assert_eq!(
            failed.next_step().unwrap(),
            format!(
                "the next write or backup read finishes it from {record}; a start refuses to \
                 serve until the pair's files are checked and {record} is moved aside by hand, \
                 unless it can and may finish it"
            )
        );
    }

    #[tokio::test]
    async fn a_commit_left_for_recovery_is_finished_before_the_pair_is_read() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("left-then-read");
        let serving = start(provider, dir.managed()).unwrap();
        let cert = left_for_recovery(provider, &serving, &dir).await;
        assert_eq!(serving.pair().await.unwrap().cert_pem, cert);
        assert_eq!(dir.listing(), ["cert.pem", "key.pem"]);
    }

    #[tokio::test]
    async fn a_commit_left_for_recovery_is_finished_before_the_next_commit() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("left-then-commit");
        let serving = start(provider, dir.managed()).unwrap();
        left_for_recovery(provider, &serving, &dir).await;
        let (cert, key) = another_pair(provider);
        install(&serving, &cert, &key).await.unwrap();
        assert_eq!(on_disk(&dir.join("cert.pem")), fingerprint(&cert));
        assert_eq!(dir.listing(), ["cert.pem", "key.pem"]);
    }

    #[tokio::test]
    async fn the_location_finishes_an_interrupted_write_before_reading_the_pair() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("left-then-location");
        let serving = start(provider, dir.managed()).unwrap();
        let cert = left_for_recovery(provider, &serving, &dir).await;
        drop(serving);
        assert_eq!(dir.managed().read_pair().unwrap().unwrap().cert_pem, cert);

        left_for_recovery(provider, &start(provider, dir.managed()).unwrap(), &dir).await;
        dir.managed().recover().unwrap();
        assert_eq!(dir.listing(), ["cert.pem", "key.pem"]);
    }

    #[tokio::test]
    async fn the_record_is_where_a_commit_left_for_recovery_leaves_it() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("record-path");
        let serving = start(provider, dir.managed()).unwrap();
        left_for_recovery(provider, &serving, &dir).await;
        assert_eq!(dir.managed().record(), dir.join("key.pem.txn"));
        assert!(dir.managed().record().exists());
        let bare = Location::managed("cert.pem", "key.pem");
        assert_eq!(bare.record(), Path::new("key.pem.txn"));
    }

    /// A pending record naming a file the pair does not hold.
    fn plant_record(dir: &Scratch) {
        let elsewhere = fs::canonicalize(&dir.0).unwrap().join("elsewhere.pem");
        write(
            &dir.join("key.pem.txn"),
            &format!("pending\n{}\n", elsewhere.display()),
        );
    }

    #[test]
    fn a_refused_record_fails_a_read_and_nothing_is_set_aside_or_minted() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("refused-read");
        start(provider, dir.managed()).unwrap();
        plant_record(&dir);
        let before = dir.listing();
        for location in [dir.managed(), dir.named()] {
            let refused = location.read_pair().unwrap_err();
            let ServingError::RecordRefused { record, .. } = &refused else {
                panic!("{refused}");
            };
            assert_eq!(record, &location.record());
            assert!(refused.to_string().contains("by hand"), "{refused}");
            assert!(matches!(
                location.recover(),
                Err(ServingError::RecordRefused { .. })
            ));
        }
        assert_eq!(dir.listing(), before);
    }

    #[tokio::test]
    async fn a_refused_record_fails_the_served_pair_and_a_commit() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("refused-serving");
        let serving = start(provider, dir.managed()).unwrap();
        plant_record(&dir);
        let before = dir.listing();
        assert!(matches!(
            serving.pair().await,
            Err(ServingError::RecordRefused { .. })
        ));
        let (cert, key) = another_pair(provider);
        let refused = install(&serving, &cert, &key).await.map(drop);
        assert!(
            matches!(refused, Err(ServingError::RecordRefused { .. })),
            "{refused:?}"
        );
        assert_eq!(dir.listing(), before);
    }

    #[cfg(unix)]
    fn loosen(dir: &Scratch) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o777)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_record_in_a_named_directory_others_may_write_is_refused() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("named-loose-dir");
        start(provider, dir.named()).unwrap();
        let mut crashed = Transaction::begin(&dir.0, "key.pem").unwrap();
        crashed
            .stage(&dir.join("key.pem"), b"staged", &Options::new())
            .unwrap();
        std::mem::forget(crashed);
        loosen(&dir);
        let before = dir.listing();

        let refused = dir.named().recover().unwrap_err();
        let ServingError::RecordRefused { source, .. } = &refused else {
            panic!("{refused}");
        };
        assert!(
            source.to_string().contains(&*dir.0.to_string_lossy()),
            "{source}"
        );
        assert_named(start(provider, dir.named()), |source| {
            matches!(source, ServingError::RecordRefused { .. })
        });
        assert_eq!(dir.listing(), before);
        dir.managed().recover().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn any_record_at_a_named_location_is_left_for_the_operator() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("named-windows");
        start(provider, dir.named()).unwrap();
        std::mem::forget(Transaction::begin(&dir.0, "key.pem").unwrap());
        let before = dir.listing();
        let refused = dir.named().recover();
        assert!(
            matches!(&refused, Err(ServingError::RecordRefused { .. })),
            "{refused:?}"
        );
        assert_named(start(provider, dir.named()), |source| {
            matches!(source, ServingError::RecordRefused { .. })
        });
        assert_eq!(dir.listing(), before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_serving_finishes_the_record_its_own_commit_left_whatever_its_directory() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("own-record");
        let serving = start(provider, dir.named()).unwrap();
        loosen(&dir);
        let cert = left_for_recovery(provider, &serving, &dir).await;
        assert!(
            dir.named().recover().is_err(),
            "another reader gets the full checks"
        );
        assert_eq!(serving.pair().await.unwrap().cert_pem, cert);
        assert_eq!(dir.listing(), ["cert.pem", "key.pem"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_record_swapped_after_a_failed_commit_gets_the_full_checks() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("swapped-record");
        let serving = start(provider, dir.named()).unwrap();
        loosen(&dir);
        left_for_recovery(provider, &serving, &dir).await;
        let (record, swapped) = (dir.join("key.pem.txn"), dir.join("swapped"));
        fs::copy(&record, &swapped).unwrap();
        fs::rename(&swapped, &record).unwrap();
        assert!(matches!(
            serving.pair().await,
            Err(ServingError::RecordRefused { .. })
        ));
        assert!(record.exists());
    }

    /// A committed write whose certificate cannot be renamed into place
    /// because a directory is there.
    fn wedged(dir: &Scratch) {
        let (cert, key) = another_pair(&providers()[0].1);
        let mut crashed = Transaction::begin(&dir.0, "key.pem").unwrap();
        crashed
            .stage(&dir.join("key.pem"), key.as_bytes(), &Options::new())
            .unwrap();
        crashed
            .stage(&dir.join("cert.pem"), cert.as_bytes(), &Options::new())
            .unwrap();
        occupy(&dir.join("cert.pem"));
        assert!(crashed.commit().is_err());
    }

    #[test]
    fn a_recover_that_fails_at_the_managed_location_is_set_aside_and_the_start_goes_on() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("wedged-managed");
        start(provider, dir.managed()).unwrap();
        wedged(&dir);

        start(provider, dir.managed()).unwrap();
        assert_eq!(
            dir.listing(),
            [
                "cert.pem",
                "cert.pem.key.pem.txn.unusable",
                "cert.pem.unusable",
                "key.pem",
                "key.pem.txn.unusable",
                "key.pem.unusable",
            ]
        );
        start(provider, dir.managed()).expect("the fresh pair loads");
    }

    #[test]
    fn a_half_rolled_pair_left_by_a_set_aside_is_mismatched_and_replaced() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("half-rolled");
        start(provider, dir.managed()).unwrap();
        let old_key = fs::read_to_string(dir.join("key.pem")).unwrap();
        let (new_cert, _) = another_pair(provider);
        let canonical = fs::canonicalize(&dir.0).unwrap();
        write(
            &dir.join("key.pem.txn"),
            &format!(
                "committed\n{}\n{}\n",
                canonical.join("cert.pem").display(),
                canonical.join("key.pem").display()
            ),
        );
        write(&dir.join("cert.pem.key.pem.txn"), &new_cert);
        occupy(&dir.join("key.pem.key.pem.txn"));

        start(provider, dir.managed()).unwrap();
        assert!(dir.join("key.pem.txn.unusable").exists());
        assert_eq!(
            fs::read_to_string(dir.join("cert.pem.unusable")).unwrap(),
            new_cert
        );
        assert_eq!(
            fs::read_to_string(dir.join("key.pem.unusable")).unwrap(),
            old_key
        );
        let displaced =
            Location::named(dir.join("cert.pem.unusable"), dir.join("key.pem.unusable"));
        assert!(matches!(
            load(provider, &displaced),
            Err(ServingError::Mismatched)
        ));
        assert_ne!(on_disk(&dir.join("cert.pem")), fingerprint(&new_cert));
        start(provider, dir.managed()).expect("the fresh pair loads");
    }

    #[test]
    fn a_recover_that_fails_at_a_named_location_is_an_error_and_nothing_moves() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("wedged-named");
        start(provider, dir.named()).unwrap();
        wedged(&dir);
        let before = dir.listing();

        assert_named(start(provider, dir.named()), |source| match source {
            ServingError::RecordRefused { .. } => cfg!(windows),
            ServingError::Recover { record, .. } => {
                *record == dir.named().record() && source.to_string().contains("by hand")
            }
            _ => false,
        });
        assert_eq!(dir.listing(), before);
    }

    fn assert_named(
        started: Result<Serving, ServingError>,
        expected: impl FnOnce(&ServingError) -> bool,
    ) {
        match started {
            Err(ServingError::Named { source, .. }) if expected(&source) => {}
            other => panic!("{:?}", other.map(drop)),
        }
    }

    #[test]
    fn the_names_are_asked_for_only_when_minting() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("names-on-mint");
        let asked = std::cell::Cell::new(0);
        let names = || {
            asked.set(asked.get() + 1);
            vec!["widget-01".parse().unwrap()]
        };
        start_naming(provider, dir.managed(), names).unwrap();
        start_naming(provider, dir.managed(), names).unwrap();
        assert_eq!(asked.get(), 1);
    }

    #[tokio::test]
    async fn each_written_configuration_is_sent_to_the_watchers_in_order() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("watch");
        let serving = start(provider, dir.managed()).unwrap();
        let mut configs = serving.watch();
        assert!(Arc::ptr_eq(&configs.borrow(), &serving.config()));
        assert!(!configs.has_changed().unwrap());

        let (cert, key) = another_pair(provider);
        let installed = install(&serving, &cert, &key).await.unwrap();
        let regenerated = serving
            .regenerate(&["widget-02".parse().unwrap()], KeyAlgorithm::EcP256)
            .await
            .unwrap();
        assert!(configs.has_changed().unwrap());
        assert!(Arc::ptr_eq(&configs.borrow_and_update(), &regenerated));
        assert!(!Arc::ptr_eq(&installed.config, &regenerated));

        let (_, other_key) = another_pair(provider);
        install(&serving, &cert, &other_key).await.unwrap_err();
        left_for_recovery(provider, &serving, &dir).await;
        assert!(
            !configs.has_changed().unwrap(),
            "only a write in place is sent"
        );
    }

    #[tokio::test]
    async fn the_alpn_asked_for_is_served_by_every_configuration() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("alpn");
        let started = start(provider, dir.managed()).unwrap();
        assert!(started.config().alpn_protocols.is_empty());
        let mut configs = started.watch();
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let serving = started.with_alpn(alpn.clone());
        assert_eq!(serving.config().alpn_protocols, alpn);
        assert_eq!(configs.borrow_and_update().alpn_protocols, alpn);

        let (cert, key) = another_pair(provider);
        let installed = install(&serving, &cert, &key).await.unwrap();
        assert_eq!(installed.config.alpn_protocols, alpn);
        assert_eq!(configs.borrow_and_update().alpn_protocols, alpn);
        let regenerated = serving
            .regenerate(&["widget-02".parse().unwrap()], KeyAlgorithm::EcP256)
            .await
            .unwrap();
        assert_eq!(regenerated.alpn_protocols, alpn);
        assert!(Arc::ptr_eq(&configs.borrow(), &serving.config()));
    }

    /// One handshake from `client` to `config` over loopback, and the leaf the server verified.
    async fn admitted(
        config: Arc<ServerConfig>,
        client: ClientConfig,
    ) -> io::Result<Option<CertificateDer<'static>>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accepting = async {
            let (tcp, _) = listener.accept().await?;
            let stream = TlsAcceptor::from(config).accept(tcp).await?;
            Ok(stream
                .get_ref()
                .1
                .peer_certificates()
                .map(|chain| chain[0].clone()))
        };
        let dialling = async {
            let tcp = TcpStream::connect(addr).await?;
            let name = ServerName::try_from("127.0.0.1").expect("an address");
            TlsConnector::from(Arc::new(client))
                .connect(name, tcp)
                .await
        };
        tokio::join!(accepting, dialling).0
    }

    #[tokio::test]
    async fn a_server_requiring_client_auth_admits_only_what_its_authority_signed_and_sees_who() {
        for (name, provider) in providers() {
            let dir = Scratch::new(&format!("client-auth-{name}"));
            let clients = Authority::new(provider.clone(), "Client Root");
            let serving = start(&provider, dir.managed())
                .unwrap()
                .with_client_auth(std::slice::from_ref(&clients.certificate))
                .unwrap();
            let mut trust = Trust::default();
            trust.pin(
                "127.0.0.1",
                fingerprint(&serving.pair().await.unwrap().cert_pem),
            );
            let outbound = Arc::new(Outbound::new(provider.clone(), trust).unwrap());
            let presenting = |pair: Pair| {
                outbound
                    .client_config_presenting(pair.chain, pair.key)
                    .unwrap()
            };

            let none = admitted(serving.config(), outbound.client_config()).await;
            assert!(none.is_err(), "{name}: no certificate");
            let stranger = Authority::new(provider.clone(), "Client Root").sign_client("Session");
            let foreign = admitted(serving.config(), presenting(stranger)).await;
            assert!(foreign.is_err(), "{name}: another authority's");

            let client = clients.sign_client("Session");
            let presented = client.chain[0].clone();
            let seen = admitted(serving.config(), presenting(client))
                .await
                .expect(name)
                .expect("a client certificate");
            assert_eq!(seen, presented, "{name}");
            let (seen, presented) = (
                wslib_crypto_x509::inspect(&seen).unwrap(),
                wslib_crypto_x509::inspect(&presented).unwrap(),
            );
            assert_eq!(seen.subject, "CN=Session", "{name}");
            assert_eq!(seen.serial, presented.serial, "{name}");
        }
    }

    #[tokio::test]
    async fn client_auth_holds_in_every_configuration_written_after_it() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("client-auth-kept");
        let clients = Authority::new(provider.clone(), "Client Root");
        let serving = start(provider, dir.managed())
            .unwrap()
            .with_client_auth(std::slice::from_ref(&clients.certificate))
            .unwrap()
            .with_alpn(vec![b"h2".to_vec()]);
        let regenerated = serving
            .regenerate(&["127.0.0.1".parse().unwrap()], KeyAlgorithm::EcP256)
            .await
            .unwrap();
        assert_eq!(regenerated.alpn_protocols, [b"h2".to_vec()]);

        let mut trust = Trust::default();
        trust.pin(
            "127.0.0.1",
            fingerprint(&serving.pair().await.unwrap().cert_pem),
        );
        let outbound = Arc::new(Outbound::new(provider.clone(), trust).unwrap());
        let mut anonymous = outbound.client_config();
        anonymous.alpn_protocols = vec![b"h2".to_vec()];
        assert!(admitted(regenerated, anonymous).await.is_err());
    }

    #[test]
    fn client_auth_takes_one_authority_or_more_and_no_leaf() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("client-auth-refused");
        let serving = start(provider, dir.managed()).unwrap();
        assert!(matches!(
            serving.with_client_auth(&[]),
            Err(AnchorError::NoneGiven)
        ));
        let serving = start(provider, dir.managed()).unwrap();
        let leaf = self_signed(provider.clone(), &["127.0.0.1"]).chain;
        assert!(matches!(
            serving.with_client_auth(&leaf),
            Err(AnchorError::NotAnAuthority { .. })
        ));
    }

    #[tokio::test]
    async fn a_write_refused_before_its_commit_names_the_file_and_replaces_nothing() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("rolled-back");
        let serving = start(provider, dir.managed()).unwrap();
        let before = on_disk(&dir.join("cert.pem"));
        occupy(&dir.join("cert.pem.key.pem.txn"));

        let (cert, key) = another_pair(provider);
        let failed = install(&serving, &cert, &key).await.unwrap_err();
        let ServingError::Write { path, .. } = &failed else {
            panic!("{failed}");
        };
        assert_eq!(path, &dir.join("cert.pem"));
        assert!(
            failed.to_string().contains("nothing was replaced"),
            "{failed}"
        );
        assert_eq!(on_disk(&dir.join("cert.pem")), before);
    }

    #[tokio::test]
    async fn an_untouched_read_refuses_an_interrupted_write_and_changes_nothing() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("untouched");
        assert!(dir.managed().read_pair_untouched().unwrap().is_none());
        let serving = start(provider, dir.managed()).unwrap();
        let served = serving.pair().await.unwrap();
        let read = dir.named().read_pair_untouched().unwrap().unwrap();
        assert_eq!(read.cert_pem, served.cert_pem);

        left_for_recovery(provider, &serving, &dir).await;
        drop(serving);
        let before = dir.listing();
        for location in [dir.managed(), dir.named()] {
            let refused = location.read_pair_untouched().unwrap_err();
            let ServingError::Interrupted { record } = &refused else {
                panic!("{refused}");
            };
            assert_eq!(record, &location.record());
        }
        assert_eq!(dir.listing(), before);
    }

    #[cfg(unix)]
    #[test]
    fn the_served_pair_is_read_off_the_runtime_thread() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("off-runtime");
        let serving = start(provider, dir.managed()).unwrap();
        let fifo = dir.join("cert.pem");
        let cert = fs::read_to_string(&fifo).unwrap();
        fs::remove_file(&fifo).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(
            unsafe { libc::mkfifo(c_path(&fifo).unwrap().as_ptr(), 0o600) },
            0
        );

        let (sent, reads) = std::sync::mpsc::channel();
        let written = cert.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            // The writer runs on the one runtime thread, so only once the read has left it.
            let (pair, ()) = runtime
                .block_on(async { tokio::join!(serving.pair(), async { write(&fifo, &written) }) });
            let _ = sent.send(pair.map(|pair| pair.cert_pem));
        });
        let read = reads.recv_timeout(std::time::Duration::from_secs(10));
        assert_eq!(
            read.expect("the read held the runtime thread").unwrap(),
            cert
        );
    }

    #[test]
    fn displacing_never_replaces_an_earlier_unusable_file_or_directory() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("displace-twice");
        write(&dir.join("cert.pem"), "not PEM");
        write(&dir.join("key.pem"), "not PEM either");
        write(&dir.join("cert.pem.unusable"), "an earlier incident");
        occupy(&dir.join("key.pem.unusable"));

        start(provider, dir.managed()).unwrap();
        let read = |name: &str| fs::read_to_string(dir.join(name)).unwrap();
        assert_eq!(read("cert.pem.unusable"), "an earlier incident");
        assert_eq!(read("cert.pem.unusable.1"), "not PEM");
        assert!(dir.join("key.pem.unusable/inside").exists());
        assert_eq!(read("key.pem.unusable.1"), "not PEM either");
    }

    #[cfg(unix)]
    thread_local! {
        pub(super) static NO_REPLACE_UNSUPPORTED: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    #[cfg(unix)]
    #[test]
    fn without_a_no_replace_rename_a_file_is_linked_aside_and_a_directory_moved_to_a_free_name() {
        let dir = Scratch::new("displace-unsupported");
        write(&dir.join("key.pem"), "a key");
        write(&dir.join("key.pem.unusable"), "an earlier key");
        occupy(&dir.join("cert.pem"));
        occupy(&dir.join("cert.pem.unusable"));

        NO_REPLACE_UNSUPPORTED.set(true);
        let displaced =
            displace(&dir.join("key.pem")).and_then(|()| displace(&dir.join("cert.pem")));
        NO_REPLACE_UNSUPPORTED.set(false);
        displaced.unwrap();
        let read = |name: &str| fs::read_to_string(dir.join(name)).unwrap();
        assert_eq!(read("key.pem.unusable"), "an earlier key");
        assert_eq!(read("key.pem.unusable.1"), "a key");
        assert!(dir.join("cert.pem.unusable/inside").exists());
        assert!(dir.join("cert.pem.unusable.1/inside").exists());
        assert_eq!(
            dir.listing(),
            [
                "cert.pem.unusable",
                "cert.pem.unusable.1",
                "key.pem.unusable",
                "key.pem.unusable.1"
            ]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unwritable_directory_is_reported_before_any_write() {
        use std::os::unix::fs::PermissionsExt;

        let (_, provider) = &providers()[0];
        let dir = Scratch::new("unwritable");
        let keys = dir.join("keys");
        fs::create_dir(&keys).unwrap();
        let location = Location::managed(dir.join("cert.pem"), keys.join("key.pem"));
        start(provider, location.clone()).unwrap();
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o500)).unwrap();
        if probe(&keys).is_ok() {
            return; // root writes anywhere
        }

        let serving = start(provider, location).unwrap();
        let before = serving.pair().await.unwrap();
        let unwritable =
            |e| matches!(e, Err(ServingError::Unwritable { directory, .. }) if directory == keys);
        assert!(unwritable(serving.replaceable()));
        let (cert, key) = another_pair(provider);
        assert!(unwritable(install(&serving, &cert, &key).await.map(drop)));
        assert_eq!(serving.pair().await.unwrap().cert_pem, before.cert_pem);
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
