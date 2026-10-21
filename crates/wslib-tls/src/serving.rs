use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;
use std::{fmt, fs, io};

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_x509::pem::{self, CERTIFICATE, PRIVATE_KEY};
use wslib_crypto_x509::{CertificateView, Report, SubjectAltName};
use wslib_file_atomic::{Options, Transaction};

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

    /// The pair on disk, for a backup taken with nothing serving; `None` when neither file is there.
    ///
    /// Whether the pair loads is not asked.
    pub fn read_pair(&self) -> Result<Option<ServingPair>, ServingError> {
        match present(self)? {
            Present::Both => read_pair(self).map(Some),
            Present::Neither => Ok(None),
            Present::Half(half) => Err(half),
        }
    }
}

/// A serving pair as PEM text: the certificate chain, leaf first, and its private key.
#[derive(Clone)]
#[non_exhaustive]
pub struct ServingPair {
    pub cert_pem: String,
    pub key_pem: String,
}

impl fmt::Debug for ServingPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServingPair")
            .field("cert_pem", &self.cert_pem)
            .finish_non_exhaustive()
    }
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
    current: RwLock<Arc<ServerConfig>>,
    cannot_replace: Option<(PathBuf, io::ErrorKind)>,
    installing: tokio::sync::Mutex<()>,
}

impl Serving {
    /// Loads the pair at `location`, or mints a self-signed one for `names`
    /// with a new `algorithm` key, as the crate doc says.
    ///
    /// Blocks: it reads and writes files, and RSA generation takes seconds.
    pub fn load_or_mint(
        provider: Arc<CryptoProvider>,
        location: Location,
        names: &[SubjectAltName],
        algorithm: KeyAlgorithm,
    ) -> Result<Self, ServingError> {
        let (record_dir, record) = transaction(&location);
        wslib_file_atomic::recover(record_dir, &record).map_err(ServingError::Recover)?;

        let unusable = match present(&location)? {
            Present::Both => match load(&provider, &location) {
                Ok(config) => return Ok(Self::new(provider, location, config)),
                Err(unusable) => unusable,
            },
            Present::Neither => return Self::mint(provider, location, names, algorithm),
            Present::Half(half) => half,
        };
        if location.named {
            return Err(ServingError::Named {
                cert: location.cert,
                key: location.key,
                source: Box::new(unusable),
            });
        }
        tracing::warn!(
            cert = %location.cert.display(),
            because = %unusable,
            "moving the serving pair aside and minting a fresh one"
        );
        displace(&location.cert)?;
        displace(&location.key)?;
        Self::mint(provider, location, names, algorithm)
    }

    fn new(provider: Arc<CryptoProvider>, location: Location, config: Arc<ServerConfig>) -> Self {
        // Once, at startup: a directory that becomes unwritable later fails the write itself.
        let cannot_replace = writable(&location).err();
        Self {
            provider,
            location,
            current: RwLock::new(config),
            cannot_replace,
            installing: tokio::sync::Mutex::new(()),
        }
    }

    fn mint(
        provider: Arc<CryptoProvider>,
        location: Location,
        names: &[SubjectAltName],
        algorithm: KeyAlgorithm,
    ) -> Result<Self, ServingError> {
        tracing::info!(cert = %location.cert.display(), ?names, "minting a serving pair");
        let key = PrivateKeyDer::from(algorithm.generate().map_err(ServingError::Generate)?);
        let signer = Signer::new(provider.clone(), &key).map_err(ServingError::KeyRefused)?;
        let cert = wslib_crypto_x509::mint(&signer, names).map_err(ServingError::Mint)?;
        commit_pair(
            &location,
            &pem::encode(CERTIFICATE, &cert),
            &pem::encode(PRIVATE_KEY, key.secret_der()),
        )?;
        let config = server_config(&provider, vec![cert], key)?;
        Ok(Self::new(provider, location, config))
    }

    /// The configuration being served, built on the caller's provider with no ALPN.
    pub fn config(&self) -> Arc<ServerConfig> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
    /// name the operator reached the app by, for the report.
    pub async fn install_pem(
        &self,
        cert_pem: &str,
        key_pem: &str,
        host: Option<&str>,
    ) -> Result<Installed, ServingError> {
        let cert_pem = pem::normalise(cert_pem).map_err(ServingError::Certificate)?;
        let key_pem = pem::normalise(key_pem).map_err(ServingError::Key)?;
        let (chain, key, view) = parse(&self.provider, &cert_pem, &key_pem)?;
        let report = wslib_crypto_x509::examine(view, host, SystemTime::now());
        let config = server_config(&self.provider, chain, key)?;

        let _turn = self.installing.lock().await;
        self.replaceable()?;
        let location = self.location.clone();
        tokio::task::spawn_blocking(move || commit_pair(&location, &cert_pem, &key_pem))
            .await
            .map_err(|e| ServingError::Write(io::Error::other(e)))??;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = config.clone();
        Ok(Installed { config, report })
    }

    /// The pair on disk, for a backup; never one install's key beside another's certificate.
    pub async fn pair(&self) -> Result<ServingPair, ServingError> {
        let _turn = self.installing.lock().await;
        read_pair(&self.location)
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
    #[error("finishing an interrupted write of the pair: {0}")]
    Recover(#[source] io::Error),
    #[error("generating a key: {0}")]
    Generate(#[source] wslib_crypto::Error),
    #[error("minting a certificate: {0}")]
    Mint(#[source] wslib_crypto_x509::Error),
    #[error("writing the pair: {0}")]
    Write(#[source] io::Error),
    #[error("cannot write to {}: {kind}", directory.display())]
    Unwritable {
        directory: PathBuf,
        kind: io::ErrorKind,
    },
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

fn load(
    provider: &Arc<CryptoProvider>,
    location: &Location,
) -> Result<Arc<ServerConfig>, ServingError> {
    let pair = read_pair(location)?;
    let (chain, key, _) = parse(provider, &pair.cert_pem, &pair.key_pem)?;
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
        key_pem: read(&location.key)?,
    })
}

fn parse(
    provider: &CryptoProvider,
    cert_pem: &str,
    key_pem: &str,
) -> Result<
    (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        CertificateView,
    ),
    ServingError,
> {
    let chain = pem::certificates(cert_pem).map_err(ServingError::Certificate)?;
    let key = pem::private_key(key_pem).map_err(ServingError::Key)?;
    let view = wslib_crypto_x509::inspect(&chain[0]).map_err(ServingError::Certificate)?;
    if !wslib_crypto::key_matches(provider, &key, &view.spki).map_err(ServingError::KeyRefused)? {
        return Err(ServingError::Mismatched);
    }
    Ok((chain, key, view))
}

fn server_config(
    provider: &Arc<CryptoProvider>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, ServingError> {
    ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .and_then(|builder| builder.with_no_client_auth().with_single_cert(chain, key))
        .map(Arc::new)
        .map_err(ServingError::Refused)
}

/// The record sits beside the key and is named for it, so two pairs in one directory never share one.
fn transaction(location: &Location) -> (&Path, String) {
    let name = location.key.file_name().unwrap_or_default();
    (
        directory_of(&location.key),
        name.to_string_lossy().into_owned(),
    )
}

/// Both or neither, across a crash, once [`wslib_file_atomic::recover`] has
/// run; the key is renamed into place first. Both `0600`, staged and renamed
/// over the targets, so a symlink there is replaced and not followed.
fn commit_pair(location: &Location, cert_pem: &str, key_pem: &str) -> Result<(), ServingError> {
    let (record_dir, record) = transaction(location);
    let write = || -> io::Result<()> {
        let mut pair = Transaction::begin(record_dir, &record)?;
        pair.stage(&location.key, key_pem.as_bytes(), &Options::new())?;
        pair.stage(&location.cert, cert_pem.as_bytes(), &Options::new())?;
        Ok(pair.commit()?)
    };
    write().map_err(ServingError::Write)
}

fn displace(path: &Path) -> Result<(), ServingError> {
    let aside = wslib_file_atomic::beside(path, DISPLACED);
    match fs::rename(path, &aside) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ServingError::Displace {
            path: path.to_path_buf(),
            source,
        }),
        Ok(()) => {
            tracing::warn!(from = %path.display(), to = %aside.display(), "kept the unusable file");
            Ok(())
        }
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

    use super::*;
    use crate::testing::{TlsPeer, providers, self_signed};
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
        let names = ["widget-01", "127.0.0.1"].map(|name| name.parse().unwrap());
        Serving::load_or_mint(provider.clone(), location, &names, KeyAlgorithm::EcP256)
    }

    fn another_pair(provider: &Arc<CryptoProvider>) -> (String, String) {
        let pair = self_signed(provider.clone(), &["127.0.0.1"]);
        (
            pem::encode(CERTIFICATE, &pair.chain[0]),
            pem::encode(PRIVATE_KEY, pair.key.secret_der()),
        )
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

            let installed = serving
                .install_pem(&crlf, &key, Some("127.0.0.1"))
                .await
                .expect(name);
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
    async fn a_pair_that_is_not_one_is_refused_before_disk() {
        for (name, provider) in providers() {
            let dir = Scratch::new(&format!("refused-{name}"));
            let serving = start(&provider, dir.managed()).expect(name);
            let before = serving.pair().await.unwrap();
            let (cert, key) = another_pair(&provider);
            let (_, other_key) = another_pair(&provider);

            let mismatched = serving.install_pem(&cert, &other_key, None).await;
            assert!(
                matches!(mismatched, Err(ServingError::Mismatched)),
                "{name}"
            );
            let combined = serving
                .install_pem(&format!("{cert}{key}"), &key, None)
                .await;
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
                (after.cert_pem, after.key_pem),
                (before.cert_pem, before.key_pem)
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
        serving.install_pem(&cert, &key, None).await.unwrap();
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
        assert_eq!((pair.cert_pem, pair.key_pem), (cert, key));
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
        serving.install_pem(&cert, &key, None).await.unwrap();
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), untouched);
        assert!(
            !fs::symlink_metadata(dir.join("cert.pem"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(on_disk(&dir.join("cert.pem")), fingerprint(&cert));
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
        assert!(unwritable(
            serving.install_pem(&cert, &key, None).await.map(drop)
        ));
        assert_eq!(serving.pair().await.unwrap().cert_pem, before.cert_pem);
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
