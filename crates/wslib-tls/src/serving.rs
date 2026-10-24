use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;
use std::{fs, io};

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_x509::pem::{self, CERTIFICATE, PRIVATE_KEY};
use wslib_crypto_x509::{CertificateView, Report, SubjectAltName};
use wslib_file_atomic::{Options, RecordIdentity, Transaction};
use wslib_secret::Secret;

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

    /// Finishes an interrupted write of the pair, refusing a record naming
    /// other files or one not this process's own; at a named location also
    /// one in a directory others may write, or on Windows any record.
    pub fn recover(&self) -> Result<(), ServingError> {
        recover(self, None)
    }

    /// The pair on disk, for a backup taken with nothing serving, after
    /// [`recover`](Self::recover); `None` when neither file is there.
    ///
    /// Whether the pair loads is not asked.
    pub fn read_pair(&self) -> Result<Option<ServingPair>, ServingError> {
        self.recover()?;
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
    current: RwLock<Arc<ServerConfig>>,
    cannot_replace: Option<(PathBuf, io::ErrorKind)>,
    /// Taken for each install, holding the record a failed commit left.
    installing: tokio::sync::Mutex<Option<RecordIdentity>>,
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
        if let Err(failed) = recover(&location, None) {
            if location.named {
                return Err(failed);
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
        let (pair, config) = mint_pair(&provider, names, algorithm)?;
        commit_pair(&location, &pair).map_err(|(error, _)| error)?;
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
        let config = server_config(&self.provider, chain, key)?;
        self.commit(pair, config.clone()).await?;
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
        let (pair, config) = blocking(move || mint_pair(&provider, &names, algorithm)).await?;
        self.commit(pair, config.clone()).await?;
        Ok(config)
    }

    async fn commit(
        &self,
        pair: ServingPair,
        config: Arc<ServerConfig>,
    ) -> Result<(), ServingError> {
        let mut left = self.installing.lock().await;
        self.replaceable()?;
        let (location, remembered) = (self.location.clone(), left.take());
        let (written, still_left) = blocking(move || {
            if let Err(error) = recover(&location, remembered.as_ref()) {
                return (Err(error), remembered);
            }
            match commit_pair(&location, &pair) {
                Ok(()) => (Ok(()), None),
                Err((error, identity)) => (Err(error), identity),
            }
        })
        .await;
        *left = still_left;
        written?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = config;
        Ok(())
    }

    /// The pair on disk, for a backup, after finishing an interrupted write;
    /// never one install's key beside another's certificate.
    pub async fn pair(&self) -> Result<ServingPair, ServingError> {
        let mut left = self.installing.lock().await;
        recover(&self.location, left.as_ref())?;
        *left = None;
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
) -> Result<(ServingPair, Arc<ServerConfig>), ServingError> {
    let key = PrivateKeyDer::from(algorithm.generate().map_err(ServingError::Generate)?);
    let signer = Signer::new(provider.clone(), &key).map_err(ServingError::KeyRefused)?;
    let cert = wslib_crypto_x509::mint(&signer, names).map_err(ServingError::Mint)?;
    let pair = ServingPair {
        cert_pem: pem::encode(CERTIFICATE, &cert),
        key_pem: Secret::new(pem::encode(PRIVATE_KEY, key.secret_der())),
    };
    Ok((pair, server_config(provider, vec![cert], key)?))
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

/// The record a commit `left` is finished without the trust checks while it
/// is still that file and names only this pair.
fn recover(location: &Location, left: Option<&RecordIdentity>) -> Result<(), ServingError> {
    let (record_dir, record) = transaction(location);
    let targets = [location.cert.as_path(), &location.key];
    if let Some(identity) = left
        && wslib_file_atomic::recover_identified(record_dir, &record, &targets, identity)
            .map_err(ServingError::Recover)?
            .is_some()
    {
        return Ok(());
    }
    if location.named {
        named_record_acted_on(record_dir, &record).map_err(ServingError::Recover)?;
    }
    wslib_file_atomic::recover_expecting(record_dir, &record, &targets)
        .map(drop)
        .map_err(ServingError::Recover)
}

/// Only a record that is there is judged, so a named pair in a shared directory still starts.
fn named_record_acted_on(record_dir: &Path, record: &str) -> io::Result<()> {
    let path = record_dir.join(format!("{record}.txn"));
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        there => there.map(drop)?,
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let directory = fs::metadata(record_dir)?;
        // SAFETY: a plain syscall with no arguments.
        let euid = unsafe { libc::geteuid() };
        if [euid, 0].contains(&directory.uid()) && directory.mode() & 0o022 == 0 {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} may be written by others, so {} is not acted on",
                record_dir.display(),
                path.display()
            ),
        ))
    }
    #[cfg(windows)]
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} is at a named location, so it is left for the operator",
            path.display()
        ),
    ))
}

/// The staged files go aside before the record, as a record lost first would
/// strand a staged key with nothing naming it.
fn set_aside_interrupted(location: &Location) -> Result<(), ServingError> {
    let (record_dir, record) = transaction(location);
    let suffix = format!("{record}.txn");
    displace(&wslib_file_atomic::beside(&location.cert, &suffix))?;
    displace(&wslib_file_atomic::beside(&location.key, &suffix))?;
    displace(&record_dir.join(suffix))
}

/// Both or neither, across a crash, once [`recover`] has run; the key is
/// renamed into place first. Both `0600`, staged and renamed over the
/// targets, so a symlink there is replaced and not followed. A commit left
/// for recovery hands back its record's identity.
fn commit_pair(
    location: &Location,
    pair: &ServingPair,
) -> Result<(), (ServingError, Option<RecordIdentity>)> {
    let (record_dir, record) = transaction(location);
    let unwritten = |error| (ServingError::Write(error), None);
    let mut txn = Transaction::begin(record_dir, &record).map_err(unwritten)?;
    txn.stage(
        &location.key,
        pair.key_pem.expose().as_bytes(),
        &Options::new(),
    )
    .map_err(unwritten)?;
    txn.stage(&location.cert, pair.cert_pem.as_bytes(), &Options::new())
        .map_err(unwritten)?;
    txn.commit_identified()
        .map_err(|(error, identity)| (ServingError::Write(error.into()), identity))
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
        let failed = install(serving, &cert, &key).await.map(drop);
        assert!(matches!(failed, Err(ServingError::Write(_))), "{failed:?}");
        fs::remove_dir_all(dir.join("cert.pem")).unwrap();
        cert
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
            let refused = location.read_pair();
            assert!(
                matches!(&refused, Err(ServingError::Recover(e)) if e.kind() == io::ErrorKind::PermissionDenied),
                "{refused:?}"
            );
            assert!(location.recover().is_err());
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
            Err(ServingError::Recover(_))
        ));
        let (cert, key) = another_pair(provider);
        let refused = install(&serving, &cert, &key).await.map(drop);
        assert!(
            matches!(refused, Err(ServingError::Recover(_))),
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
        let ServingError::Recover(e) = &refused else {
            panic!("{refused}");
        };
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains(&*dir.0.to_string_lossy()), "{e}");
        assert!(matches!(
            start(provider, dir.named()),
            Err(ServingError::Recover(_))
        ));
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
            matches!(&refused, Err(ServingError::Recover(e)) if e.kind() == io::ErrorKind::PermissionDenied),
            "{refused:?}"
        );
        assert!(matches!(
            start(provider, dir.named()),
            Err(ServingError::Recover(_))
        ));
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
            Err(ServingError::Recover(_))
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
    fn a_recover_that_fails_at_the_managed_location_is_set_aside_and_a_pair_minted() {
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
    fn a_recover_that_fails_at_a_named_location_is_an_error_and_nothing_moves() {
        let (_, provider) = &providers()[0];
        let dir = Scratch::new("wedged-named");
        start(provider, dir.named()).unwrap();
        wedged(&dir);
        let before = dir.listing();

        let e = start(provider, dir.named()).expect_err("a named pair is the operator's");
        assert!(matches!(e, ServingError::Recover(_)), "{e}");
        assert_eq!(dir.listing(), before);
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
