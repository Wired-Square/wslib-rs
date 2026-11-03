//! The certificate a backend with its own TLS listener serves, minted by the
//! daemon at first start (never by the package, or every card from one image
//! would share a key). Loading, minting and writing are `wslib_tls::Serving`'s.
//!
//! A pair that cannot be used is moved aside to `.unusable` and replaced at the
//! default location, since refusing to start would take the control socket down
//! too; a pair somebody named
//! ([`Tls::named`](wslib_appliance_config::Tls::named)) refuses the start
//! instead. [`Tls::install_pem`] writes both files as one transaction, then
//! reloads the listener and renews its open connections. Dialling out is
//! [`Outbound`]'s.

pub(crate) mod inspect;
pub(crate) mod outbound;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use axum_server::tls_rustls::RustlsConfig;
use rustls::crypto::CryptoProvider;
use wslib_appliance_types::tls::{CertificateReport, ServingPair};
use wslib_crypto::KeyAlgorithm;
use wslib_crypto_x509::SubjectAltName;
use wslib_secret::Secret;
use wslib_tls::{Location, Serving, ServingError};

use crate::control::ServeError;

pub(crate) use inspect::{normalise_pem, read_authority};
pub use outbound::Outbound;

/// Covered beyond the box's own names, for a port-forwarded or local browser.
const ALWAYS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

const NO_PAIR: &str = "this installation serves no TLS certificate";

const NAMED: &str = "These files were named in this appliance's configuration, so it will not \
                     move them aside and make its own";

/// Why something about a certificate could not be done. Every variant's
/// `Display` is a sentence for an operator, since it reaches a Settings screen.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The text is not what it should be. Carries the sentence.
    #[error("{0}")]
    Pem(String),

    /// Longer than `MAX_PEM_LEN`, refused before anything parsed it.
    #[error("a certificate or key may be at most {limit} bytes, and that is {actual}")]
    TooLong { limit: usize, actual: usize },

    /// Both halves read, but they are not a pair.
    #[error(
        "that private key does not belong to that certificate. Both are readable, so this is \
         most likely one half of an older pair."
    )]
    Mismatched,

    /// rustls will not serve the pair, for a reason only rustls knows.
    #[error("this appliance cannot serve that pair: {0}")]
    Unloadable(String),

    /// This appliance may not write these files, serves no pair, or refuses
    /// the record an interrupted write left.
    #[error("{0}")]
    Unsupported(String),

    /// Writing went wrong, which is this box and not the caller.
    #[error("could not write {}: {because}", path.display())]
    Unwritable { path: PathBuf, because: String },

    /// Written past the commit point but not finished; the listener serves the
    /// old pair.
    #[error(
        "the pair was written but not finished ({because}); installing it again serves it, and \
         {next}"
    )]
    Unfinished { because: String, next: String },

    /// Where a look at a host was aimed is not a place. Carries the sentence.
    #[error("{0}")]
    Target(String),

    /// A dialled host presented no readable certificate.
    #[error("{0}")]
    Unreachable(String),

    /// Anything else, which is this daemon being broken.
    #[error("{0}")]
    Internal(String),
}

/// The served pair and its two files, if any, on
/// [`ApplianceState`](crate::ApplianceState) so a restore route can install one.
#[derive(Debug)]
pub struct Tls {
    served: Option<Served>,
}

#[derive(Debug)]
struct Served {
    serving: Serving,
    listener: RustlsConfig,
    renewing: wslib_http_server::Tls,
    /// Held across reading the configuration and reloading the listener, so a
    /// reload that lost the race cannot put back a replaced pair.
    reloading: Mutex<()>,
}

impl Tls {
    /// Load the pair, or make one.
    pub(crate) async fn load_or_mint(
        settings: &wslib_appliance_config::Tls,
        alias: Option<&str>,
    ) -> Result<Self, ServeError> {
        let location = match settings.named {
            true => Location::named(&settings.cert, &settings.key),
            false => Location::managed(&settings.cert, &settings.key),
        };
        let alias = alias.map(str::to_string);
        let provider = provider()?;
        let serving =
            tokio::task::spawn_blocking(move || start(provider, location, alias.as_deref()))
                .await
                .map_err(|e| format!("loading the pair: {e}"))
                .and_then(|started| started)
                .map_err(|because| ServeError::Tls {
                    cert: settings.cert.clone(),
                    key: settings.key.clone(),
                    because,
                })?
                .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let listener = RustlsConfig::from_config(serving.config());
        Ok(Self {
            served: Some(Served {
                renewing: wslib_http_server::Tls::from(listener.clone()),
                listener,
                serving,
                reloading: Mutex::default(),
            }),
        })
    }

    /// No pair: nothing is minted or written, and everything that would read
    /// or replace a pair answers [`TlsError::Unsupported`].
    pub(crate) fn none() -> Self {
        Self { served: None }
    }

    /// Whether there is a pair at all; `false` only for [`none`](Self::none).
    pub(crate) fn serves(&self) -> bool {
        self.served.is_some()
    }

    fn served(&self) -> Result<&Served, TlsError> {
        self.served
            .as_ref()
            .ok_or_else(|| TlsError::Unsupported(NO_PAIR.to_string()))
    }

    /// The listener's configuration, for a backend that serves its own.
    pub(crate) fn config(&self) -> Option<RustlsConfig> {
        self.served.as_ref().map(|served| served.listener.clone())
    }

    /// The listener's configuration as `serve_https` takes it, so an install
    /// also renews the connections open on it.
    pub(crate) fn serving_tls(&self) -> Option<wslib_http_server::Tls> {
        self.served.as_ref().map(|served| served.renewing.clone())
    }

    /// Install a pair an operator holds; `host` is the name the requesting
    /// browser uses, so the report can warn when it is not covered.
    pub async fn install_pem(
        &self,
        cert_pem: &str,
        key_pem: &Secret,
        host: Option<&str>,
    ) -> Result<CertificateReport, TlsError> {
        let served = self.served()?;
        let cert_pem = normalise_pem(cert_pem)?;
        let key_pem = Secret::new(normalise_pem(key_pem.expose())?);
        let certificate = inspect::parse(&cert_pem)?;
        inspect::check_pair(&certificate, key_pem.expose())?;
        let now = wslib_appliance_store::now();
        let report = inspect::examine(&certificate, host, now);

        served
            .serving
            .install_pem(&cert_pem, &key_pem, host, now.into())
            .await
            .map_err(|e| tls_error(e, served.serving.location()))?;
        let _reloading = served
            .reloading
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        served.listener.reload_from_config(served.serving.config());
        served.renewing.renew();
        Ok(report)
    }

    /// Both halves, for a backup to carry, the key as a [`Secret`] and the
    /// certificate filtered to its `CERTIFICATE` sections. An interrupted write
    /// is finished first, or the read fails as an install would
    /// ([`TlsError::Unsupported`]).
    pub async fn pair(&self) -> Result<ServingPair, TlsError> {
        let serving = &self.served()?.serving;
        serving
            .pair()
            .await
            .map(ours)
            .map_err(|e| tls_error(e, serving.location()))
    }

    /// The refusal [`install_pem`](Self::install_pem) would answer, for a caller
    /// to check before committing something a failed install would leave half-done.
    pub fn replaceable(&self) -> Result<(), TlsError> {
        let serving = &self.served()?.serving;
        serving
            .replaceable()
            .map_err(|e| tls_error(e, serving.location()))
    }

    /// Whether the pair was named in this appliance's configuration, so
    /// something outside it may be managing those files.
    pub fn named(&self) -> bool {
        self.served
            .as_ref()
            .is_some_and(|served| served.serving.location().is_named())
    }
}

/// Load or mint the pair at `location`. Blocks.
fn start(
    provider: Arc<CryptoProvider>,
    location: Location,
    alias: Option<&str>,
) -> Result<Serving, String> {
    if !location.is_named() {
        for stale in [location.cert(), location.key()] {
            if let Err(e) = wslib_file_atomic::discard(stale, "new") {
                let staged = wslib_file_atomic::beside(stale, "new");
                tracing::warn!(path = %staged.display(), error = %e, "could not remove a staged file an earlier version left");
            }
        }
    }
    Serving::load_or_mint(
        provider,
        location,
        || sans(names_for(box_name().as_deref(), alias)),
        KeyAlgorithm::EcP256,
    )
    .map_err(|e| unusable(&e))
}

fn box_name() -> Option<String> {
    let host = wslib_host::hostname();
    if host.is_none() {
        tracing::warn!(
            source = wslib_host::HOSTNAME_SOURCE,
            "could not read this box's name; the certificate made now covers no name of its own, \
             only loopback and any alias, and a browser reaching it by name will report a mismatch"
        );
    }
    host
}

/// Each name a certificate can carry, and a warning for each it cannot.
fn sans(names: Vec<String>) -> Vec<SubjectAltName> {
    names
        .into_iter()
        .filter_map(|name| match name.parse() {
            Ok(san) => Some(san),
            Err(e) => {
                tracing::warn!(%name, error = %e, "a name this appliance answers to cannot go in a certificate and is left out");
                None
            }
        })
        .collect()
}

/// The process's rustls provider, which the consumer installs.
pub(crate) fn provider() -> Result<Arc<CryptoProvider>, ServeError> {
    #[cfg(test)]
    let _ = rustls::crypto::ring::default_provider().install_default();
    CryptoProvider::get_default()
        .cloned()
        .ok_or(ServeError::NoCryptoProvider)
}

fn ours(pair: wslib_tls::ServingPair) -> ServingPair {
    ServingPair {
        cert_pem: pair.cert_pem,
        key_pem: pair.key_pem,
    }
}

/// Why the pair will not load, or an interrupted write of it will not finish,
/// as the journal says it.
fn unusable(e: &ServingError) -> String {
    match e {
        ServingError::Named { source, .. } => match **source {
            ServingError::RecordRefused { .. } | ServingError::Recover { .. } => {
                format!("{source}. {NAMED}")
            }
            _ => format!(
                "{}. {NAMED}: correct them, or unset the setting to have the appliance manage \
                 its own pair",
                unusable(source)
            ),
        },
        ServingError::HalfPair { present, missing } => format!(
            "{} is there and {} is not — a half-supplied pair is not completed with a \
             generated file, because the two would not match",
            present.display(),
            missing.display(),
        ),
        ServingError::Refused(e) => format!("the pair on disk will not load: {e}"),
        e => e.to_string(),
    }
}

/// [`TlsError::Unsupported`] for a directory this appliance cannot write.
fn cannot_write(directory: &Path, kind: std::io::ErrorKind) -> TlsError {
    TlsError::Unsupported(format!(
        "this appliance cannot write to {}, so the certificate has to be replaced by hand there \
         ({kind})",
        directory.display(),
    ))
}

fn tls_error(e: ServingError, location: &Location) -> TlsError {
    match e {
        ServingError::Unwritable { directory, kind } => cannot_write(&directory, kind),
        ServingError::Refused(e) => TlsError::Unloadable(e.to_string()),
        ServingError::Mismatched => TlsError::Mismatched,
        e @ ServingError::RecordRefused { .. } => TlsError::Unsupported(e.to_string()),
        ServingError::Unfinished { ref source, .. } => TlsError::Unfinished {
            because: crate::redact::foreign(source),
            next: e.next_step().unwrap_or_default(),
        },
        ServingError::Write { path, source, .. } => TlsError::Unwritable {
            path,
            because: crate::redact::foreign(&source),
        },
        ServingError::Interrupted { record } => TlsError::Internal(format!(
            "a write of the serving pair was interrupted and {} records it; start the \
             appliance and stop it again before sealing",
            record.display()
        )),
        e @ ServingError::HalfPair { .. } => TlsError::Internal(unusable(&e)),
        ServingError::NoCertificate { path } => TlsError::Internal(format!(
            "the file at {} holds no certificate",
            path.display()
        )),
        ServingError::Certificate(e) => TlsError::Internal(format!(
            "the certificate on disk at {} is not PEM: {e}",
            location.cert().display()
        )),
        ServingError::Unreadable { path, source } => TlsError::Internal(format!(
            "could not read {}: {}",
            path.display(),
            crate::redact::foreign(&source)
        )),
        e => TlsError::Internal(e.to_string()),
    }
}

/// Every name this box might be reached by, given the one it calls itself and
/// the `.local` alias it answers to, if any.
pub(crate) fn names_for(host: Option<&str>, alias: Option<&str>) -> Vec<String> {
    // The box's own name leads, because it is what the subject is built from
    // and what an operator is actually typing.
    let mut names: Vec<String> = Vec::new();
    if let Some(host) = host {
        names.push(host.to_string());
        // `.local` because that is how a box on a small network is reached, and
        // it is not what the kernel reports.
        let local = local_name(host);
        if local != host {
            names.push(local);
        }
    }
    let alias = alias.map(local_name);
    for name in alias.iter().map(String::as_str).chain(ALWAYS) {
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// The `.local` name avahi advertises for `host`: its first label's.
fn local_name(host: &str) -> String {
    format!(
        "{}.local",
        host.split_once('.').map_or(host, |(label, _)| label)
    )
}

/// The pair on disk, for an offline backup. **Never while the daemon runs**: it
/// reads without the install lock. `Ok(None)` when neither file is there; any
/// partial, mismatched or interrupted pair is an error, and nothing is written.
/// Checking the pair needs a rustls provider installed in this process.
#[doc(hidden)]
pub fn pair_at(settings: &wslib_appliance_config::Tls) -> Result<Option<ServingPair>, TlsError> {
    let location = Location::managed(&settings.cert, &settings.key);
    let pair = location
        .read_pair_untouched()
        .map_err(|e| tls_error(e, &location))?;
    if let Some(pair) = &pair {
        inspect::check_pair(&inspect::parse(&pair.cert_pem)?, pair.key_pem.expose())?;
    }
    Ok(pair.map(ours))
}

/// Moves aside the record an interrupted write of the pair left, for an
/// operator to run with the daemon stopped once a start refuses it; a line
/// saying what moved.
pub fn discard_pending(settings: &wslib_appliance_config::Tls) -> Result<String, TlsError> {
    let location = Location::managed(&settings.cert, &settings.key);
    let record = location.record().display().to_string();
    let aside = location
        .discard_pending()
        .map_err(|e| tls_error(e, &location))?;
    Ok(match aside {
        Some(aside) => format!("moved {record} aside to {}", aside.display()),
        None => format!("no interrupted write is recorded at {record}"),
    })
}

#[cfg(any(test, feature = "testing"))]
impl Tls {
    /// Mint into `dir` through the real [`Tls::load_or_mint`].
    pub(crate) async fn minted_in(dir: impl AsRef<std::path::Path>) -> Self {
        Self::load_or_mint(&wslib_appliance_config::Tls::default_in(dir.as_ref()), None)
            .await
            .unwrap_or_else(|e| panic!("minting a pair for a test: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inspect::inspect_pem;
    use tempfile::TempDir;
    use wslib_appliance_types::tls::CertificateView;

    fn on_disk(tls: &Tls) -> Result<CertificateView, TlsError> {
        let cert = tls.served()?.serving.location().cert();
        inspect_pem(&std::fs::read_to_string(cert).expect("readable"))
    }

    fn listing(dir: &TempDir) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    async fn another_pair() -> ServingPair {
        let elsewhere = tempfile::tempdir().unwrap();
        Tls::minted_in(&elsewhere).await.pair().await.expect("read")
    }

    /// An install failing past its commit point: a non-empty directory at the
    /// certificate's name defeats the rename, even for root.
    async fn an_install_left_unfinished(dir: &TempDir, tls: &Tls) -> ServingPair {
        std::fs::remove_file(dir.path().join("cert.pem")).unwrap();
        std::fs::create_dir(dir.path().join("cert.pem")).unwrap();
        std::fs::write(dir.path().join("cert.pem").join("in-the-way"), "").unwrap();
        let pair = another_pair().await;
        let e = tls
            .install_pem(&pair.cert_pem, &pair.key_pem, None)
            .await
            .expect_err("the certificate cannot be renamed into place");
        assert!(matches!(e, TlsError::Unfinished { .. }), "{e}");
        assert!(e.to_string().contains("finishes it from"), "{e}");
        std::fs::remove_dir_all(dir.path().join("cert.pem")).unwrap();
        pair
    }

    #[tokio::test]
    async fn a_first_start_makes_a_pair_and_a_second_start_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));

        Tls::minted_in(&dir).await;
        let (first_cert, first_key) = (std::fs::read(&cert).unwrap(), std::fs::read(&key).unwrap());
        assert!(first_cert.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(String::from_utf8_lossy(&first_key).contains("PRIVATE KEY"));

        Tls::minted_in(&dir).await;
        assert_eq!(std::fs::read(&cert).unwrap(), first_cert);
        assert_eq!(std::fs::read(&key).unwrap(), first_key);
    }

    #[tokio::test]
    async fn a_half_pair_at_the_default_location_is_displaced_and_a_fresh_pair_minted() {
        for present in ["cert.pem", "key.pem"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(present), "theirs").expect("write");

            let tls = Tls::minted_in(&dir).await;
            assert_eq!(
                std::fs::read_to_string(dir.path().join(format!("{present}.unusable")))
                    .expect("the half that was there is kept"),
                "theirs"
            );
            assert!(
                on_disk(&tls).expect("a fresh one").self_signed,
                "and a usable pair is in place"
            );
        }
    }

    #[tokio::test]
    async fn a_half_pair_or_an_unloadable_pair_at_a_named_path_is_refused() {
        for theirs in [&["cert.pem"][..], &["cert.pem", "key.pem"][..]] {
            let dir = tempfile::tempdir().unwrap();
            for file in theirs {
                std::fs::write(dir.path().join(file), "theirs").expect("write");
            }
            let named = wslib_appliance_config::Tls::supplied(
                dir.path().join("cert.pem"),
                dir.path().join("key.pem"),
            );

            let e = Tls::load_or_mint(&named, None)
                .await
                .expect_err("a named pair this cannot use is refused");
            assert!(e.to_string().contains("named in this appliance"), "{e}");
            for file in theirs {
                assert_eq!(
                    std::fs::read_to_string(dir.path().join(file)).unwrap(),
                    "theirs",
                    "and their file is where they left it"
                );
            }
            assert!(
                !dir.path().join("cert.pem.unusable").exists(),
                "nothing was moved aside"
            );
        }
    }

    /// `app.crt` beside `app.key`: the two staging names must differ.
    #[tokio::test]
    async fn a_named_pair_sharing_a_stem_stages_and_replaces_without_colliding() {
        let dir = tempfile::tempdir().unwrap();
        let named = wslib_appliance_config::Tls::supplied(
            dir.path().join("app.crt"),
            dir.path().join("app.key"),
        );
        let tls = Tls::load_or_mint(&named, None)
            .await
            .expect("mints into the named paths");
        let before = on_disk(&tls).expect("read").sha256;

        let pair = another_pair().await;
        tls.install_pem(&pair.cert_pem, &pair.key_pem, None)
            .await
            .expect("a replacement writes two distinct staging files");
        assert_ne!(on_disk(&tls).expect("read").sha256, before);
        assert_eq!(listing(&dir), ["app.crt", "app.key"]);
    }

    #[tokio::test]
    async fn an_unloadable_pair_at_the_default_location_is_kept_as_unusable_and_replaced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cert.pem"), "not a certificate").expect("write");
        std::fs::write(dir.path().join("key.pem"), "not a key").expect("write");

        let tls = Tls::minted_in(&dir).await;
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cert.pem.unusable")).expect("kept"),
            "not a certificate"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("key.pem.unusable")).expect("kept"),
            "not a key"
        );
        assert!(on_disk(&tls).is_ok());
    }

    #[tokio::test]
    async fn the_pair_on_disk_is_read_whole_or_not_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let settings = wslib_appliance_config::Tls::default_in(dir.path());
        assert!(pair_at(&settings).unwrap().is_none(), "never started");

        let tls = Tls::minted_in(&dir).await;
        let offline = pair_at(&settings).unwrap().expect("minted");
        let served = tls.pair().await.unwrap();
        assert_eq!(offline.cert_pem, served.cert_pem);
        assert_eq!(offline.key_pem.expose(), served.key_pem.expose());

        std::fs::write(dir.path().join("cert.pem"), "no certificate in here").unwrap();
        let hollow = pair_at(&settings).unwrap_err().to_string();
        assert!(hollow.contains("holds no certificate"), "{hollow}");

        std::fs::remove_file(dir.path().join("cert.pem")).unwrap();
        let half = pair_at(&settings).unwrap_err().to_string();
        assert!(half.contains("half-supplied"), "{half}");
    }

    /// An orphaned key would make every later start refuse the half pair, and
    /// `Restart=always` loop on it.
    #[tokio::test]
    async fn a_failed_certificate_write_leaves_no_orphaned_key() {
        let dir = tempfile::tempdir().unwrap();
        // A missing parent stands in for ENOSPC on the certificate's write.
        let named = wslib_appliance_config::Tls::supplied(
            dir.path().join("nowhere").join("cert.pem"),
            dir.path().join("key.pem"),
        );
        Tls::load_or_mint(&named, None)
            .await
            .expect_err("the certificate cannot be written");
        assert_eq!(listing(&dir), Vec::<String>::new());
    }

    #[tokio::test]
    async fn an_unfinished_install_is_finished_before_the_pair_is_next_read_or_written() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        let unfinished = an_install_left_unfinished(&dir, &tls).await;

        let read = tls.pair().await.expect("finished, then read");
        assert_eq!(read.cert_pem, unfinished.cert_pem);
        assert_eq!(read.key_pem.expose(), unfinished.key_pem.expose());
        assert_eq!(listing(&dir), ["cert.pem", "key.pem"]);

        let next = another_pair().await;
        tls.install_pem(&next.cert_pem, &next.key_pem, None)
            .await
            .expect("the next install goes ahead");
    }

    /// The offline seal writes nothing, so it refuses rather than finishes.
    #[tokio::test]
    async fn the_offline_seal_refuses_a_pair_whose_install_was_interrupted() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        an_install_left_unfinished(&dir, &tls).await;
        drop(tls);
        let before = listing(&dir);

        let e = pair_at(&wslib_appliance_config::Tls::default_in(dir.path()))
            .expect_err("an interrupted install");
        assert!(
            e.to_string()
                .contains("start the appliance and stop it again before sealing"),
            "{e}"
        );
        assert_eq!(listing(&dir), before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_offline_seal_refuses_a_dangling_record_and_leaves_it() {
        let dir = tempfile::tempdir().unwrap();
        drop(Tls::minted_in(&dir).await);
        std::os::unix::fs::symlink(dir.path().join("nowhere"), dir.path().join("key.pem.txn"))
            .unwrap();
        let before = listing(&dir);

        let e = pair_at(&wslib_appliance_config::Tls::default_in(dir.path()))
            .expect_err("a record is there");
        assert!(
            e.to_string()
                .contains("start the appliance and stop it again before sealing"),
            "{e}"
        );
        assert_eq!(listing(&dir), before);
    }

    /// A record `content` at the default record path, as another writer left it.
    fn a_record(dir: &TempDir, content: &str) {
        let record = dir.path().join("key.pem.txn");
        std::fs::write(&record, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// The record was written by this process, so it is trusted though others
    /// may write the directory.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unfinished_install_at_a_shared_named_location_is_finished_by_a_retry() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let named = wslib_appliance_config::Tls::supplied(
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
        );
        let tls = Tls::load_or_mint(&named, None).await.expect("mints");
        an_install_left_unfinished(&dir, &tls).await;

        let retry = another_pair().await;
        let installed = tls.install_pem(&retry.cert_pem, &retry.key_pem, None).await;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        installed.expect("the retry finishes this process's own record and installs");
        assert_eq!(listing(&dir), ["cert.pem", "key.pem"]);
    }

    #[tokio::test]
    async fn the_offline_seal_refuses_two_halves_that_are_not_a_pair() {
        let dir = tempfile::tempdir().unwrap();
        drop(Tls::minted_in(&dir).await);
        let other = another_pair().await;
        std::fs::write(dir.path().join("key.pem"), other.key_pem.expose()).unwrap();

        let e = pair_at(&wslib_appliance_config::Tls::default_in(dir.path()))
            .expect_err("a key that is not the certificate's");
        assert!(matches!(e, TlsError::Mismatched), "{e}");
    }

    /// Another user could have planted it: install, backup read and the next
    /// start are all refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_record_in_a_directory_others_may_write_is_refused_at_a_named_location() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let named = wslib_appliance_config::Tls::supplied(
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
        );
        let tls = Tls::load_or_mint(&named, None).await.expect("mints");
        a_record(
            &dir,
            &format!(
                "pending\n{}\n{}\n",
                absolute(&dir, "key.pem"),
                absolute(&dir, "cert.pem")
            ),
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();

        let pair = another_pair().await;
        let installed = tls.install_pem(&pair.cert_pem, &pair.key_pem, None).await;
        let read = tls.pair().await;
        drop(tls);
        let started = Tls::load_or_mint(&named, None).await;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        for e in [
            installed.expect_err("an install over a record anybody could have left"),
            read.expect_err("a read over a record anybody could have left"),
        ] {
            assert!(matches!(e, TlsError::Unsupported(_)), "{e}");
            assert!(e.to_string().contains("aside by hand"), "{e}");
        }
        let e = started.expect_err("a start over a record anybody could have left");
        assert!(e.to_string().contains("may be written by others"), "{e}");
        assert!(e.to_string().contains("named in this appliance"), "{e}");
        assert!(dir.path().join("key.pem.txn").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_named_pair_in_a_shared_volume_starts_once_the_operator_discards_its_record() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let named = wslib_appliance_config::Tls::supplied(
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
        );
        drop(Tls::load_or_mint(&named, None).await.expect("mints"));
        a_record(&dir, "pending\n");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        Tls::load_or_mint(&named, None)
            .await
            .expect_err("a record anybody in the group could have left");

        let record = dir.path().join("key.pem.txn");
        assert_eq!(
            discard_pending(&named).unwrap(),
            format!(
                "moved {} aside to {}.unusable",
                record.display(),
                record.display()
            )
        );
        Tls::load_or_mint(&named, None)
            .await
            .expect("starts with no write in flight");
        assert_eq!(
            discard_pending(&named).unwrap(),
            format!("no interrupted write is recorded at {}", record.display())
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn a_record_at_a_named_location_is_never_recovered_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let named = wslib_appliance_config::Tls::supplied(
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
        );
        drop(Tls::load_or_mint(&named, None).await.expect("mints"));
        a_record(&dir, "pending\n");

        let e = Tls::load_or_mint(&named, None)
            .await
            .expect_err("a record nobody vouches for");
        assert!(e.to_string().contains("aside by hand"), "{e}");
        assert!(e.to_string().contains("named in this appliance"), "{e}");
        assert!(dir.path().join("key.pem.txn").exists());
    }

    /// Where `name` in `dir` is, as a record spells a target.
    #[cfg(unix)]
    fn absolute(dir: &TempDir, name: &str) -> String {
        std::fs::canonicalize(dir.path())
            .unwrap()
            .join(name)
            .display()
            .to_string()
    }

    #[tokio::test]
    async fn an_unrecoverable_record_at_the_default_location_is_set_aside_and_the_box_starts() {
        let dir = tempfile::tempdir().unwrap();
        let before = on_disk(&Tls::minted_in(&dir).await).unwrap().sha256;
        a_record(&dir, "neither pending nor committed\n");

        let tls = Tls::minted_in(&dir).await;
        assert_eq!(on_disk(&tls).unwrap().sha256, before);
        assert_eq!(
            listing(&dir),
            ["cert.pem", "key.pem", "key.pem.txn.unusable"]
        );
    }

    #[tokio::test]
    async fn an_unrecoverable_record_at_a_named_location_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let named = wslib_appliance_config::Tls::supplied(
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
        );
        drop(Tls::load_or_mint(&named, None).await.expect("mints"));
        a_record(&dir, "neither pending nor committed\n");
        let before = listing(&dir);

        let e = Tls::load_or_mint(&named, None)
            .await
            .expect_err("their record is not set aside");
        assert!(e.to_string().contains("key.pem.txn"), "{e}");
        assert_eq!(listing(&dir), before);
    }

    #[tokio::test]
    async fn a_start_clears_what_the_old_staging_left() {
        let dir = tempfile::tempdir().unwrap();
        drop(Tls::minted_in(&dir).await);
        for stale in ["cert.pem.new", "key.pem.new"] {
            std::fs::write(dir.path().join(stale), "stale").unwrap();
        }
        Tls::minted_in(&dir).await;
        assert_eq!(listing(&dir), ["cert.pem", "key.pem"]);
    }

    /// A dangling link aimed at the database reads as absent, and a plain
    /// `fs::write` would create a PEM at its target.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_certificate_path_is_replaced_rather_than_followed() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let target = dir.path().join("appliance.db");
        std::os::unix::fs::symlink(&target, &cert).expect("symlink");

        Tls::minted_in(&dir).await;

        assert!(
            !target.exists(),
            "the symlink was followed and a file created"
        );
        assert!(
            !std::fs::symlink_metadata(&cert)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the symlink survived, so the next write would go through it"
        );
        assert!(
            std::fs::read(&cert)
                .expect("a real file")
                .starts_with(b"-----BEGIN")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_key_is_written_unreadable_to_anybody_else() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        Tls::minted_in(&dir).await;

        let mode = std::fs::metadata(dir.path().join("key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the key is {mode:o}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_replacement_keeps_the_key_unreadable_and_leaves_no_staging_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        let before = on_disk(&tls).expect("read").sha256;

        let pair = another_pair().await;
        tls.install_pem(&pair.cert_pem, &pair.key_pem, None)
            .await
            .expect("replaces");

        let after = on_disk(&tls).expect("read").sha256;
        assert_ne!(before, after, "a new certificate is on disk");
        let mode = std::fs::metadata(dir.path().join("key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the key is {mode:o}");
        assert_eq!(listing(&dir), ["cert.pem", "key.pem"]);
    }

    #[tokio::test]
    async fn an_install_writes_the_pair_and_serves_it() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        let pair = another_pair().await;
        let serving = tls.config().unwrap().get_inner();

        let report = tls
            .install_pem(&pair.cert_pem, &pair.key_pem, None)
            .await
            .expect("a pair this appliance made is one it can take");
        assert_eq!(
            report.certificate.sha256,
            inspect_pem(&pair.cert_pem).expect("reads").sha256
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cert.pem")).unwrap(),
            pair.cert_pem,
            "and it is the text that went to disk"
        );
        let reloaded = tls.config().unwrap().get_inner();
        assert!(
            !Arc::ptr_eq(&serving, &reloaded),
            "the listener is still on the old configuration"
        );
        assert_eq!(
            reloaded.alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[tokio::test]
    async fn an_install_renews_the_connections_open_on_the_listener() {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, ServerName};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;
        use wslib_http_server::{Bounds, Listener, serve_https};

        const WITHIN: Duration = Duration::from_secs(5);
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        let listener = Listener::bind(([127, 0, 0, 1], 0).into(), Bounds::SERVING)
            .await
            .unwrap();
        let address = listener.local_addr();
        let serving = tls.serving_tls().unwrap();
        tokio::spawn(serve_https(
            listener,
            axum::Router::new(),
            serving,
            std::future::pending(),
        ));

        let pem = std::fs::read(dir.path().join("cert.pem")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(&pem).unwrap())
            .unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider().unwrap())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut peer = timeout(
            WITHIN,
            tokio_rustls::TlsConnector::from(Arc::new(client))
                .connect(ServerName::try_from("localhost").unwrap(), tcp),
        )
        .await
        .expect("a handshake")
        .unwrap();
        peer.write_all(b"GET / HTTP/1.1\r\nHost: box\r\n\r\n")
            .await
            .unwrap();
        let mut status = [0; 12];
        timeout(WITHIN, peer.read_exact(&mut status))
            .await
            .expect("an answer")
            .unwrap();

        let pair = another_pair().await;
        tls.install_pem(&pair.cert_pem, &pair.key_pem, None)
            .await
            .expect("installs");
        let mut rest = Vec::new();
        let _ = timeout(WITHIN, peer.read_to_end(&mut rest))
            .await
            .expect("the open connection is closed after the install");
    }

    /// `openssl pkcs12 -nodes` writes the key beside the certificate.
    #[tokio::test]
    async fn only_the_certificate_sections_of_the_file_are_carried() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        let pair = tls.pair().await.expect("read");
        let (cert, key) = (&pair.cert_pem, pair.key_pem.expose());

        // A filter that kept everything after the first certificate fails one.
        for combined in [format!("{key}{cert}"), format!("{cert}{key}")] {
            std::fs::write(dir.path().join("cert.pem"), combined)
                .expect("a combined file, as somebody's tool wrote it");

            let carried = tls.pair().await.expect("read").cert_pem;
            assert_eq!(&carried, cert);
            assert!(!carried.contains("PRIVATE KEY"));
        }
    }

    #[tokio::test]
    async fn an_unreadable_pair_at_the_default_location_is_displaced_like_an_unloadable_one() {
        let dir = tempfile::tempdir().unwrap();
        // `EISDIR`, even for root.
        std::fs::create_dir(dir.path().join("cert.pem")).expect("mkdir");
        std::fs::write(dir.path().join("key.pem"), "theirs").expect("write");

        let tls = Tls::minted_in(&dir).await;
        assert!(
            dir.path().join("cert.pem.unusable").is_dir(),
            "kept, as it was"
        );
        assert!(on_disk(&tls).is_ok(), "and a usable pair is in place");
    }

    #[tokio::test]
    async fn a_combined_file_in_the_certificate_box_is_refused_before_disk() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        let before = std::fs::read_to_string(dir.path().join("cert.pem")).unwrap();
        let pair = tls.pair().await.expect("read");

        let combined = format!("{}{}", pair.cert_pem, pair.key_pem.expose());
        let e = tls
            .install_pem(&combined, &pair.key_pem, None)
            .await
            .expect_err("a key beside the certificate");
        assert!(e.to_string().contains("beside the certificate"), "{e}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cert.pem")).unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn a_mismatched_pair_is_refused_before_anything_touches_disk() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        let before = std::fs::read_to_string(dir.path().join("cert.pem")).unwrap();

        let other = another_pair().await;
        let ours = tls.pair().await.expect("read");

        let e = tls
            .install_pem(&ours.cert_pem, &other.key_pem, None)
            .await
            .expect_err("two halves of two different pairs");
        assert!(matches!(e, TlsError::Mismatched), "{e}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cert.pem")).unwrap(),
            before,
            "the working certificate is untouched"
        );
    }

    /// Relies on mode `0o500`, so under root it has nothing to show.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unwritable_directory_for_either_half_is_reported_before_any_write() {
        use std::os::unix::fs::PermissionsExt;

        struct Writable<'a>(&'a std::path::Path);
        impl Drop for Writable<'_> {
            fn drop(&mut self) {
                std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700)).ok();
            }
        }

        let pair = another_pair().await;
        for half in ["cert.pem", "key.pem"] {
            let dir = tempfile::tempdir().unwrap();
            let held = dir.path().join("held");
            std::fs::create_dir(&held).unwrap();
            let at = |name: &str| match name == half {
                true => held.join(name),
                false => dir.path().join(name),
            };
            let named = wslib_appliance_config::Tls::supplied(at("cert.pem"), at("key.pem"));
            drop(Tls::load_or_mint(&named, None).await.expect("mints"));
            let _writable = Writable(&held);
            std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o500)).unwrap();
            if std::fs::write(held.join("probe"), "").is_ok() {
                eprintln!("skipped: this user writes a 0500 directory, as root does");
                return;
            }

            let tls = Tls::load_or_mint(&named, None).await.expect("loads");
            assert!(
                matches!(tls.replaceable(), Err(TlsError::Unsupported(_))),
                "{half}"
            );
            let e = tls
                .install_pem(&pair.cert_pem, &pair.key_pem, None)
                .await
                .expect_err("and the install refuses rather than half-writing");
            assert!(matches!(e, TlsError::Unsupported(_)), "{half}: {e}");
            assert!(e.to_string().contains("cannot write to"), "{half}: {e}");
        }
    }

    /// rustls accepts no all-digit hostname.
    #[test]
    fn a_name_no_certificate_can_carry_is_left_out_and_the_rest_kept() {
        let names: Vec<String> = sans(names_for(Some("12345"), None))
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["12345.local", "localhost", "127.0.0.1", "::1"]);
    }

    #[test]
    fn a_named_box_is_covered_by_that_name_and_its_local_one() {
        let named = names_for(Some("widget-a1b2c3"), None);
        assert_eq!(
            named,
            [
                "widget-a1b2c3",
                "widget-a1b2c3.local",
                "localhost",
                "127.0.0.1",
                "::1"
            ]
        );
        // The subject is built from the first.
        assert_eq!(named[0], "widget-a1b2c3");
    }

    #[test]
    fn a_dotted_name_is_covered_at_the_local_name_avahi_advertises() {
        assert_eq!(
            names_for(Some("widget-01.example.com"), None),
            [
                "widget-01.example.com",
                "widget-01.local",
                "localhost",
                "127.0.0.1",
                "::1"
            ]
        );
        assert_eq!(
            names_for(Some("widget-01.local"), None),
            ["widget-01.local", "localhost", "127.0.0.1", "::1"]
        );
    }

    #[test]
    fn loopback_is_always_covered_and_never_twice() {
        for host in [None, Some("localhost")] {
            let names = names_for(host, None);
            for always in ALWAYS {
                assert_eq!(
                    names.iter().filter(|n| *n == always).count(),
                    1,
                    "{always} in {names:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn no_pair_answers_unsupported_to_everything_that_would_read_or_replace_one() {
        let tls = Tls::none();
        let unsupported = |e: TlsError| matches!(e, TlsError::Unsupported(_));
        assert!(!tls.serves());
        assert!(unsupported(tls.replaceable().unwrap_err()));
        let pem = Secret::new("not a key");
        assert!(unsupported(
            tls.install_pem("not a certificate", &pem, None)
                .await
                .unwrap_err()
        ));
        assert!(unsupported(tls.pair().await.unwrap_err()));
    }

    #[tokio::test]
    async fn a_freshly_minted_pair_has_nothing_to_warn_about() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::minted_in(&dir).await;
        let pem = tls.pair().await.expect("read").cert_pem;
        let report = inspect::examine(
            &inspect::parse(&pem).expect("parses"),
            Some("localhost"),
            wslib_appliance_store::now(),
        );
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert!(report.certificate.self_signed);
        assert_eq!(report.certificate.key, "ECDSA P-256");
    }

    #[tokio::test]
    async fn a_minted_certificate_is_valid_from_1975_to_4096() {
        let dir = tempfile::tempdir().unwrap();
        let view = on_disk(&Tls::minted_in(&dir).await).expect("reads");
        assert_eq!(view.not_before.to_rfc3339(), "1975-01-01T00:00:00+00:00");
        assert_eq!(view.not_after.to_rfc3339(), "4096-01-01T00:00:00+00:00");
    }

    #[test]
    fn the_alias_is_covered_at_its_local_name_once_and_after_the_boxs_own() {
        assert_eq!(
            names_for(Some("widget-a1b2c3"), Some("widget")),
            [
                "widget-a1b2c3",
                "widget-a1b2c3.local",
                "widget.local",
                "localhost",
                "127.0.0.1",
                "::1"
            ]
        );
        assert_eq!(
            names_for(Some("widget"), Some("widget")),
            ["widget", "widget.local", "localhost", "127.0.0.1", "::1"]
        );
    }

    #[tokio::test]
    async fn a_pair_this_appliance_makes_names_the_alias_and_an_older_one_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let settings = wslib_appliance_config::Tls::default_in(dir.path());
        let sans = |tls: &Tls| on_disk(tls).expect("read").sans;

        let before = Tls::load_or_mint(&settings, None).await.expect("mints");
        assert!(!sans(&before).contains(&"widget.local".to_string()));
        drop(before);

        let aliased = Tls::load_or_mint(&settings, Some("widget"))
            .await
            .expect("loads");
        assert!(
            !sans(&aliased).contains(&"widget.local".to_string()),
            "the pair on disk was kept"
        );

        let fresh = tempfile::tempdir().unwrap();
        let minted = Tls::load_or_mint(
            &wslib_appliance_config::Tls::default_in(fresh.path()),
            Some("widget"),
        )
        .await
        .expect("mints");
        assert!(sans(&minted).contains(&"widget.local".to_string()));
    }
}
