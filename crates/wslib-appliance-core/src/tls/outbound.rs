//! What this appliance trusts when it dials out: the store's pins and
//! authorities beside the OS's roots, read live by every handshake. A pinned
//! host is trusted for exactly that certificate, name and expiry unchecked;
//! any other is verified against the roots and every installed authority, whose
//! own dates are not checked. An unpinned handshake before the first OS-store
//! read lands waits for it, at most 30 s.
//!
//! A write inside a transaction (a restore, a reset) must call
//! [`Outbound::reload`] after its commit. `SSL_CERT_FILE` and `SSL_CERT_DIR`
//! replace the OS store, and the static musl binary never resolves `.local`.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::crypto::CryptoProvider;
use tokio::sync::watch;
use wslib_appliance_store::{Store, StoreError};
use wslib_appliance_types::trust::Peer;
use wslib_appliance_types::{TrustedCa, TrustedCert};
use wslib_crypto::Fingerprint;
use wslib_tls::{ProbeError, Trust};

pub(crate) use wslib_tls::normalise_host;

use super::TlsError;
use super::inspect::{self, parse};
use crate::control::ServeError;

/// What this appliance trusts for the connections it makes; one per appliance,
/// on [`ApplianceState`](crate::ApplianceState).
#[derive(Debug)]
pub struct Outbound {
    trusting: Arc<wslib_tls::Outbound>,
    /// Held across a reading and its swap, so an older reading never lands last.
    reloading: tokio::sync::Mutex<()>,
}

/// How the OS store is read: `wslib_tls::Outbound::new`, except under test.
pub(crate) type OsStore =
    fn(Arc<CryptoProvider>, Trust) -> Result<wslib_tls::Outbound, rustls::Error>;

impl Outbound {
    /// Read the tables, and start reading the OS store in the background.
    pub(crate) async fn load(store: &Store, os: OsStore) -> Result<Self, ServeError> {
        let trust = read(store)
            .await
            .map_err(|e| ServeError::Trust(e.to_string()))?;
        let trusting =
            os(super::provider()?, trust).map_err(|e| ServeError::Trust(e.to_string()))?;
        Ok(Self {
            trusting: Arc::new(trusting),
            reloading: tokio::sync::Mutex::new(()),
        })
    }

    /// Read the tables again and tell every subscriber, after a transaction's
    /// commit; the writes below do this themselves.
    #[doc(hidden)]
    pub async fn reload(&self, store: &Store) -> Result<(), StoreError> {
        let _one = self.reloading.lock().await;
        self.trusting.set_trust(read(store).await?);
        Ok(())
    }

    /// Trust this certificate for this host, replacing any earlier pin.
    pub(crate) async fn pin(&self, store: &Store, cert: &TrustedCert) -> Result<(), StoreError> {
        store.pin_cert(cert).await?;
        self.reload(store).await
    }

    /// Stop trusting a host. `false` when it was not pinned.
    pub(crate) async fn unpin(&self, store: &Store, host: &str) -> Result<bool, StoreError> {
        let was = store.unpin_cert(host).await?;
        self.reload(store).await?;
        Ok(was)
    }

    /// Trust this authority beside the OS's.
    pub(crate) async fn trust(&self, store: &Store, ca: &TrustedCa) -> Result<(), StoreError> {
        store.trust_ca(ca).await?;
        self.reload(store).await
    }

    /// Stop trusting an authority. `false` when it was not trusted.
    pub(crate) async fn distrust(&self, store: &Store, sha256: &str) -> Result<bool, StoreError> {
        let was = store.distrust_ca(sha256).await?;
        self.reload(store).await?;
        Ok(was)
    }

    /// Changes whenever the trust is re-read; an open connection is not
    /// reached, so a holder of pooled clients rebuilds them here.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.trusting.subscribe()
    }

    /// A client configuration that verifies as the module doc says. ALPN offers
    /// only `http/1.1`; a client that negotiates `h2` adds it first.
    pub fn client_config(&self) -> ClientConfig {
        let mut config = self.trusting.client_config();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    }

    /// Connect to `target` (an `https://` URL or a host, port optional) and
    /// describe the certificate it presents, trusting nothing.
    pub(crate) async fn inspect(&self, target: &str) -> Result<Peer, TlsError> {
        let presented = self.trusting.inspect(target).await.map_err(unreachable)?;
        let (host, port) = (presented.host, presented.port);
        let certificate = inspect::read(&presented.end_entity)
            .map(|read| inspect::view(&read))
            .map_err(|e| {
                TlsError::Unreachable(format!(
                    "{host}:{port} presented a certificate this appliance cannot read — {e}"
                ))
            })?;
        Ok(Peer {
            certificate,
            host,
            port,
        })
    }
}

/// The probe's own sentences, but a failed connection's cause redacted.
fn unreachable(e: ProbeError) -> TlsError {
    match e {
        ProbeError::Failed { host, port, source } => TlsError::Unreachable(format!(
            "{host}:{port} presented no certificate: {}",
            crate::redact::foreign(&source)
        )),
        e @ (ProbeError::NotHttps { .. }
        | ProbeError::NoHost { .. }
        | ProbeError::BadPort { .. }
        | ProbeError::NotAServerName { .. }) => TlsError::Target(e.to_string()),
        e => TlsError::Unreachable(e.to_string()),
    }
}

/// The two tables, beside the OS's roots.
async fn read(store: &Store) -> Result<Trust, StoreError> {
    let mut trust = Trust::os_roots();
    for pin in store.trusted_certs().await? {
        match canonical_sha256(&pin.sha256)
            .and_then(|hex| hex.parse::<Fingerprint>().map_err(|e| e.to_string()))
        {
            Ok(fingerprint) => trust.pin(&pin.host, fingerprint),
            Err(why) => {
                tracing::warn!(host = %pin.host, why, "a pin holds no usable fingerprint and is ignored")
            }
        }
    }
    for ca in &store.trusted_cas().await? {
        // A restored row was never checked by the route: skip a bad one.
        if let Err(why) = anchor(&mut trust, ca) {
            tracing::warn!(sha256 = %ca.sha256, why, "an installed authority was not read");
        }
    }
    Ok(trust)
}

fn anchor(trust: &mut Trust, ca: &TrustedCa) -> Result<(), String> {
    let leaf = parse(&ca.pem).map_err(|e| e.to_string())?;
    if Ok(leaf.sha256()) != canonical_sha256(&ca.sha256) {
        return Err("the row's fingerprint is not the certificate's".to_string());
    }
    trust.anchor(&leaf.into_der()).map_err(|e| e.to_string())
}

/// A pasted SHA-256 fingerprint (bare, colon- or space-separated, either case)
/// as the lowercase hex a pin is compared in.
pub(crate) fn canonical_sha256(sha256: &str) -> Result<String, String> {
    let hex = sha256.trim().replace([':', ' '], "").to_ascii_lowercase();
    if hex.len() != 64 {
        return Err(format!(
            "a sha-256 fingerprint is 64 hex characters, and this is {}",
            hex.len()
        ));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("a sha-256 fingerprint is hexadecimal".to_string());
    }
    Ok(hex)
}

/// A loopback host to dial, over `wslib_tls::testing`; exported under
/// [`testing`](crate::testing).
#[cfg(any(test, feature = "testing"))]
pub(crate) mod peer {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use rustls::crypto::CryptoProvider;
    use wslib_crypto_x509::pem::{self, CERTIFICATE, PRIVATE_KEY};
    use wslib_tls::testing::Pair;

    /// Panics unless the test installed a rustls crypto provider.
    fn provider() -> Arc<CryptoProvider> {
        crate::tls::provider().expect("a test installs a rustls crypto provider first")
    }

    /// A certificate authority, for signing a peer's certificate.
    pub struct Authority {
        /// Its certificate, PEM.
        pub pem: String,
        signing: wslib_tls::testing::Authority,
    }

    impl Authority {
        pub fn new(name: &str) -> Self {
            let signing = wslib_tls::testing::Authority::new(provider(), name);
            Self {
                pem: pem::encode(CERTIFICATE, &signing.certificate),
                signing,
            }
        }

        /// A pair for `names`, signed by this authority: certificate PEM, key PEM.
        pub fn sign(&self, names: &[&str]) -> (String, String) {
            as_pem(&self.signing.sign(names))
        }
    }

    /// A pair signed by nobody, covering loopback: certificate PEM, key PEM.
    pub fn self_signed() -> (String, String) {
        as_pem(&wslib_tls::testing::self_signed(
            provider(),
            &crate::tls::ALWAYS,
        ))
    }

    fn as_pem(pair: &Pair) -> (String, String) {
        (
            pair.chain
                .iter()
                .map(|der| pem::encode(CERTIFICATE, der))
                .collect(),
            pem::encode(PRIVATE_KEY, pair.key.secret_der()),
        )
    }

    /// A loopback TLS listener presenting one pair, answering 204 until dropped.
    pub struct TlsPeer {
        #[doc(hidden)]
        pub addr: SocketAddr,
        listening: wslib_tls::testing::TlsPeer,
    }

    impl TlsPeer {
        pub async fn presenting((cert_pem, key_pem): &(String, String)) -> Self {
            let pair = Pair {
                chain: pem::certificates(cert_pem).expect("a certificate"),
                key: pem::private_key(key_pem).expect("a key"),
            };
            let listening = wslib_tls::testing::TlsPeer::presenting(provider(), &pair).await;
            Self {
                addr: listening.addr,
                listening,
            }
        }

        /// Where to point a look at this peer.
        pub fn target(&self) -> String {
            self.listening.target()
        }

        /// One handshake and one request with this peer through `config`.
        pub async fn handshake(&self, config: &Arc<rustls::ClientConfig>) -> Result<(), String> {
            self.listening
                .handshake(config)
                .await
                .map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::inspect::inspect_pem;
    use super::peer::{Authority, TlsPeer, self_signed};
    use super::*;

    async fn store() -> Store {
        Store::open_in_memory(None).await.expect("store")
    }

    /// An OS store of `roots` alone, rather than the machine's.
    async fn outbound(store: &Store, roots: &[&Authority]) -> Arc<Outbound> {
        let roots: Vec<_> = roots
            .iter()
            .map(|root| parse(&root.pem).expect("readable").into_der())
            .collect();
        let trust = read(store).await.expect("read");
        let trusting = wslib_tls::testing::outbound_with_os_roots(
            super::super::provider().unwrap(),
            trust,
            roots,
        )
        .expect("a client");
        Arc::new(Outbound {
            trusting: Arc::new(trusting),
            reloading: tokio::sync::Mutex::new(()),
        })
    }

    fn pin(host: &str, sha256: &str) -> TrustedCert {
        let at = wslib_appliance_store::now();
        TrustedCert {
            host: host.to_string(),
            sha256: sha256.to_string(),
            subject: String::new(),
            issuer: String::new(),
            not_before: at,
            not_after: at,
            added_at: at,
            added_by: "admin".to_string(),
        }
    }

    /// A pair signed by nobody, for another name, and expired: what a pin
    /// forgives and nothing else does.
    fn stale_pair() -> (String, String) {
        use wslib_crypto_x509::pem::{self, CERTIFICATE, PRIVATE_KEY};
        let key = wslib_crypto::KeyAlgorithm::EcP256.generate().expect("key");
        let signer =
            wslib_crypto::Signer::new(super::super::provider().unwrap(), &key.clone_key().into())
                .expect("loads");
        let mut params =
            rcgen::CertificateParams::new(vec!["widget-09.local".to_string()]).expect("names");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        params.serial_number = Some(1u64.into());
        (
            pem::encode(
                CERTIFICATE,
                params.self_signed(&signer).expect("signs").der(),
            ),
            pem::encode(PRIVATE_KEY, key.secret_pkcs8_der()),
        )
    }

    fn trusted(ca: &Authority) -> TrustedCa {
        let view = inspect_pem(&ca.pem).expect("readable");
        let at = wslib_appliance_store::now();
        TrustedCa {
            sha256: view.sha256,
            subject: view.subject,
            not_before: view.not_before,
            not_after: view.not_after,
            added_at: at,
            added_by: "admin".to_string(),
            pem: ca.pem.clone(),
        }
    }

    #[tokio::test]
    async fn a_pinned_certificate_is_trusted_though_nobody_signed_it() {
        // Another name, expired, and the pin in a spelling the verifier folds.
        let store = store().await;
        let pair = stale_pair();
        let peer = TlsPeer::presenting(&pair).await;
        let sha256 = inspect_pem(&pair.0).expect("readable").sha256;
        store
            .pin_cert(&pin("[127.0.0.1]", &sha256.to_uppercase()))
            .await
            .expect("pin");

        let config = Arc::new(outbound(&store, &[]).await.client_config());
        peer.handshake(&config)
            .await
            .expect("the pinned host connects");
    }

    #[tokio::test]
    async fn a_host_presenting_something_other_than_its_pin_is_refused_by_name() {
        let store = store().await;
        let pair = self_signed();
        let peer = TlsPeer::presenting(&pair).await;
        let presented = inspect_pem(&pair.0).expect("readable").sha256;
        store
            .pin_cert(&pin("127.0.0.1", &"ab".repeat(32)))
            .await
            .expect("pin");

        let config = Arc::new(outbound(&store, &[]).await.client_config());
        let why = peer
            .handshake(&config)
            .await
            .expect_err("a mismatch must not connect");
        // The sentence names both what is there and what was agreed.
        assert!(why.contains(&presented), "{why}");
        assert!(why.contains(&"ab".repeat(32)), "{why}");
    }

    #[tokio::test]
    async fn an_unpinned_self_signed_certificate_is_refused_at_the_roots() {
        // Additive: with no pin, refused as it would be with no table at all.
        let store = store().await;
        let peer = TlsPeer::presenting(&self_signed()).await;
        let unrelated = Authority::new("OS Root");
        let config = Arc::new(outbound(&store, &[&unrelated]).await.client_config());

        let why = peer
            .handshake(&config)
            .await
            .expect_err("nothing vouches for it");
        assert!(why.contains("UnknownIssuer"), "{why}");
    }

    #[tokio::test]
    async fn an_installed_authority_vouches_for_what_it_signed_with_no_client_rebuilt() {
        let store = store().await;
        let ca = Authority::new("Widget Root");
        let peer = TlsPeer::presenting(&ca.sign(&["127.0.0.1"])).await;
        let unrelated = Authority::new("OS Root");
        let outbound = outbound(&store, &[&unrelated]).await;
        let changes = outbound.subscribe();
        // Built before the authority exists: the verifier reads the live set.
        let config = Arc::new(outbound.client_config());

        let why = peer
            .handshake(&config)
            .await
            .expect_err("nobody vouches for it yet");
        assert!(why.contains("UnknownIssuer"), "{why}");

        let authority = trusted(&ca);
        outbound.trust(&store, &authority).await.expect("trust");
        assert!(changes.has_changed().expect("open"), "a write is a change");
        peer.handshake(&config)
            .await
            .expect("the authority's signature is enough");

        assert!(
            outbound
                .distrust(&store, &authority.sha256)
                .await
                .expect("distrust")
        );
        assert!(
            peer.handshake(&config).await.is_err(),
            "and removing it takes the trust away"
        );
    }

    #[tokio::test]
    async fn a_row_whose_bytes_are_not_the_authority_it_claims_anchors_nothing() {
        // A self-signed leaf must anchor nothing either: webpki would otherwise
        // take it as its own issuer and trust the host presenting it.
        let store = store().await;
        let ca = Authority::new("Widget Root");
        let signed = TlsPeer::presenting(&ca.sign(&["127.0.0.1"])).await;
        let pair = self_signed();
        let leaf = TlsPeer::presenting(&pair).await;
        store
            .trust_ca(&TrustedCa {
                sha256: "ab".repeat(32),
                ..trusted(&ca)
            })
            .await
            .expect("the authority under the wrong fingerprint");
        store
            .trust_ca(&TrustedCa {
                sha256: inspect_pem(&pair.0).expect("readable").sha256,
                pem: pair.0.clone(),
                ..trusted(&ca)
            })
            .await
            .expect("a leaf under its own");

        let config = Arc::new(outbound(&store, &[]).await.client_config());
        assert!(
            signed.handshake(&config).await.is_err(),
            "a mis-fingerprinted authority vouches for nothing"
        );
        assert!(
            leaf.handshake(&config).await.is_err(),
            "a leaf is not an authority, whatever row it sits in"
        );
    }

    #[tokio::test]
    async fn an_authority_vouches_only_for_the_names_it_signed() {
        let store = store().await;
        let ca = Authority::new("Widget Root");
        let peer = TlsPeer::presenting(&ca.sign(&["widget-02.local"])).await;
        store.trust_ca(&trusted(&ca)).await.expect("trust");

        let config = Arc::new(outbound(&store, &[]).await.client_config());
        let why = peer
            .handshake(&config)
            .await
            .expect_err("the name is wrong");
        assert!(why.contains("not valid for name"), "{why}");
    }

    #[tokio::test]
    async fn with_no_root_and_no_authority_only_a_pinned_host_connects() {
        let store = store().await;
        let peer = TlsPeer::presenting(&self_signed()).await;
        let why = peer
            .handshake(&Arc::new(outbound(&store, &[]).await.client_config()))
            .await
            .expect_err("nothing to check it against");
        assert!(why.contains("no authority to check it against"), "{why}");
    }

    #[tokio::test]
    async fn a_client_offers_http_1_1_and_nothing_else() {
        let store = store().await;
        assert_eq!(
            outbound(&store, &[]).await.client_config().alpn_protocols,
            [b"http/1.1".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_look_describes_what_a_host_presents_and_trusts_nothing() {
        let store = store().await;
        let pair = self_signed();
        let peer = TlsPeer::presenting(&pair).await;
        let outbound = outbound(&store, &[]).await;

        let seen = outbound.inspect(&peer.target()).await.expect("readable");
        assert_eq!(seen.host, "127.0.0.1");
        assert_eq!(seen.port, peer.addr.port());
        assert_eq!(
            seen.certificate.sha256,
            inspect_pem(&pair.0).expect("readable").sha256
        );
        assert!(seen.certificate.self_signed);
        assert!(
            store.trusted_certs().await.expect("pins").is_empty(),
            "looking is not trusting"
        );
    }

    #[tokio::test]
    async fn a_host_that_presents_nothing_is_reported_without_a_fingerprint() {
        let store = store().await;
        let outbound = outbound(&store, &[]).await;
        // A port that was just bound and released: nothing answers on it.
        let addr = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind")
            .local_addr()
            .expect("addr");

        let why = outbound
            .inspect(&format!("https://{addr}"))
            .await
            .expect_err("nothing to inspect");
        assert!(matches!(why, TlsError::Unreachable(_)), "{why}");
        let why = why.to_string();
        assert!(
            why.starts_with(&format!(
                "127.0.0.1:{} presented no certificate: ",
                addr.port()
            )),
            "{why}"
        );
        assert!(!why.contains("sha256"), "{why}");
    }

    #[tokio::test]
    async fn a_target_that_is_not_a_place_is_refused_as_one() {
        let store = store().await;
        let outbound = outbound(&store, &[]).await;
        for bad in ["http://widget.local/", "https://", "host:x"] {
            assert!(
                matches!(outbound.inspect(bad).await, Err(TlsError::Target(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_fingerprint_is_read_in_the_forms_people_paste() {
        let bare = "ab".repeat(32);
        let spaced = bare
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":")
            .to_uppercase();
        assert_eq!(canonical_sha256(&bare).unwrap(), bare);
        assert_eq!(canonical_sha256(&spaced).unwrap(), bare);
        assert!(canonical_sha256("AA:BB").is_err(), "too short");
        assert!(canonical_sha256(&"g".repeat(64)).is_err(), "not hex");
    }
}
