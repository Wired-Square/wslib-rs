use std::fmt;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WantsClientCert, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{
    CertificateError, ClientConfig, ConfigBuilder, DigitallySignedStruct, RootCertStore,
    SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio::sync::watch;
use wslib_crypto::Fingerprint;

use crate::os::{OsRoots, ReadOs};
use crate::trust::Pin;
use crate::{KeyFingerprint, Rejection, Trust, normalise_host};

pub(crate) const OS_WAIT: Duration = Duration::from_secs(30);

/// What an app trusts for the connections it makes, on the caller's provider.
pub struct Outbound {
    provider: Arc<CryptoProvider>,
    current: RwLock<Arc<Reading>>,
    changed: watch::Sender<u64>,
    os: Arc<OsRoots>,
    os_wait: Duration,
}

/// One [`Trust`], with the verifier over its roots built by the first handshake that needs it.
struct Reading {
    trust: Trust,
    built: Mutex<Option<BuiltOn>>,
}

struct BuiltOn {
    os: Option<Arc<RootCertStore>>,
    verifier: Option<Arc<WebPkiServerVerifier>>,
}

impl Outbound {
    /// Starts reading the OS store in the background when `trust` asks for it, and returns without waiting.
    ///
    /// Fails when the provider cannot make a TLS 1.2 or 1.3 client.
    pub fn new(provider: Arc<CryptoProvider>, trust: Trust) -> Result<Self, rustls::Error> {
        Self::reading_os_with(
            provider,
            trust,
            Arc::new(rustls_native_certs::load_native_certs),
            OS_WAIT,
        )
    }

    pub(crate) fn reading_os_with(
        provider: Arc<CryptoProvider>,
        trust: Trust,
        read: ReadOs,
        os_wait: Duration,
    ) -> Result<Self, rustls::Error> {
        ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?;
        let outbound = Self {
            provider,
            current: RwLock::new(Arc::new(Reading::new(Trust::default()))),
            changed: watch::Sender::new(0),
            os: OsRoots::new(read),
            os_wait,
        };
        outbound.replace(trust);
        Ok(outbound)
    }

    /// Replaces what is trusted, for the next handshake of every client built here, and tells subscribers.
    pub fn set_trust(&self, trust: Trust) {
        self.replace(trust);
        self.changed.send_modify(|generation| *generation += 1);
    }

    /// What is trusted now, as last given to [`set_trust`](Self::set_trust).
    pub fn trust(&self) -> Trust {
        self.reading().trust.clone()
    }

    /// Changes whenever [`set_trust`](Self::set_trust) is called; the value is a generation.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// A client configuration verifying as the crate doc says, with resumption
    /// off and no ALPN, for `reqwest`'s `use_preconfigured_tls` or a `TlsConnector`.
    pub fn client_config(self: &Arc<Self>) -> ClientConfig {
        self.config(Judge::Trusting(self.clone()))
    }

    /// [`client_config`](Self::client_config), presenting `chain`, leaf first,
    /// and its `key` to a server that asks for a client certificate.
    ///
    /// Fails when the provider cannot load the key or it is not the leaf's.
    pub fn client_config_presenting(
        self: &Arc<Self>,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, rustls::Error> {
        self.verifying(Judge::Trusting(self.clone()))
            .with_client_auth_cert(chain, key)
            .map(without_resumption)
    }

    pub(crate) fn config(&self, judge: Judge) -> ClientConfig {
        without_resumption(self.verifying(judge).with_no_client_auth())
    }

    fn verifying(&self, judge: Judge) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("checked in Outbound::new")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Verifier {
                provider: self.provider.clone(),
                judge,
            }))
    }

    fn replace(&self, trust: Trust) {
        if trust.os_roots {
            self.os.refresh();
        }
        *self.current.write().unwrap_or_else(PoisonError::into_inner) =
            Arc::new(Reading::new(trust));
    }

    fn reading(&self) -> Arc<Reading> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let host = normalise_host(&server_name.to_str());
        let mut reading = self.reading();
        if let Some(answer) = reading.pinned(&host, end_entity) {
            return answer;
        }
        let os = match (reading.trust.os_roots, self.os.landed()) {
            (false, _) => None,
            (true, Some(os)) => Some(os),
            (true, None) => {
                let os = self
                    .os
                    .within(self.os_wait)
                    .ok_or_else(|| Rejection::OsRootsNotRead { host: host.clone() })?;
                // The trust may have been replaced during the wait.
                reading = self.reading();
                if let Some(answer) = reading.pinned(&host, end_entity) {
                    return answer;
                }
                reading.trust.os_roots.then_some(os)
            }
        };
        reading
            .verifier(os, &self.provider)
            .ok_or(Rejection::NoAuthority { host })?
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }
}

fn without_resumption(mut config: ClientConfig) -> ClientConfig {
    config.resumption = Resumption::disabled();
    config
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbound")
            .field("generation", &*self.changed.borrow())
            .finish_non_exhaustive()
    }
}

impl Reading {
    fn new(trust: Trust) -> Self {
        Self {
            trust,
            built: Mutex::default(),
        }
    }

    fn pinned(
        &self,
        host: &str,
        end_entity: &CertificateDer<'_>,
    ) -> Option<Result<ServerCertVerified, rustls::Error>> {
        Some(match *self.trust.pins.get(host)? {
            Pin::Certificate(pinned) => match Fingerprint::of(end_entity) {
                presented if presented == pinned => Ok(ServerCertVerified::assertion()),
                presented => Err(Rejection::PinMismatch {
                    host: host.to_string(),
                    presented,
                    pinned,
                }
                .into()),
            },
            Pin::Key(pinned) => match KeyFingerprint::of(end_entity) {
                Ok(presented) if presented == pinned => Ok(ServerCertVerified::assertion()),
                Ok(presented) => Err(Rejection::KeyPinMismatch {
                    host: host.to_string(),
                    presented,
                    pinned,
                }
                .into()),
                Err(_) => Err(CertificateError::BadEncoding.into()),
            },
        })
    }

    /// `None` when there are neither OS roots nor anchors.
    fn verifier(
        &self,
        os: Option<Arc<RootCertStore>>,
        provider: &Arc<CryptoProvider>,
    ) -> Option<Arc<WebPkiServerVerifier>> {
        let mut built = self.built.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(built) = &*built
            && built.os.as_ref().map(Arc::as_ptr) == os.as_ref().map(Arc::as_ptr)
        {
            return built.verifier.clone();
        }
        let mut roots = os.as_deref().cloned().unwrap_or_else(RootCertStore::empty);
        roots.extend(self.trust.anchors.iter().map(|(_, anchor)| anchor.clone()));
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .ok();
        *built = Some(BuiltOn {
            os,
            verifier: verifier.clone(),
        });
        verifier
    }
}

#[derive(Debug)]
pub(crate) enum Judge {
    Trusting(Arc<Outbound>),
    /// Keeps the chain it was shown and accepts it: the look before a pin.
    Recording(Recorder),
}

pub(crate) type Recorder =
    Arc<Mutex<Option<(CertificateDer<'static>, Vec<CertificateDer<'static>>)>>>;

#[derive(Debug)]
struct Verifier {
    provider: Arc<CryptoProvider>,
    judge: Judge,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match &self.judge {
            Judge::Trusting(outbound) => {
                outbound.verify(end_entity, intermediates, server_name, ocsp_response, now)
            }
            Judge::Recording(seen) => {
                *seen.lock().unwrap_or_else(PoisonError::into_inner) = Some((
                    end_entity.clone().into_owned(),
                    intermediates
                        .iter()
                        .map(|der| der.clone().into_owned())
                        .collect(),
                ));
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Condvar;

    use rustls::CertificateError;
    use rustls_native_certs::CertificateResult;

    use super::*;
    use wslib_crypto::{KeyAlgorithm, Signer};

    use crate::testing::{
        Authority, Pair, TlsPeer, outbound_with_os_roots, providers, self_signed,
    };
    use crate::{Cause, cause};

    /// An OS store holding one root that signed nothing here.
    fn unrelated_os(provider: &Arc<CryptoProvider>) -> Vec<CertificateDer<'static>> {
        vec![Authority::new(provider.clone(), "OS Root").certificate]
    }

    fn outbound(
        provider: &Arc<CryptoProvider>,
        trust: Trust,
        os: Vec<CertificateDer<'static>>,
    ) -> Arc<Outbound> {
        Arc::new(outbound_with_os_roots(provider.clone(), trust, os).expect("a client"))
    }

    fn refused(result: std::io::Result<()>) -> Cause {
        cause(&result.expect_err("refused")).expect("a cause")
    }

    #[tokio::test]
    async fn a_pinned_certificate_is_trusted_though_nobody_signed_it_for_that_name_or_now() {
        for (name, provider) in providers() {
            let pair = Authority::new(provider.clone(), "Nobody").sign_with(
                &["widget-09.local"],
                |params| {
                    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
                    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
                },
            );
            let peer = TlsPeer::presenting(provider.clone(), &pair).await;
            let mut trust = Trust::default();
            trust.pin("[127.0.0.1]", Fingerprint::of(&pair.chain[0]));

            let config =
                Arc::new(outbound(&provider, trust, unrelated_os(&provider)).client_config());
            peer.handshake(&config).await.expect(name);
        }
    }

    #[tokio::test]
    async fn a_host_presenting_something_other_than_its_pin_is_refused_with_both() {
        for (name, provider) in providers() {
            let pair = self_signed(provider.clone(), &["127.0.0.1"]);
            let peer = TlsPeer::presenting(provider.clone(), &pair).await;
            let pinned = Fingerprint::of(b"another certificate");
            let mut trust = Trust::os_roots();
            trust.pin("127.0.0.1", pinned);

            let config =
                Arc::new(outbound(&provider, trust, unrelated_os(&provider)).client_config());
            assert_eq!(
                refused(peer.handshake(&config).await),
                Cause::Rejected(Rejection::PinMismatch {
                    host: "127.0.0.1".into(),
                    presented: Fingerprint::of(&pair.chain[0]),
                    pinned,
                }),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn an_installed_authority_vouches_for_what_it_signed_with_no_client_rebuilt() {
        for (name, provider) in providers() {
            let ca = Authority::new(provider.clone(), "Widget Root");
            let peer = TlsPeer::presenting(provider.clone(), &ca.sign(&["127.0.0.1"])).await;
            let outbound = outbound(&provider, Trust::os_roots(), unrelated_os(&provider));
            let changes = outbound.subscribe();
            let config = Arc::new(outbound.client_config());
            assert!(config.alpn_protocols.is_empty());

            assert_eq!(
                refused(peer.handshake(&config).await),
                Cause::Certificate(CertificateError::UnknownIssuer),
                "{name}"
            );

            let mut trust = Trust::os_roots();
            trust.anchor(&ca.certificate).expect("an authority");
            outbound.set_trust(trust);
            assert!(changes.has_changed().expect("open"), "{name}");
            assert!(outbound.trust().anchors().eq([&ca.certificate]), "{name}");
            peer.handshake(&config).await.expect(name);

            outbound.set_trust(Trust::os_roots());
            assert!(
                peer.handshake(&config).await.is_err(),
                "{name}: and gone again"
            );
        }
    }

    #[tokio::test]
    async fn an_authority_vouches_only_for_the_names_it_signed() {
        for (name, provider) in providers() {
            let ca = Authority::new(provider.clone(), "Widget Root");
            let peer = TlsPeer::presenting(provider.clone(), &ca.sign(&["widget-02.local"])).await;
            let mut trust = Trust::default();
            trust.anchor(&ca.certificate).expect("an authority");

            let config =
                Arc::new(outbound(&provider, trust, unrelated_os(&provider)).client_config());
            assert!(
                matches!(
                    refused(peer.handshake(&config).await),
                    Cause::Certificate(
                        CertificateError::NotValidForName
                            | CertificateError::NotValidForNameContext { .. }
                    )
                ),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn with_no_roots_and_no_authority_only_a_pin_connects() {
        for (name, provider) in providers() {
            let peer = TlsPeer::presenting(
                provider.clone(),
                &self_signed(provider.clone(), &["127.0.0.1"]),
            )
            .await;
            let config = Arc::new(outbound(&provider, Trust::os_roots(), vec![]).client_config());
            assert_eq!(
                refused(peer.handshake(&config).await),
                Cause::Rejected(Rejection::NoAuthority {
                    host: "127.0.0.1".into()
                }),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn a_look_returns_the_chain_a_host_presents_and_trusts_nothing() {
        for (name, provider) in providers() {
            let ca = Authority::new(provider.clone(), "Widget Root");
            let mut pair = ca.sign(&["widget-02.local"]);
            pair.chain.push(ca.certificate.clone());
            let peer = TlsPeer::presenting(provider.clone(), &pair).await;
            let outbound = outbound(&provider, Trust::default(), vec![]);

            let seen = outbound.inspect(&peer.target()).await.expect(name);
            assert_eq!(seen.host, "127.0.0.1");
            assert_eq!(seen.port, peer.addr.port());
            assert_eq!(seen.end_entity, pair.chain[0]);
            assert_eq!(seen.intermediates, [ca.certificate]);
        }
    }

    #[tokio::test]
    async fn a_host_that_presents_nothing_is_reported_by_host_and_port() {
        let (_, provider) = &providers()[0];
        let outbound = outbound(provider, Trust::default(), vec![]);
        let addr = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind")
            .local_addr()
            .expect("addr");

        let why = outbound
            .inspect(&format!("https://{addr}"))
            .await
            .expect_err("nothing to inspect");
        assert!(
            matches!(&why, crate::ProbeError::Failed { host, port, .. } if host == "127.0.0.1" && *port == addr.port()),
            "{why}"
        );
    }

    /// An OS store whose read waits until released, or until this is dropped.
    #[derive(Clone, Default)]
    struct Held(Arc<(Mutex<Option<Vec<CertificateDer<'static>>>>, Condvar)>);

    impl Held {
        fn reader(&self) -> ReadOs {
            let held = self.clone();
            Arc::new(move || {
                let (roots, released) = &*held.0;
                let roots = released
                    .wait_while(roots.lock().unwrap(), |roots| roots.is_none())
                    .unwrap();
                let mut read = CertificateResult::default();
                read.certs = roots.clone().unwrap_or_default();
                read
            })
        }

        fn release(&self, roots: Vec<CertificateDer<'static>>) {
            let (held, released) = &*self.0;
            held.lock().unwrap().get_or_insert(roots);
            released.notify_all();
        }
    }

    impl Drop for Held {
        fn drop(&mut self) {
            self.release(Vec::new());
        }
    }

    /// An outbound trusting one authority and the OS store, and a peer the authority alone would vouch for.
    struct Vouched {
        provider: Arc<CryptoProvider>,
        held: Held,
        peer: Arc<TlsPeer>,
        outbound: Arc<Outbound>,
    }

    impl Vouched {
        async fn new(provider: Arc<CryptoProvider>, os_wait: Duration) -> Self {
            let ca = Authority::new(provider.clone(), "Widget Root");
            let mut trust = Trust::os_roots();
            trust.anchor(&ca.certificate).expect("an authority");
            let peer =
                Arc::new(TlsPeer::presenting(provider.clone(), &ca.sign(&["127.0.0.1"])).await);
            let held = Held::default();
            let outbound = Arc::new(
                Outbound::reading_os_with(provider.clone(), trust, held.reader(), os_wait)
                    .expect("a client"),
            );
            Self {
                provider,
                held,
                peer,
                outbound,
            }
        }

        fn dial(&self) -> tokio::task::JoinHandle<std::io::Result<()>> {
            let peer = self.peer.clone();
            let config = Arc::new(self.outbound.client_config());
            tokio::spawn(async move { peer.handshake(&config).await })
        }
    }

    async fn answer(dial: tokio::task::JoinHandle<std::io::Result<()>>) -> std::io::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), dial)
            .await
            .expect("the dial goes on once the OS store lands")
            .expect("did not panic")
    }

    /// Long enough for a spawned dial to reach the verifier and wait there.
    const INTO_THE_WAIT: Duration = Duration::from_millis(300);

    // Multi-threaded, as a waiting handshake hands its worker on only there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_before_the_os_store_lands_waits_for_it_then_connects() {
        for (name, provider) in providers() {
            let vouched = Vouched::new(provider, OS_WAIT).await;
            let dial = vouched.dial();
            tokio::time::sleep(INTO_THE_WAIT).await;
            assert!(
                !dial.is_finished(),
                "{name}: the authority alone would have answered"
            );

            vouched.held.release(Vec::new());
            answer(dial).await.expect(name);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pin_made_during_the_wait_decides_the_waiting_dial() {
        for (name, provider) in providers() {
            let vouched = Vouched::new(provider, OS_WAIT).await;
            let dial = vouched.dial();
            tokio::time::sleep(INTO_THE_WAIT).await;
            let pinned = Fingerprint::of(b"another certificate");
            let mut trust = Trust::os_roots();
            trust.pin("127.0.0.1", pinned);
            vouched.outbound.set_trust(trust);

            vouched.held.release(Vec::new());
            assert!(
                matches!(refused(answer(dial).await), Cause::Rejected(Rejection::PinMismatch { pinned: p, .. }) if p == pinned),
                "{name}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_authority_removed_during_the_wait_no_longer_vouches() {
        for (name, provider) in providers() {
            let vouched = Vouched::new(provider, OS_WAIT).await;
            let dial = vouched.dial();
            tokio::time::sleep(INTO_THE_WAIT).await;
            vouched.outbound.set_trust(Trust::os_roots());

            vouched.held.release(Vec::new());
            assert_eq!(
                refused(answer(dial).await),
                Cause::Rejected(Rejection::NoAuthority {
                    host: "127.0.0.1".into()
                }),
                "{name}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dials_waiting_on_the_os_store_leave_the_runtime_free() {
        for (name, provider) in providers() {
            let vouched = Vouched::new(provider, OS_WAIT).await;
            let dials: Vec<_> = (0..4).map(|_| vouched.dial()).collect();

            // Waited out on this thread: with every worker frozen, the runtime's timers would not fire.
            std::thread::sleep(INTO_THE_WAIT);
            let (ran, answered) = std::sync::mpsc::channel();
            tokio::spawn(async move { ran.send(()) });
            assert!(
                answered.recv_timeout(Duration::from_secs(2)).is_ok(),
                "{name}: an unrelated task runs while four dials wait"
            );
            assert!(dials.iter().all(|dial| !dial.is_finished()), "{name}");

            vouched.held.release(Vec::new());
            for dial in dials {
                answer(dial).await.expect(name);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_that_outwaits_the_os_store_fails_and_leaves_nothing_cached() {
        for (name, provider) in providers() {
            let vouched = Vouched::new(provider, Duration::from_millis(200)).await;
            assert_eq!(
                refused(answer(vouched.dial()).await),
                Cause::Rejected(Rejection::OsRootsNotRead {
                    host: "127.0.0.1".into()
                }),
                "{name}"
            );

            // A root only the OS store holds: what it signed connects only if the landed read is used.
            let os_authority = Authority::new(vouched.provider.clone(), "OS Root");
            vouched.held.release(vec![os_authority.certificate.clone()]);
            vouched
                .outbound
                .os
                .within(Duration::from_secs(5))
                .expect("the OS store lands");
            TlsPeer::presenting(vouched.provider.clone(), &os_authority.sign(&["127.0.0.1"]))
                .await
                .handshake(&Arc::new(vouched.outbound.client_config()))
                .await
                .expect(name);
        }
    }

    /// A self-signed certificate for `127.0.0.1` over `key`, freshly minted.
    fn minted_over(provider: &Arc<CryptoProvider>, key: &PrivateKeyDer<'static>) -> Pair {
        let signer = Signer::new(provider.clone(), key).expect("loads");
        let names = ["127.0.0.1".parse().expect("an address")];
        Pair {
            chain: vec![wslib_crypto_x509::mint(&signer, &names).expect("mints")],
            key: key.clone_key(),
        }
    }

    fn generated() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from(KeyAlgorithm::EcP256.generate().expect("generates"))
    }

    #[tokio::test]
    async fn a_key_pin_trusts_a_certificate_re_minted_over_the_same_key() {
        for (name, provider) in providers() {
            let key = generated();
            let (printed, reminted) = (minted_over(&provider, &key), minted_over(&provider, &key));
            assert_ne!(printed.chain, reminted.chain);
            let mut trust = Trust::default();
            trust.pin_key(
                "127.0.0.1",
                KeyFingerprint::of(&printed.chain[0]).expect("readable"),
            );

            let peer = TlsPeer::presenting(provider.clone(), &reminted).await;
            let config = Arc::new(outbound(&provider, trust, vec![]).client_config());
            peer.handshake(&config).await.expect(name);
        }
    }

    #[tokio::test]
    async fn a_key_pin_refuses_a_certificate_over_another_key_with_both() {
        for (name, provider) in providers() {
            let pinned = KeyFingerprint::of(&minted_over(&provider, &generated()).chain[0])
                .expect("readable");
            let other = minted_over(&provider, &generated());
            let mut trust = Trust::default();
            trust.pin_key("127.0.0.1", pinned);

            let peer = TlsPeer::presenting(provider.clone(), &other).await;
            let config = Arc::new(outbound(&provider, trust, vec![]).client_config());
            assert_eq!(
                refused(peer.handshake(&config).await),
                Cause::Rejected(Rejection::KeyPinMismatch {
                    host: "127.0.0.1".into(),
                    presented: KeyFingerprint::of(&other.chain[0]).expect("readable"),
                    pinned,
                }),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn a_look_reports_the_fingerprint_of_the_key_presented() {
        for (name, provider) in providers() {
            let key = generated();
            let signer = Signer::new(provider.clone(), &key).expect("loads");
            let peer = TlsPeer::presenting(provider.clone(), &minted_over(&provider, &key)).await;
            let outbound = outbound(&provider, Trust::default(), vec![]);

            let seen = outbound.inspect(&peer.target()).await.expect(name);
            assert_eq!(
                seen.key_fingerprint,
                Some(KeyFingerprint(Fingerprint::of(signer.spki()))),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn a_client_presents_its_certificate_to_a_server_that_asks() {
        for (name, provider) in providers() {
            let clients = Authority::new(provider.clone(), "Client Root");
            let mut roots = RootCertStore::empty();
            roots.add(clients.certificate.clone()).expect("a root");
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider.clone(),
            )
            .build()
            .expect("a verifier");
            let served = self_signed(provider.clone(), &["127.0.0.1"]);
            let config = rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("TLS 1.2 or 1.3")
                .with_client_cert_verifier(verifier)
                .with_single_cert(served.chain.clone(), served.key.clone_key())
                .expect("a pair");
            let peer = TlsPeer::serving(Arc::new(config)).await;
            let mut trust = Trust::default();
            trust.pin("127.0.0.1", Fingerprint::of(&served.chain[0]));
            let outbound = outbound(&provider, trust, vec![]);

            assert!(
                peer.handshake(&Arc::new(outbound.client_config()))
                    .await
                    .is_err(),
                "{name}: no certificate"
            );
            let client = clients.sign_client("Session");
            let presenting = outbound
                .client_config_presenting(client.chain, client.key)
                .expect("the key is the leaf's");
            peer.handshake(&Arc::new(presenting)).await.expect(name);
        }
    }

    #[test]
    fn a_client_key_that_is_not_the_leafs_is_refused_up_front() {
        let (_, provider) = &providers()[0];
        let outbound = outbound(provider, Trust::default(), vec![]);
        let client = Authority::new(provider.clone(), "Client Root").sign_client("Session");
        assert!(
            outbound
                .client_config_presenting(client.chain, generated())
                .is_err()
        );
    }

    #[test]
    fn a_provider_that_cannot_make_a_client_is_refused_up_front() {
        let provider = CryptoProvider {
            cipher_suites: Vec::new(),
            ..rustls::crypto::ring::default_provider()
        };
        assert!(Outbound::new(Arc::new(provider), Trust::default()).is_err());
    }
}
