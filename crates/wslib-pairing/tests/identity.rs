use std::sync::Arc;
use std::time::SystemTime;

use rustls::crypto::ring::default_provider;
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_x509::SubjectAltName;
use wslib_crypto_x509::pem::{self, CERTIFICATE};
use wslib_tls::{KeyFingerprint, Location, Serving};

fn pin(cert_pem: &str) -> KeyFingerprint {
    KeyFingerprint::of(&pem::certificates(cert_pem).unwrap()[0]).unwrap()
}

#[tokio::test]
async fn the_serving_key_survives_a_chain_replacement() {
    let provider = Arc::new(default_provider());
    let dir = tempfile::tempdir().unwrap();
    let location =
        || Location::managed(dir.path().join("daemon.crt"), dir.path().join("daemon.key"));
    let names = || vec![SubjectAltName::Dns("daemon.lan".into())];

    let serving =
        Serving::load_or_mint(provider.clone(), location(), names, KeyAlgorithm::EcP256).unwrap();
    let minted = serving.pair().await.unwrap();

    let key = pem::private_key(minted.key_pem.expose()).unwrap();
    let signer = Signer::new(provider.clone(), &key).unwrap();
    let signed =
        wslib_crypto_x509::mint(&signer, &[SubjectAltName::Dns("signed.lan".into())]).unwrap();
    let chain = pem::encode(CERTIFICATE, &signed);
    serving
        .install_pem(&chain, &minted.key_pem, None, SystemTime::now())
        .await
        .unwrap();
    drop(serving);

    let restarted =
        Serving::load_or_mint(provider, location(), names, KeyAlgorithm::EcP256).unwrap();
    let after = restarted.pair().await.unwrap();
    assert_ne!(after.cert_pem, minted.cert_pem);
    assert!(after.key_pem.matches(&minted.key_pem));
    assert_eq!(pin(&after.cert_pem), pin(&minted.cert_pem));
}
