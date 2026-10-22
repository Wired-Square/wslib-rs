#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, SignatureVerificationAlgorithm};
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_ca::Subject;
use wslib_crypto_x509::SubjectAltName;

pub fn providers() -> [(&'static str, Arc<CryptoProvider>); 2] {
    [
        ("ring", Arc::new(rustls::crypto::ring::default_provider())),
        (
            "aws-lc-rs",
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ),
    ]
}

pub fn algorithms() -> &'static [&'static dyn SignatureVerificationAlgorithm] {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all
}

pub fn key(algorithm: KeyAlgorithm) -> PrivateKeyDer<'static> {
    let index = KeyAlgorithm::ALL
        .iter()
        .position(|a| *a == algorithm)
        .unwrap();
    keys()[index].clone_key().into()
}

/// A P-256 key that is none of [`key`]'s.
pub fn another_key() -> PrivateKeyDer<'static> {
    keys()[KeyAlgorithm::ALL.len()].clone_key().into()
}

fn keys() -> &'static [PrivatePkcs8KeyDer<'static>] {
    static KEYS: OnceLock<Vec<PrivatePkcs8KeyDer<'static>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        KeyAlgorithm::ALL
            .iter()
            .chain([&KeyAlgorithm::EcP256])
            .map(|algorithm| algorithm.generate().expect("generates"))
            .collect()
    })
}

pub fn signer(provider: &Arc<CryptoProvider>, algorithm: KeyAlgorithm) -> Signer {
    Signer::new(provider.clone(), &key(algorithm)).expect("loads")
}

pub fn names(names: &[&str]) -> Vec<SubjectAltName> {
    names.iter().map(|name| name.parse().unwrap()).collect()
}

/// The subject of `tests/data/openssl-p256.csr`, field for field.
pub fn widget_subject(common_name: &str) -> Subject {
    Subject {
        common_name: common_name.to_string(),
        country: Some("AU".into()),
        state: Some("Victoria".into()),
        locality: Some("Melbourne".into()),
        organisation: Some("Wïdget Co".into()),
        organisational_unit: Some("Ops".into()),
        email: Some("ops@example.com".into()),
    }
}

pub const OPENSSL_P256_CSR: &str = include_str!("../data/openssl-p256.csr");
pub const OPENSSL_RSA3072_CSR: &str = include_str!("../data/openssl-rsa3072.csr");
