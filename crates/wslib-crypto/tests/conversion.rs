use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{PrivateKeyDer, PrivateSec1KeyDer};
use wslib_crypto::{Error, KeyAlgorithm, Signer, to_pkcs8};

fn read(pem: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem).expect("fixture reads")
}

fn spki(key: &PrivateKeyDer<'_>) -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Signer::new(provider, key).expect("loads").spki().to_vec()
}

#[test]
fn a_sec1_or_pkcs1_key_converts_to_the_same_key_in_pkcs8() {
    for (pem, algorithm) in [
        (
            &include_bytes!("../testdata/p256.sec1.pem")[..],
            KeyAlgorithm::EcP256,
        ),
        (
            include_bytes!("../testdata/p384.sec1.pem"),
            KeyAlgorithm::EcP384,
        ),
        (
            include_bytes!("../testdata/rsa2048.pkcs1.pem"),
            KeyAlgorithm::Rsa2048,
        ),
    ] {
        let original = read(pem);
        assert!(!matches!(original, PrivateKeyDer::Pkcs8(_)), "{algorithm}");
        let converted = PrivateKeyDer::Pkcs8(to_pkcs8(&original).expect("converts"));
        assert_eq!(spki(&converted), spki(&original), "{algorithm}");
        assert_eq!(KeyAlgorithm::of_spki(&spki(&converted)), Some(algorithm));
    }
}

#[test]
fn a_pkcs1_key_is_wrapped_as_openssl_wraps_it() {
    let converted = to_pkcs8(&read(include_bytes!("../testdata/rsa2048.pkcs1.pem"))).unwrap();
    let openssl = read(include_bytes!("../testdata/rsa2048.pkcs8.pem"));
    assert_eq!(converted.secret_pkcs8_der(), openssl.secret_der());
}

#[test]
fn a_pkcs8_key_passes_through_unchanged() {
    let key = KeyAlgorithm::EcP256.generate().unwrap();
    let converted = to_pkcs8(&PrivateKeyDer::Pkcs8(key.clone_key())).unwrap();
    assert_eq!(converted.secret_pkcs8_der(), key.secret_pkcs8_der());
}

#[test]
fn another_curve_or_rsa_size_is_unsupported() {
    for pem in [
        &include_bytes!("../testdata/secp256k1.sec1.pem")[..],
        include_bytes!("../testdata/rsa1024.pkcs1.pem"),
    ] {
        assert!(matches!(to_pkcs8(&read(pem)), Err(Error::Unsupported)));
    }
}

#[test]
fn garbage_is_malformed() {
    let garbage = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(vec![0x30, 0x03, 0x02, 0x01]));
    assert!(matches!(to_pkcs8(&garbage), Err(Error::Malformed(_))));
    let garbage = PrivateKeyDer::Pkcs1(vec![0x30, 0x00].into());
    assert!(matches!(to_pkcs8(&garbage), Err(Error::Malformed(_))));
}
