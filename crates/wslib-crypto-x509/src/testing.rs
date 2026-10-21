use std::sync::{Arc, OnceLock};

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, SerialNumber};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use wslib_crypto::{KeyAlgorithm, Signer, random_serial};

use crate::pem;

fn key(algorithm: KeyAlgorithm) -> PrivatePkcs8KeyDer<'static> {
    static KEYS: OnceLock<Vec<PrivatePkcs8KeyDer<'static>>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        [
            KeyAlgorithm::EcP256,
            KeyAlgorithm::EcP384,
            KeyAlgorithm::Rsa2048,
        ]
        .map(|algorithm| algorithm.generate().expect("generates"))
        .into()
    });
    let index = KeyAlgorithm::ALL
        .iter()
        .position(|a| *a == algorithm)
        .unwrap();
    keys[index].clone_key()
}

pub fn signer(algorithm: KeyAlgorithm) -> Signer {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Signer::new(provider, &PrivateKeyDer::Pkcs8(key(algorithm))).expect("loads")
}

pub fn key_pem() -> String {
    pem::encode(
        pem::PRIVATE_KEY,
        key(KeyAlgorithm::EcP256).secret_pkcs8_der(),
    )
}

/// A server certificate for `widget-01.local`, self-signed with P-256, changed by `build`.
pub fn certificate(build: impl FnOnce(&mut CertificateParams)) -> String {
    certificate_by(&signer(KeyAlgorithm::EcP256), build)
}

pub fn certificate_by(signer: &Signer, build: impl FnOnce(&mut CertificateParams)) -> String {
    let mut params = CertificateParams::new(vec!["widget-01.local".to_string()]).unwrap();
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_identifier_method = KeyIdMethod::PreSpecified(signer.key_identifier().to_vec());
    params.serial_number = Some(SerialNumber::from_slice(
        &random_serial(signer.provider()).unwrap(),
    ));
    build(&mut params);
    pem::encode(
        pem::CERTIFICATE,
        params.self_signed(signer).expect("signs").der(),
    )
}
