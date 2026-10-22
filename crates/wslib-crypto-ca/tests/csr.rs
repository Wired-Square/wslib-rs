mod common;

use common::{OPENSSL_P256_CSR, OPENSSL_RSA3072_CSR, algorithms, names, providers, signer};
use wslib_crypto::KeyAlgorithm;
use wslib_crypto_ca::{CERTIFICATE_REQUEST, Csr, CsrView, Error, Subject, build_csr};
use wslib_crypto_x509::pem;
use wslib_crypto_x509::signature::SignatureError;

#[test]
fn a_built_request_reads_back_on_every_provider_and_key() {
    let subject = common::widget_subject("host.example.com");
    let requested = names(&["host.example.com", "10.0.0.5", "ops@example.com"]);
    for (name, provider) in providers() {
        for algorithm in KeyAlgorithm::ALL {
            let signer = signer(&provider, algorithm);
            let der = build_csr(&signer, &subject, &requested).unwrap();
            let csr = Csr::from_der(&der, provider.signature_verification_algorithms.all)
                .unwrap_or_else(|e| panic!("{name} {algorithm}: {e}"));
            assert_eq!(csr.subject(), subject.to_der().unwrap());
            assert_eq!(csr.common_name(), Some("host.example.com"));
            assert_eq!(csr.names(), requested);
            assert_eq!(csr.spki(), signer.spki());
            assert_eq!(csr.key_algorithm(), Some(algorithm));
            assert_eq!(
                csr.has_rsa_key(),
                matches!(algorithm, KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096)
            );
        }
    }
}

#[test]
fn a_request_without_names_asks_for_none() {
    let (_, provider) = &providers()[0];
    let der = build_csr(
        &signer(provider, KeyAlgorithm::EcP256),
        &Subject::new("Alex"),
        &[],
    )
    .unwrap();
    let csr = Csr::from_der(&der, algorithms()).unwrap();
    assert_eq!(csr.names(), []);
    assert_eq!(csr.common_name(), Some("Alex"));
}

#[test]
fn an_openssl_request_reads_with_its_subject_byte_for_byte() {
    let csr = Csr::from_pem(OPENSSL_P256_CSR, algorithms()).unwrap();
    assert_eq!(
        csr.subject(),
        common::widget_subject("host.example.com").to_der().unwrap(),
        "Subject writes the string types OpenSSL does"
    );
    assert_eq!(
        csr.names(),
        names(&[
            "host.example.com",
            "www.example.com",
            "10.0.0.5",
            "2001:db8::1",
            "ops@example.com",
            "spiffe://prod/web",
        ])
    );
    assert_eq!(csr.key_algorithm(), Some(KeyAlgorithm::EcP256));
    assert_eq!(
        pem::encode(CERTIFICATE_REQUEST, csr.der()),
        OPENSSL_P256_CSR
    );
}

#[test]
fn an_rsa_key_of_a_size_we_do_not_generate_is_still_rsa() {
    let csr = Csr::from_pem(OPENSSL_RSA3072_CSR, algorithms()).unwrap();
    assert_eq!(csr.key_algorithm(), None);
    assert!(csr.has_rsa_key());
}

#[test]
fn a_tampered_request_is_refused() {
    let mut der = Csr::from_pem(OPENSSL_P256_CSR, algorithms())
        .unwrap()
        .der()
        .to_vec();
    let at = der
        .windows(9)
        .position(|w| w == b"Melbourne")
        .expect("the locality is in the request");
    der[at] = b'm';
    assert!(matches!(
        Csr::from_der(&der, algorithms()),
        Err(Error::Signature(SignatureError::BadSignature))
    ));
}

#[test]
fn a_request_needs_an_algorithm_the_caller_allows() {
    assert!(matches!(
        Csr::from_pem(OPENSSL_P256_CSR, &[]),
        Err(Error::Signature(SignatureError::NoAlgorithm))
    ));
}

#[test]
fn what_is_not_a_request_is_malformed() {
    assert!(matches!(
        Csr::from_der(b"\x30\x03\x02\x01\x01", algorithms()),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        Csr::from_pem(
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
            algorithms()
        ),
        Err(Error::Malformed(_))
    ));
    let long = " ".repeat(pem::MAX_LEN + 1);
    assert!(matches!(
        Csr::from_pem(&long, algorithms()),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn a_subject_refuses_what_its_string_types_cannot_hold() {
    let refused = |subject: Subject| matches!(subject.to_der(), Err(Error::Name { .. }));
    assert!(refused(Subject::new("")));
    for country in ["AUS", "Ä1", "A"] {
        assert!(refused(Subject {
            country: Some(country.into()),
            ..Subject::new("x")
        }));
    }
    assert!(refused(Subject {
        email: Some("öps@example.com".into()),
        ..Subject::new("x")
    }));
}

#[test]
fn a_non_ascii_name_cannot_be_requested() {
    let (_, provider) = &providers()[0];
    let name = wslib_crypto_x509::SubjectAltName::Dns("bücher.example".into());
    assert!(matches!(
        build_csr(
            &signer(provider, KeyAlgorithm::EcP256),
            &Subject::new("x"),
            &[name]
        ),
        Err(Error::Name { .. })
    ));
}

#[test]
fn a_stored_request_reads_without_a_provider_and_verifies_into_a_csr() {
    let view = CsrView::from_pem(OPENSSL_P256_CSR).unwrap();
    assert_eq!(view.common_name(), Some("host.example.com"));
    assert_eq!(view.names().len(), 6);
    let csr = view.verify(algorithms()).unwrap();
    assert_eq!(*csr, view);
    assert_eq!(csr, Csr::from_pem(OPENSSL_P256_CSR, algorithms()).unwrap());
}

#[test]
fn a_sha1_request_reads_but_does_not_verify_without_a_sha1_algorithm() {
    let view = CsrView::from_pem(include_str!("data/openssl-sha1.csr")).unwrap();
    assert_eq!(view.common_name(), Some("legacy.example.com"));
    assert_eq!(view.names(), names(&["legacy.example.com"]));
    assert!(view.has_rsa_key());
    assert!(matches!(
        view.verify(algorithms()),
        Err(Error::Signature(SignatureError::NoAlgorithm))
    ));
}
