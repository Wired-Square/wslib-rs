use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use rcgen::SigningKey;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyIdMethod, KeyUsagePurpose, SerialNumber,
};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{
    AlgorithmIdentifier, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, alg_id,
};
use wslib_crypto::{KeyAlgorithm, Signer, key_matches, random_serial};
use wslib_crypto_x509::chain::{self, ChainError, Purpose};
use wslib_crypto_x509::signature::{self, SignatureError};
use wslib_crypto_x509::{SubjectAltName, examine, inspect, mint, pem};

fn providers() -> [(&'static str, Arc<CryptoProvider>); 2] {
    [
        ("ring", Arc::new(rustls::crypto::ring::default_provider())),
        (
            "aws-lc-rs",
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ),
    ]
}

fn key(algorithm: KeyAlgorithm) -> PrivateKeyDer<'static> {
    static KEYS: OnceLock<Vec<PrivatePkcs8KeyDer<'static>>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        KeyAlgorithm::ALL
            .iter()
            .map(|algorithm| algorithm.generate().expect("generates"))
            .collect()
    });
    let index = KeyAlgorithm::ALL
        .iter()
        .position(|a| *a == algorithm)
        .unwrap();
    keys[index].clone_key().into()
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

/// 2027-01-15, inside every certificate here.
fn january() -> SystemTime {
    at(1_800_000_000)
}

#[test]
fn a_generated_key_mints_a_certificate_that_reads_examines_and_verifies() {
    let names: Vec<SubjectAltName> = vec!["widget-01.local".parse().unwrap()];
    for (name, provider) in providers() {
        let algorithms = provider.signature_verification_algorithms.all;
        for algorithm in KeyAlgorithm::ALL {
            let signer = Signer::new(provider.clone(), &key(algorithm)).unwrap();
            let der = mint(&signer, &names).unwrap_or_else(|e| panic!("{name} {algorithm}: {e}"));

            let pem = pem::encode(pem::CERTIFICATE, &der);
            let view = wslib_crypto_x509::inspect_pem(&pem).unwrap();
            assert_eq!(view, inspect(&der).unwrap());
            assert!(key_matches(&provider, &key(algorithm), &view.spki).unwrap());
            let other = if algorithm == KeyAlgorithm::EcP256 {
                KeyAlgorithm::EcP384
            } else {
                KeyAlgorithm::EcP256
            };
            assert!(!key_matches(&provider, &key(other), &view.spki).unwrap());

            let report = examine(view, Some("widget-01.local"), january());
            assert_eq!(report.warnings, [], "{name} {algorithm}");

            let anchor = chain::trust_anchor(&der).unwrap();
            chain::verify(
                &der,
                &[],
                &[anchor],
                Purpose::SERVER_AUTH,
                january(),
                algorithms,
            )
            .unwrap_or_else(|e| panic!("{name} {algorithm}: {e:?}"));
        }
    }
}

struct Chain {
    root: CertificateDer<'static>,
    intermediate: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
}

fn params(signer: &Signer, name: &str, ca: bool) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2028, 1, 1);
    params.serial_number = Some(SerialNumber::from_slice(
        &random_serial(signer.provider()).unwrap(),
    ));
    params.key_identifier_method = KeyIdMethod::PreSpecified(signer.key_identifier().to_vec());
    params.use_authority_key_identifier_extension = true;
    if ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    }
    params
}

fn issue(provider: &Arc<CryptoProvider>, root: KeyAlgorithm, leaf: KeyAlgorithm) -> Chain {
    issue_with(provider, root, leaf, |_| {})
}

fn issue_with(
    provider: &Arc<CryptoProvider>,
    root: KeyAlgorithm,
    leaf: KeyAlgorithm,
    build: impl FnOnce(&mut CertificateParams),
) -> Chain {
    let signer = |algorithm| Signer::new(provider.clone(), &key(algorithm)).unwrap();
    let (root_key, intermediate_key, leaf_key) = (signer(root), signer(root), signer(leaf));

    let root_params = params(&root_key, "Root", true);
    let root_certificate = root_params.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(root_params, root_key);

    let intermediate_params = params(&intermediate_key, "Intermediate", true);
    let intermediate = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .unwrap();
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);

    let mut leaf_params = params(&leaf_key, "widget-01.local", false);
    leaf_params.subject_alt_names = vec![rcgen::SanType::DnsName(
        "widget-01.local".try_into().unwrap(),
    )];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    build(&mut leaf_params);
    let leaf = leaf_params
        .signed_by(&leaf_key, &intermediate_issuer)
        .unwrap();

    Chain {
        root: root_certificate.der().clone(),
        intermediate: intermediate.der().clone(),
        leaf: leaf.der().clone(),
    }
}

#[test]
fn a_chain_through_an_intermediate_verifies_in_both_providers() {
    for (name, provider) in providers() {
        let algorithms = provider.signature_verification_algorithms.all;
        for root in KeyAlgorithm::ALL {
            for leaf in [KeyAlgorithm::EcP256, KeyAlgorithm::Rsa2048] {
                let issued = issue(&provider, root, leaf);
                let anchors = [chain::trust_anchor(&issued.root).unwrap()];
                chain::verify(
                    &issued.leaf,
                    &[issued.intermediate],
                    &anchors,
                    Purpose::SERVER_AUTH,
                    january(),
                    algorithms,
                )
                .unwrap_or_else(|e| panic!("{name} root={root} leaf={leaf}: {e:?}"));
            }
        }
    }
}

#[test]
fn a_chain_that_does_not_hold_says_why() {
    let (_, provider) = &providers()[0];
    let algorithms = provider.signature_verification_algorithms.all;
    let issued = issue(provider, KeyAlgorithm::EcP384, KeyAlgorithm::EcP256);
    let anchors = [chain::trust_anchor(&issued.root).unwrap()];
    let intermediates = [issued.intermediate.clone()];
    let verify = |intermediates: &[CertificateDer<'_>], purpose, at| {
        chain::verify(
            &issued.leaf,
            intermediates,
            &anchors,
            purpose,
            at,
            algorithms,
        )
    };

    assert_eq!(
        verify(&intermediates, Purpose::SERVER_AUTH, at(1_900_000_000)),
        Err(ChainError::Expired)
    );
    assert_eq!(
        verify(&intermediates, Purpose::SERVER_AUTH, at(1_700_000_000)),
        Err(ChainError::NotYetValid)
    );
    assert_eq!(
        verify(&intermediates, Purpose::CODE_SIGNING, january()),
        Err(ChainError::WrongPurpose)
    );
    assert!(matches!(
        verify(&[], Purpose::SERVER_AUTH, january()),
        Err(ChainError::Untrusted(_))
    ));

    let stranger = issue(provider, KeyAlgorithm::EcP256, KeyAlgorithm::EcP256);
    let elsewhere = [chain::trust_anchor(&stranger.root).unwrap()];
    let refused = chain::verify(
        &issued.leaf,
        &intermediates,
        &elsewhere,
        Purpose::SERVER_AUTH,
        january(),
        algorithms,
    );
    assert!(
        matches!(refused, Err(ChainError::Untrusted(_))),
        "{refused:?}"
    );

    let not_a_certificate = CertificateDer::from(vec![0x30, 0x00]);
    assert!(matches!(
        chain::trust_anchor(&not_a_certificate),
        Err(ChainError::Invalid(_))
    ));
}

fn der_sequence(contents: &AlgorithmIdentifier) -> Vec<u8> {
    [&[0x30, contents.len() as u8], contents.as_ref()].concat()
}

#[test]
fn a_signature_verifies_with_the_certificates_key_by_the_algorithm_it_names() {
    let message = b"index.json";
    for (name, provider) in providers() {
        let algorithms = provider.signature_verification_algorithms.all;
        for algorithm in KeyAlgorithm::ALL {
            let signer = Signer::new(provider.clone(), &key(algorithm)).unwrap();
            let spki = inspect(&mint(&signer, &["widget-01".parse().unwrap()]).unwrap())
                .unwrap()
                .spki;
            let named = der_sequence(&match algorithm {
                KeyAlgorithm::EcP256 => alg_id::ECDSA_SHA256,
                KeyAlgorithm::EcP384 => alg_id::ECDSA_SHA384,
                _ => alg_id::RSA_PKCS1_SHA256,
            });
            let mut signed = signer.sign(message).unwrap();
            let verify = |algorithm: &[u8], signed: &[u8]| {
                signature::verify(&spki, algorithm, message, signed, algorithms)
            };

            assert_eq!(verify(&named, &signed), Ok(()), "{name} {algorithm}");
            let other = der_sequence(&alg_id::ED25519);
            assert_eq!(
                verify(&other, &signed),
                Err(SignatureError::NoAlgorithm),
                "{name} {algorithm}"
            );
            *signed.last_mut().unwrap() ^= 1;
            assert_eq!(
                verify(&named, &signed),
                Err(SignatureError::BadSignature),
                "{name} {algorithm}"
            );
            assert!(matches!(
                signature::verify(&spki[1..], &named, message, &signed, algorithms),
                Err(SignatureError::Malformed(_))
            ));
            assert!(matches!(
                verify(&named[2..], &signed),
                Err(SignatureError::Malformed(_))
            ));
        }
    }
}

#[test]
fn a_code_signing_leaf_must_allow_digital_signatures_when_it_limits_its_key() {
    let (_, provider) = &providers()[0];
    let algorithms = provider.signature_verification_algorithms.all;
    let verify = |key_usages: Vec<KeyUsagePurpose>| {
        let issued = issue_with(
            provider,
            KeyAlgorithm::EcP256,
            KeyAlgorithm::EcP256,
            |params| {
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
                params.key_usages = key_usages;
            },
        );
        chain::verify(
            &issued.leaf,
            &[],
            &[chain::trust_anchor(&issued.intermediate).unwrap()],
            Purpose::CODE_SIGNING,
            january(),
            algorithms,
        )
    };
    assert_eq!(verify(vec![]), Ok(()));
    assert_eq!(verify(vec![KeyUsagePurpose::DigitalSignature]), Ok(()));
    assert_eq!(
        verify(vec![KeyUsagePurpose::KeyEncipherment]),
        Err(ChainError::WrongKeyUsage)
    );
}
