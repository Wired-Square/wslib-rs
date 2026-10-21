use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyIdMethod, KeyUsagePurpose, SerialNumber,
};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use wslib_crypto::{KeyAlgorithm, Signer, key_matches, random_serial};
use wslib_crypto_x509::chain::{self, ChainError, Purpose};
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
