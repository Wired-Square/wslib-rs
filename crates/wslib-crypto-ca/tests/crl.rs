mod common;

use std::time::{Duration, SystemTime};

use common::{algorithms, another_key, providers, signer, widget_subject};
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_ca::{
    Authority, BasicConstraints, CrlView, Error, Extension, KeyIdentifierMethod, Profile, Reason,
    Revocation, Serial, Validity, X509_CRL,
};
use wslib_crypto_x509::signature::SignatureError;
use wslib_crypto_x509::{KeyUsage, pem};
use x509_parser::prelude::{CertificateRevocationList, FromDer};

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn serial(n: u64) -> Serial {
    Serial::try_from(n).unwrap()
}

fn ca(signer: Signer) -> Authority {
    let profile = Profile {
        basic_constraints: Some(Extension::critical(BasicConstraints::Authority {
            path_length: None,
        })),
        key_usage: Some(Extension::critical(vec![
            KeyUsage::KeyCertSign,
            KeyUsage::CrlSign,
        ])),
        ..Profile::default()
    };
    let validity = Validity {
        not_before: at(1_800_000_000),
        not_after: at(1_900_000_000),
    };
    Authority::self_signed(
        signer,
        &widget_subject("Spike Root CA").to_der().unwrap(),
        &profile,
        &serial(1),
        validity,
        KeyIdentifierMethod::Sha1,
    )
    .unwrap()
}

fn entries() -> Vec<Revocation> {
    vec![
        Revocation::new(serial(300), at(1_810_000_000)),
        Revocation {
            reason: Some(Reason::KeyCompromise),
            invalid_since: Some(at(1_809_000_000)),
            ..Revocation::new(serial(2), at(1_810_000_100))
        },
        Revocation::new(serial(256), at(1_810_000_200)),
    ]
}

#[test]
fn a_crl_reads_back_and_verifies_on_every_provider_and_ca_key() {
    for (name, provider) in providers() {
        for algorithm in KeyAlgorithm::ALL {
            let ca = ca(signer(&provider, algorithm));
            let der = ca
                .revocation_list(7, at(1_810_000_000), at(1_810_864_000), &entries())
                .unwrap_or_else(|e| panic!("{name} {algorithm}: {e}"));
            let view = CrlView::from_der(&der).unwrap();
            view.verify(
                ca.certificate(),
                provider.signature_verification_algorithms.all,
            )
            .unwrap_or_else(|e| panic!("{name} {algorithm}: {e}"));

            let mut sorted = entries();
            sorted.sort_by(|a, b| a.serial.cmp(&b.serial));
            assert_eq!(view.revoked, sorted, "entries in serial order");
            assert_eq!(view.number, Some(7));
            assert_eq!(view.this_update, at(1_810_000_000));
            assert_eq!(view.next_update, Some(at(1_810_864_000)));
            assert_eq!(
                view.authority_key_identifier.as_deref(),
                Some(ca.key_identifier())
            );
            assert_eq!(
                view.issuer,
                widget_subject("Spike Root CA").to_der().unwrap()
            );
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_extensions_are_pinned() {
    let (_, provider) = &providers()[0];
    let ca = ca(signer(provider, KeyAlgorithm::EcP256));
    let der = ca
        .revocation_list(7, at(1_810_000_000), at(1_810_864_000), &entries())
        .unwrap();
    let (_, crl) = CertificateRevocationList::from_der(&der).unwrap();
    let listed = |extensions: &[x509_parser::extensions::X509Extension<'_>]| {
        extensions
            .iter()
            .map(|e| (e.oid.to_id_string(), e.critical, hex(e.value)))
            .collect::<Vec<_>>()
    };
    assert_eq!(crl.version().map(|v| v.0), Some(1));
    assert_eq!(
        listed(crl.extensions()),
        [
            (
                "2.5.29.35".to_string(),
                false,
                format!("30168014{}", hex(ca.key_identifier()))
            ),
            ("2.5.29.20".to_string(), false, "020107".to_string()),
        ]
    );
    let entries: Vec<_> = crl.iter_revoked_certificates().collect();
    assert_eq!(
        listed(entries[0].extensions()),
        [
            ("2.5.29.21".to_string(), false, "0a0101".to_string()),
            // GeneralizedTime 2027-04-29 12:00:00 UTC
            (
                "2.5.29.24".to_string(),
                false,
                hex(b"\x18\x0f20270429120000Z")
            ),
        ]
    );
    assert_eq!(listed(entries[1].extensions()), []);
}

#[test]
fn an_empty_crl_has_no_entries() {
    let (_, provider) = &providers()[0];
    let ca = ca(signer(provider, KeyAlgorithm::EcP256));
    let der = ca
        .revocation_list(0, at(1_810_000_000), at(1_810_864_000), &[])
        .unwrap();
    let view = CrlView::from_pem(&pem::encode(X509_CRL, &der)).unwrap();
    assert_eq!(view.revoked, []);
    assert_eq!(view.number, Some(0));
    view.verify(ca.certificate(), algorithms()).unwrap();
}

#[test]
fn a_crl_verifies_only_against_its_issuer() {
    let (_, provider) = &providers()[0];
    let ca = ca(signer(provider, KeyAlgorithm::EcP256));
    let der = ca
        .revocation_list(7, at(1_810_000_000), at(1_810_864_000), &entries())
        .unwrap();

    let impostor = ca_with_other_name(Signer::new(provider.clone(), &another_key()).unwrap());
    assert!(matches!(
        CrlView::from_der(&der)
            .unwrap()
            .verify(impostor.certificate(), algorithms()),
        Err(Error::IssuerMismatch)
    ));

    let same_name = self::ca(Signer::new(provider.clone(), &another_key()).unwrap());
    assert!(matches!(
        CrlView::from_der(&der)
            .unwrap()
            .verify(same_name.certificate(), algorithms()),
        Err(Error::Signature(SignatureError::BadSignature))
    ));
}

fn ca_with_other_name(signer: Signer) -> Authority {
    let profile = Profile {
        basic_constraints: Some(Extension::critical(BasicConstraints::Authority {
            path_length: Some(0),
        })),
        ..Profile::default()
    };
    Authority::self_signed(
        signer,
        &wslib_crypto_ca::Subject::new("Impostor").to_der().unwrap(),
        &profile,
        &serial(1),
        Validity {
            not_before: at(1_800_000_000),
            not_after: at(1_900_000_000),
        },
        KeyIdentifierMethod::Sha256,
    )
    .unwrap()
}

#[test]
fn an_openssl_crl_reads_and_verifies() {
    let issuer = &pem::certificates(include_str!("data/openssl-ca.pem")).unwrap()[0];
    let view = CrlView::from_pem(include_str!("data/openssl.crl")).unwrap();
    view.verify(issuer, algorithms()).unwrap();
    assert_eq!(view.number, Some(4096));
    assert_eq!(
        view.authority_key_identifier.as_deref().map(hex).as_deref(),
        Some("8931c40c138f463602c2bff5e8bf10c0eb6c147d")
    );
    let read: Vec<_> = view
        .revoked
        .iter()
        .map(|entry| (entry.serial.as_bytes().to_vec(), entry.reason))
        .collect();
    assert_eq!(
        read,
        [
            (vec![0x03], None),
            (vec![0x0a], Some(Reason::KeyCompromise))
        ]
    );
}

#[test]
fn what_is_not_a_crl_is_malformed() {
    assert!(matches!(
        CrlView::from_der(b"\x30\x00"),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        CrlView::from_pem(include_str!("data/openssl-ca.pem")),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn a_crl_may_end_as_it_begins_but_not_before() {
    let (_, provider) = &providers()[0];
    let ca = ca(signer(provider, KeyAlgorithm::EcP256));
    let der = ca
        .revocation_list(1, at(1_810_000_000), at(1_810_000_000), &entries())
        .unwrap();
    let view = CrlView::from_der(&der).unwrap();
    view.verify(ca.certificate(), algorithms()).unwrap();
    assert_eq!(view.next_update, Some(view.this_update));
    assert!(matches!(
        ca.revocation_list(1, at(1_810_000_000), at(1_809_999_999), &[]),
        Err(Error::CrlValidity)
    ));
}

#[test]
fn a_next_update_from_2050_is_a_generalized_time() {
    let (_, provider) = &providers()[0];
    let ca = ca(signer(provider, KeyAlgorithm::EcP256));
    let next = at(2_556_144_000);
    let der = ca.revocation_list(1, at(1_810_000_000), next, &[]).unwrap();
    assert!(
        der.windows(17).any(|w| w == b"\x18\x0f20510101000000Z"),
        "2051-01-01 as GeneralizedTime"
    );
    let view = CrlView::from_der(&der).unwrap();
    assert_eq!(view.next_update, Some(next));
    view.verify(ca.certificate(), algorithms()).unwrap();
}

#[test]
fn the_issuer_reads_as_text() {
    let (_, provider) = &providers()[0];
    let ca = ca(signer(provider, KeyAlgorithm::EcP256));
    let der = ca
        .revocation_list(1, at(1_810_000_000), at(1_810_864_000), &[])
        .unwrap();
    assert_eq!(
        CrlView::from_der(&der).unwrap().issuer_text,
        "EMAIL=ops@example.com,OU=Ops,O=Wïdget Co,L=Melbourne,ST=Victoria,C=AU,CN=Spike Root CA"
    );
}
