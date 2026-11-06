mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use common::{algorithms, another_key, names, providers, signer, widget_subject};
use rustls_pki_types::CertificateDer;
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_ca::{
    Authority, BasicConstraints, Csr, Error, Extension, KeyIdentifierMethod, Profile, SanPolicy,
    Serial, Subject, Validity, build_csr,
};
use wslib_crypto_x509::chain::{self, Purpose};
use wslib_crypto_x509::{ExtendedKeyUsage, KeyUsage, NameConstraints, NameSubtree, inspect, pem};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

const CRL_URL: &str = "http://crl.example.com/ca.crl";
const CA_URL: &str = "http://ca.example.com/ca.crt";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

/// 2027-01-15 to 2028-01-15.
fn a_year() -> Validity {
    Validity {
        not_before: at(1_800_000_000),
        not_after: at(1_831_536_000),
    }
}

fn serial(n: u64) -> Serial {
    Serial::try_from(n).unwrap()
}

fn ca_profile() -> Profile {
    Profile {
        basic_constraints: Some(Extension::critical(BasicConstraints::Authority {
            path_length: None,
        })),
        key_usage: Some(Extension::critical(vec![
            KeyUsage::KeyCertSign,
            KeyUsage::CrlSign,
        ])),
        ..Profile::default()
    }
}

/// The leaf profiles of an OpenSSL-built CA, as a caller would build them.
fn leaf_profile(kind: &str, rsa: bool) -> Profile {
    let signature = |encipher: bool| {
        let mut usages = vec![KeyUsage::DigitalSignature];
        if encipher {
            usages.push(KeyUsage::KeyEncipherment);
        }
        Some(Extension::critical(usages))
    };
    let base = Profile {
        basic_constraints: Some(Extension::non_critical(BasicConstraints::EndEntity)),
        ..Profile::default()
    };
    match kind {
        "device" => Profile {
            key_usage: signature(rsa),
            extended_key_usage: Some(Extension::non_critical(vec![ExtendedKeyUsage::ClientAuth])),
            names: SanPolicy::CommonNameAndRequested,
            ..base
        },
        "vpn-client" => Profile {
            key_usage: signature(false),
            extended_key_usage: Some(Extension::critical(vec![ExtendedKeyUsage::ClientAuth])),
            names: SanPolicy::Requested,
            ..base
        },
        "vpn-server" => Profile {
            key_usage: signature(rsa),
            extended_key_usage: Some(Extension::critical(vec![ExtendedKeyUsage::ServerAuth])),
            ..base
        },
        "code-signing" => Profile {
            key_usage: signature(false),
            extended_key_usage: Some(Extension::critical(vec![ExtendedKeyUsage::CodeSigning])),
            ..base
        },
        "web-server" => Profile {
            key_usage: signature(rsa),
            extended_key_usage: Some(Extension::non_critical(vec![
                ExtendedKeyUsage::ServerAuth,
                ExtendedKeyUsage::ClientAuth,
            ])),
            names: SanPolicy::CommonNameAndRequested,
            crl_distribution_points: vec![CRL_URL.into()],
            ca_issuers: vec![CA_URL.into()],
            ..base
        },
        _ => unreachable!(),
    }
}

fn root(signer: Signer) -> Authority {
    Authority::self_signed(
        signer,
        &widget_subject("Spike Root CA").to_der().unwrap(),
        &ca_profile(),
        &serial(1),
        a_year(),
        KeyIdentifierMethod::Sha1,
    )
    .unwrap()
}

/// A request like the one OpenSSL was given when the expected extensions below were recorded.
fn request(signer: &Signer) -> Csr {
    let requested = names(&[
        "www.example.com",
        "10.0.0.5",
        "ops@example.com",
        "spiffe://prod/web",
        "host.example.com",
    ]);
    let der = build_csr(signer, &widget_subject("host.example.com"), &requested).unwrap();
    Csr::from_der(&der, algorithms()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Each extension's OID, criticality and DER value in hex, in the certificate's order.
fn extensions(der: &[u8]) -> Vec<(String, bool, String)> {
    let (_, certificate) = X509Certificate::from_der(der).unwrap();
    certificate
        .extensions()
        .iter()
        .map(|e| (e.oid.to_id_string(), e.critical, hex(e.value)))
        .collect()
}

fn ext(oid: &str, critical: bool, value: &str) -> (String, bool, String) {
    (oid.to_string(), critical, value.to_string())
}

/// SKI and AKI as OpenSSL writes them, keyid only.
fn key_identifiers(subject: &[u8], authority: &[u8]) -> Vec<(String, bool, String)> {
    vec![
        ext("2.5.29.14", false, &format!("0414{}", hex(subject))),
        ext("2.5.29.35", false, &format!("30168014{}", hex(authority))),
    ]
}

// Recorded from `openssl x509` output of the OpenSSL-built profiles for `request`'s names.
const SAN_WITH_COMMON_NAME: &str = "304d8210686f73742e6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d87040a000005810f6f7073406578616d706c652e636f6d86117370696666653a2f2f70726f642f776562";
const SAN_REQUESTED: &str = "304d820f7777772e6578616d706c652e636f6d87040a000005810f6f7073406578616d706c652e636f6d86117370696666653a2f2f70726f642f7765628210686f73742e6578616d706c652e636f6d";
const CDP: &str = "30253023a021a01f861d687474703a2f2f63726c2e6578616d706c652e636f6d2f63612e63726c";
const AIA: &str =
    "302a302806082b06010505073002861c687474703a2f2f63612e6578616d706c652e636f6d2f63612e637274";

fn expected(kind: &str, rsa: bool) -> Vec<(String, bool, String)> {
    let end_entity = ext("2.5.29.19", false, "3000");
    let signature = ext("2.5.29.15", true, "03020780");
    let signature_or_encipher = ext("2.5.29.15", true, if rsa { "030205a0" } else { "03020780" });
    let eku = |critical, value| ext("2.5.29.37", critical, value);
    let san = |value| ext("2.5.29.17", false, value);
    match kind {
        "device" => vec![
            end_entity,
            signature_or_encipher,
            eku(false, "300a06082b06010505070302"),
            san(SAN_WITH_COMMON_NAME),
        ],
        "vpn-client" => vec![
            end_entity,
            signature,
            eku(true, "300a06082b06010505070302"),
            san(SAN_REQUESTED),
        ],
        "vpn-server" => vec![
            end_entity,
            signature_or_encipher,
            eku(true, "300a06082b06010505070301"),
        ],
        "code-signing" => vec![end_entity, signature, eku(true, "300a06082b06010505070303")],
        "web-server" => vec![
            end_entity,
            signature_or_encipher,
            eku(false, "301406082b0601050507030106082b06010505070302"),
            san(SAN_WITH_COMMON_NAME),
            ext("2.5.29.31", false, CDP),
            ext("1.3.6.1.5.5.7.1.1", false, AIA),
        ],
        _ => unreachable!(),
    }
}

const KINDS: [&str; 5] = [
    "device",
    "vpn-client",
    "vpn-server",
    "code-signing",
    "web-server",
];

#[test]
fn each_profile_writes_the_extensions_openssl_wrote() {
    let (_, provider) = &providers()[0];
    let ca = root(signer(provider, KeyAlgorithm::EcP384));
    for leaf in [KeyAlgorithm::EcP256, KeyAlgorithm::Rsa2048] {
        let rsa = leaf == KeyAlgorithm::Rsa2048;
        let csr = request(&signer(provider, leaf));
        let ski = KeyIdentifierMethod::Sha1.of(csr.spki()).unwrap();
        for kind in KINDS {
            let der = ca
                .issue(&csr, &leaf_profile(kind, rsa), &serial(100), a_year())
                .unwrap();
            let mut want = key_identifiers(&ski, ca.key_identifier());
            want.extend(expected(kind, rsa));
            assert_eq!(extensions(&der), want, "{kind} {leaf}");
        }
    }
}

#[test]
fn a_self_signed_ca_writes_the_extensions_openssl_wrote() {
    let (_, provider) = &providers()[0];
    let ca = root(signer(provider, KeyAlgorithm::Rsa2048));
    let ski = KeyIdentifierMethod::Sha1.of(ca.signer().spki()).unwrap();
    assert_eq!(ca.key_identifier(), ski);
    let mut want = key_identifiers(&ski, &ski);
    want.extend([
        ext("2.5.29.19", true, "30030101ff"),
        ext("2.5.29.15", true, "03020106"),
    ]);
    assert_eq!(extensions(ca.certificate()), want);
}

#[test]
fn an_issued_certificate_chains_on_every_provider_and_ca_key() {
    for (name, provider) in providers() {
        for algorithm in KeyAlgorithm::ALL {
            let ca = root(signer(&provider, algorithm));
            let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
            let leaf = ca
                .issue(
                    &csr,
                    &leaf_profile("web-server", false),
                    &serial(7),
                    a_year(),
                )
                .unwrap_or_else(|e| panic!("{name} {algorithm}: {e}"));
            let anchors = [chain::trust_anchor(ca.certificate()).unwrap()];
            chain::verify(
                &leaf,
                &[],
                &anchors,
                Purpose::SERVER_AUTH,
                at(1_810_000_000),
                provider.signature_verification_algorithms.all,
            )
            .unwrap_or_else(|e| panic!("{name} {algorithm}: {e}"));

            let (_, issued) = X509Certificate::from_der(&leaf).unwrap();
            let (_, authority) = X509Certificate::from_der(ca.certificate()).unwrap();
            assert_eq!(issued.issuer().as_raw(), authority.subject().as_raw());
            assert_eq!(issued.subject().as_raw(), csr.subject());
            assert_eq!(issued.public_key().raw, csr.spki());
            assert_eq!(issued.raw_serial(), [7]);
            assert_eq!(issued.validity().not_before.timestamp(), 1_800_000_000);
            assert_eq!(issued.validity().not_after.timestamp(), 1_831_536_000);
        }
    }
}

/// `DC=com, DC=example, OU=Alpha + CN=Odd CA, OU=Beta`: a repeated type, a
/// multi-valued RDN and a BMPString, none of which rcgen's names can hold.
fn odd_name() -> Vec<u8> {
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        [&[tag, content.len() as u8][..], content].concat()
    }
    let attribute =
        |oid: &[u8], tag, value: &[u8]| tlv(0x30, &[tlv(0x06, oid), tlv(tag, value)].concat());
    const DC: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];
    const OU: &[u8] = &[0x55, 0x04, 0x0b];
    const CN: &[u8] = &[0x55, 0x04, 0x03];
    let rdns = [
        tlv(0x31, &attribute(DC, 0x16, b"com")),
        tlv(0x31, &attribute(DC, 0x16, b"example")),
        tlv(
            0x31,
            &[
                attribute(OU, 0x0c, b"Alpha"),
                attribute(CN, 0x1e, &[0, b'O', 0, b'd', 0, b'd']),
            ]
            .concat(),
        ),
        tlv(0x31, &attribute(OU, 0x13, b"Beta")),
    ];
    tlv(0x30, &rdns.concat())
}

#[test]
fn any_issuer_name_is_copied_byte_for_byte() {
    for (name, provider) in providers() {
        let ca = Authority::self_signed(
            signer(&provider, KeyAlgorithm::EcP256),
            &odd_name(),
            &ca_profile(),
            &serial(1),
            a_year(),
            KeyIdentifierMethod::Sha256,
        )
        .unwrap();
        let (_, root) = X509Certificate::from_der(ca.certificate()).unwrap();
        assert_eq!(root.subject().as_raw(), odd_name());
        assert_eq!(root.issuer().as_raw(), odd_name());

        let reopened = Authority::new(
            ca.certificate().clone(),
            signer(&provider, KeyAlgorithm::EcP256),
            KeyIdentifierMethod::Sha1,
        )
        .unwrap();
        let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
        let leaf = reopened
            .issue(&csr, &leaf_profile("device", false), &serial(2), a_year())
            .unwrap();
        let (_, issued) = X509Certificate::from_der(&leaf).unwrap();
        assert_eq!(issued.issuer().as_raw(), odd_name(), "{name}");
        let anchors = [chain::trust_anchor(ca.certificate()).unwrap()];
        chain::verify(
            &leaf,
            &[],
            &anchors,
            Purpose::CLIENT_AUTH,
            at(1_810_000_000),
            provider.signature_verification_algorithms.all,
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn an_openssl_csrs_subject_and_odd_sized_key_are_copied_byte_for_byte() {
    let (_, provider) = &providers()[0];
    let ca = root(signer(provider, KeyAlgorithm::EcP256));
    for pem in [common::OPENSSL_P256_CSR, common::OPENSSL_RSA3072_CSR] {
        let csr = Csr::from_pem(pem, algorithms()).unwrap();
        let profile = leaf_profile("vpn-server", csr.has_rsa_key());
        let leaf = ca.issue(&csr, &profile, &serial(3), a_year()).unwrap();
        let (_, issued) = X509Certificate::from_der(&leaf).unwrap();
        assert_eq!(issued.subject().as_raw(), csr.subject());
        assert_eq!(issued.public_key().raw, csr.spki());
    }
}

#[test]
fn a_chosen_subject_replaces_the_requests() {
    let (_, provider) = &providers()[0];
    let ca = root(signer(provider, KeyAlgorithm::EcP256));
    let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
    let chosen = Subject::new("www.example.com").to_der().unwrap();
    let leaf = ca
        .issue_with_subject(
            &csr,
            &chosen,
            &leaf_profile("web-server", false),
            &serial(2),
            a_year(),
        )
        .unwrap();
    let (_, issued) = X509Certificate::from_der(&leaf).unwrap();
    assert_ne!(csr.subject(), chosen);
    assert_eq!(issued.subject().as_raw(), chosen);
    assert_eq!(issued.public_key().raw, csr.spki());
}

/// The DNS names of a leaf issued for `subject` to a request for `csr.example.com` and `www.example.com`, and whether they are critical.
fn names_issued_for(subject: &[u8], kind: &str) -> (Vec<String>, bool) {
    let (_, provider) = &providers()[0];
    let ca = root(signer(provider, KeyAlgorithm::EcP256));
    let key = Signer::new(provider.clone(), &another_key()).unwrap();
    let csr = csr_for(&key, "csr.example.com", &["www.example.com"]);
    let leaf = ca
        .issue_with_subject(
            &csr,
            subject,
            &leaf_profile(kind, false),
            &serial(2),
            a_year(),
        )
        .unwrap();
    let (_, issued) = X509Certificate::from_der(&leaf).unwrap();
    let san = issued.subject_alternative_name().unwrap().unwrap();
    let names = san
        .value
        .general_names
        .iter()
        .map(|name| match name {
            GeneralName::DNSName(dns) => dns.to_string(),
            other => panic!("{other:?}"),
        })
        .collect();
    (names, san.critical)
}

#[test]
fn an_empty_chosen_subject_makes_the_names_critical() {
    let www = || vec!["www.example.com".to_string()];
    assert_eq!(names_issued_for(&[0x30, 0], "vpn-client"), (www(), true));
    let chosen = Subject::new("chosen.example.com").to_der().unwrap();
    assert_eq!(names_issued_for(&chosen, "vpn-client"), (www(), false));
}

#[test]
fn a_chosen_common_name_leads_the_names_as_a_requested_one_would() {
    let chosen = Subject::new("chosen.example.com").to_der().unwrap();
    assert_eq!(
        names_issued_for(&chosen, "device"),
        (
            vec!["chosen.example.com".into(), "www.example.com".into()],
            false
        )
    );
    assert_eq!(
        names_issued_for(&[0x30, 0], "device"),
        (vec!["www.example.com".into()], true)
    );
}

#[test]
fn a_chosen_subject_must_be_a_der_name() {
    let (_, provider) = &providers()[0];
    let ca = root(signer(provider, KeyAlgorithm::EcP256));
    let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
    for subject in [&[][..], &[0x30, 1], &[0x30, 0, 0], &[0x04, 0]] {
        assert!(
            matches!(
                ca.issue_with_subject(&csr, subject, &Profile::default(), &serial(2), a_year()),
                Err(Error::Malformed(_))
            ),
            "{subject:02x?}"
        );
    }
}

#[test]
fn the_sha1_method_is_openssls() {
    let ca = &pem::certificates(include_str!("data/openssl-ca.pem")).unwrap()[0];
    let (_, certificate) = X509Certificate::from_der(ca).unwrap();
    let ski = KeyIdentifierMethod::Sha1
        .of(certificate.public_key().raw)
        .unwrap();
    assert_eq!(hex(&ski), "8931c40c138f463602c2bff5e8bf10c0eb6c147d");
}

#[test]
fn the_sha256_method_is_wslib_cryptos() {
    let (_, provider) = &providers()[0];
    let signer = signer(provider, KeyAlgorithm::EcP256);
    assert_eq!(
        KeyIdentifierMethod::Sha256.of(signer.spki()).unwrap(),
        signer.key_identifier()
    );
}

#[test]
fn an_authority_needs_its_own_key_and_ca_true() {
    let (_, provider) = &providers()[0];
    let ca = &pem::certificates(include_str!("data/openssl-ca.pem")).unwrap()[0];
    assert!(matches!(
        Authority::new(
            ca.clone(),
            signer(provider, KeyAlgorithm::Rsa2048),
            KeyIdentifierMethod::Sha1
        ),
        Err(Error::KeyMismatch)
    ));

    let root = root(signer(provider, KeyAlgorithm::EcP256));
    let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
    let leaf = root
        .issue(&csr, &leaf_profile("device", false), &serial(9), a_year())
        .unwrap();
    assert!(matches!(
        Authority::new(
            leaf,
            Signer::new(provider.clone(), &another_key()).unwrap(),
            KeyIdentifierMethod::Sha1
        ),
        Err(Error::NotAnAuthority)
    ));
    assert!(matches!(
        Authority::self_signed(
            signer(provider, KeyAlgorithm::EcP256),
            &Subject::new("x").to_der().unwrap(),
            &leaf_profile("device", false),
            &serial(1),
            a_year(),
            KeyIdentifierMethod::Sha1,
        ),
        Err(Error::NotAnAuthority)
    ));
}

/// An authority whose certificate has no subject key identifier, made with rcgen directly.
fn without_key_identifier(signer: Signer) -> Authority {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut ca_true =
        rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x30, 3, 1, 1, 0xff]);
    ca_true.set_criticality(true);
    params.custom_extensions = vec![ca_true];
    params.serial_number = Some(rcgen::SerialNumber::from(5u64));
    let der = params.self_signed(&signer).unwrap().der().clone();
    let (_, parsed) = X509Certificate::from_der(&der).unwrap();
    assert!(
        parsed
            .iter_extensions()
            .all(|e| e.oid.to_id_string() != "2.5.29.14")
    );
    drop(parsed);
    Authority::new(der, signer, KeyIdentifierMethod::Sha256).unwrap()
}

#[test]
fn a_ca_without_a_key_identifier_gets_one_by_the_method() {
    let (_, provider) = &providers()[0];
    let ca = without_key_identifier(signer(provider, KeyAlgorithm::EcP256));
    assert_eq!(ca.key_identifier(), ca.signer().key_identifier());
}

#[test]
fn re_signing_keeps_the_subject_key_and_identifier() {
    let (_, provider) = &providers()[0];
    let mut ca = root(signer(provider, KeyAlgorithm::EcP256));
    let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
    let leaf = ca
        .issue(
            &csr,
            &leaf_profile("web-server", false),
            &serial(10),
            a_year(),
        )
        .unwrap();
    let before = ca.certificate().clone();
    let kept = ca.serial().clone();
    let later = Validity {
        not_before: at(1_830_000_000),
        not_after: at(1_900_000_000),
    };
    let after = ca.re_sign(&ca_profile(), &kept, later).unwrap().clone();

    let (_, old) = X509Certificate::from_der(&before).unwrap();
    let (_, new) = X509Certificate::from_der(&after).unwrap();
    assert_eq!(new.subject().as_raw(), old.subject().as_raw());
    assert_eq!(new.public_key().raw, old.public_key().raw);
    assert_eq!(new.raw_serial(), old.raw_serial());
    assert_eq!(extensions(&after), extensions(&before));
    assert_eq!(new.validity().not_after.timestamp(), 1_900_000_000);

    let anchors = [chain::trust_anchor(&after).unwrap()];
    chain::verify(
        &leaf,
        &[],
        &anchors,
        Purpose::SERVER_AUTH,
        at(1_830_000_100),
        algorithms(),
    )
    .expect("a leaf issued before the re-sign chains to the new certificate");
}

#[test]
fn only_a_self_signed_ca_is_re_signed() {
    let (_, provider) = &providers()[0];
    let root = root(signer(provider, KeyAlgorithm::EcP256));
    let intermediate_key = Signer::new(provider.clone(), &another_key()).unwrap();
    let csr = request(&intermediate_key);
    let issued: CertificateDer<'static> = root
        .issue(&csr, &ca_profile(), &serial(2), a_year())
        .unwrap();
    let mut intermediate =
        Authority::new(issued, intermediate_key, KeyIdentifierMethod::Sha1).unwrap();
    assert!(matches!(
        intermediate.re_sign(&ca_profile(), &serial(3), a_year()),
        Err(Error::NotSelfSigned)
    ));
}

#[test]
fn what_cannot_be_issued_is_refused() {
    let (_, provider) = &providers()[0];
    let ca = root(signer(provider, KeyAlgorithm::EcP256));
    let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
    let backwards = Validity {
        not_before: a_year().not_after,
        not_after: a_year().not_before,
    };
    assert!(matches!(
        ca.issue(&csr, &Profile::default(), &serial(1), backwards),
        Err(Error::Validity)
    ));
    let empty = Profile {
        key_usage: Some(Extension::critical(vec![])),
        ..Profile::default()
    };
    assert!(matches!(
        ca.issue(&csr, &empty, &serial(1), a_year()),
        Err(Error::EmptyExtension("key usage"))
    ));
    let bad_url = Profile {
        crl_distribution_points: vec!["http://bücher.example/ca.crl".into()],
        ..Profile::default()
    };
    assert!(matches!(
        ca.issue(&csr, &bad_url, &serial(1), a_year()),
        Err(Error::Name { .. })
    ));
}

#[test]
fn a_serial_is_positive_and_fits_twenty_octets() {
    assert!(matches!(Serial::try_from(0u64), Err(Error::Serial)));
    assert!(matches!(
        Serial::try_from(&[0u8, 0][..]),
        Err(Error::Serial)
    ));
    assert_eq!(Serial::try_from(&[0u8, 0, 5][..]).unwrap().as_bytes(), [5]);
    assert!(Serial::try_from(&[0x7f; 20][..]).is_ok());
    assert!(matches!(
        Serial::try_from(&[0x80; 20][..]),
        Err(Error::Serial)
    ));
    assert!(Serial::try_from(&[0x80; 19][..]).is_ok());
    let (_, provider) = &providers()[0];
    let random = Serial::random(provider).unwrap();
    assert_eq!(random.as_bytes().len(), 16);
    assert!(serial(255) < serial(256));
}

#[test]
fn a_serial_reads_and_writes_as_decimal() {
    for decimal in ["1", "255", "256", "18446744073709551616"] {
        assert_eq!(decimal.parse::<Serial>().unwrap().to_string(), decimal);
    }
    assert_eq!("00042".parse::<Serial>().unwrap(), serial(42));
    assert_eq!("256".parse::<Serial>().unwrap().as_bytes(), [1, 0]);
    let largest = [&[0x7f][..], &[0xff; 19]].concat();
    let text = Serial::try_from(largest.as_slice()).unwrap().to_string();
    assert_eq!(text.parse::<Serial>().unwrap().as_bytes(), largest);
    assert_eq!(text, "730750818665451459101842416358141509827966271487");
    assert!(matches!(
        "730750818665451459101842416358141509827966271488".parse::<Serial>(),
        Err(Error::Serial)
    ));
    for not_decimal in ["", "-1", "+1", "12a", " 1", "0x10"] {
        assert!(
            matches!(not_decimal.parse::<Serial>(), Err(Error::NotDecimal(s)) if s == not_decimal),
            "{not_decimal:?}"
        );
    }
    for out_of_range in ["0", &"9".repeat(60)] {
        assert!(
            matches!(out_of_range.parse::<Serial>(), Err(Error::Serial)),
            "{out_of_range:?}"
        );
    }
}

#[test]
fn a_serial_from_an_i64_is_positive() {
    assert_eq!(Serial::try_from(5i64).unwrap(), serial(5));
    assert!(matches!(Serial::try_from(-5i64), Err(Error::Serial)));
    assert!(matches!(Serial::try_from(0i64), Err(Error::Serial)));
}

fn constraints(permitted: &[&str], excluded: &[&str]) -> NameConstraints {
    let subtrees = |list: &[&str]| list.iter().map(|s| s.parse().unwrap()).collect();
    NameConstraints {
        permitted: subtrees(permitted),
        excluded: subtrees(excluded),
    }
}

/// The subtrees `tests/data/openssl-name-constrained-ca.pem` was made with.
fn openssl_constraints() -> NameConstraints {
    constraints(
        &[
            "example.com",
            ".example.net",
            "10.20.0.0/16",
            "fd00:20::/32",
        ],
        &["secret.example.com", "0.0.0.0/0", "::/0"],
    )
}

fn constrained_ca_profile(constraints: NameConstraints) -> Profile {
    Profile {
        basic_constraints: Some(Extension::critical(BasicConstraints::Authority {
            path_length: Some(0),
        })),
        name_constraints: Some(Extension::critical(constraints)),
        ..ca_profile()
    }
}

fn csr_for(key: &Signer, common_name: &str, names: &[&str]) -> Csr {
    let der = build_csr(key, &Subject::new(common_name), &common::names(names)).unwrap();
    Csr::from_der(&der, algorithms()).unwrap()
}

fn constrained_ca(root: &Authority, constraints: NameConstraints) -> Authority {
    let (_, provider) = &providers()[0];
    let key = Signer::new(provider.clone(), &another_key()).unwrap();
    let csr = csr_for(&key, "ACME Broker CA", &[]);
    let issued = root
        .issue(
            &csr,
            &constrained_ca_profile(constraints),
            &serial(2),
            a_year(),
        )
        .unwrap();
    Authority::new(issued, key, KeyIdentifierMethod::Sha1).unwrap()
}

const OPENSSL_NAME_CONSTRAINED_CA: &str = include_str!("data/openssl-name-constrained-ca.pem");

#[test]
fn name_constraints_are_written_as_openssl_wrote_them() {
    let (_, provider) = &providers()[0];
    let root = root(signer(provider, KeyAlgorithm::EcP256));
    let ours = Profile {
        crl_distribution_points: vec![CRL_URL.into()],
        ca_issuers: vec![CA_URL.into()],
        ..constrained_ca_profile(openssl_constraints())
    };
    let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
    let issued = root.issue(&csr, &ours, &serial(2), a_year()).unwrap();
    let openssl = &pem::certificates(OPENSSL_NAME_CONSTRAINED_CA).unwrap()[0];
    assert_eq!(extensions(&issued)[2..], extensions(openssl)[2..]);
}

#[test]
fn name_constraints_read_back_as_they_were_issued() {
    let (_, provider) = &providers()[0];
    let root = root(signer(provider, KeyAlgorithm::EcP256));
    let ca = constrained_ca(&root, openssl_constraints());
    for der in [
        ca.certificate().to_vec(),
        pem::certificates(OPENSSL_NAME_CONSTRAINED_CA).unwrap()[0].to_vec(),
    ] {
        assert_eq!(
            inspect(&der).unwrap().name_constraints,
            Some(openssl_constraints())
        );
    }
}

#[test]
fn name_constraints_must_say_something_issuable() {
    let (_, provider) = &providers()[0];
    let root = root(signer(provider, KeyAlgorithm::EcP256));
    let csr = request(&Signer::new(provider.clone(), &another_key()).unwrap());
    let issue = |constraints| {
        root.issue(
            &csr,
            &constrained_ca_profile(constraints),
            &serial(2),
            a_year(),
        )
    };
    assert!(matches!(
        issue(NameConstraints::default()),
        Err(Error::EmptyExtension("name constraints"))
    ));
    let email = NameConstraints {
        permitted: vec![NameSubtree::Other(vec![0x30, 3, 0x81, 1, b'a'])],
        excluded: vec![],
    };
    assert!(matches!(issue(email), Err(Error::Name { .. })));
}

/// `openssl verify`'s verdict on a leaf with `names` under a CA constrained to `constraints`.
fn openssl_verifies(constraints: &NameConstraints, names: &[&str]) -> Result<(), String> {
    let (_, provider) = &providers()[0];
    let root = root(signer(provider, KeyAlgorithm::EcP256));
    let ca = constrained_ca(&root, constraints.clone());
    let csr = csr_for(
        &signer(provider, KeyAlgorithm::EcP384),
        "Leaf Device",
        names,
    );
    let leaf_profile = Profile {
        basic_constraints: Some(Extension::non_critical(BasicConstraints::EndEntity)),
        names: SanPolicy::Requested,
        ..Profile::default()
    };
    let leaf = ca.issue(&csr, &leaf_profile, &serial(3), a_year()).unwrap();

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("name-constraints");
    fs::create_dir_all(&dir).unwrap();
    for (file, der) in [
        ("root.pem", root.certificate().as_ref()),
        ("ca.pem", ca.certificate().as_ref()),
        ("leaf.pem", leaf.as_ref()),
    ] {
        fs::write(dir.join(file), pem::encode(pem::CERTIFICATE, der)).unwrap();
    }
    let out = Command::new("openssl")
        .current_dir(&dir)
        .args(["verify", "-attime", "1810000000", "-CAfile", "root.pem"])
        .args(["-untrusted", "ca.pem", "leaf.pem"])
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).into_owned();
    if out.status.success() && said.trim_end().ends_with("leaf.pem: OK") {
        Ok(())
    } else {
        Err(said)
    }
}

#[test]
fn openssl_refuses_a_leaf_outside_the_subtrees_and_accepts_one_inside() {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("skipped: no openssl on the PATH");
        return;
    }
    let broker = constraints(&["example.com", "10.20.0.0/16"], &["secret.example.com"]);
    let no_addresses = constraints(&["example.com"], &["0.0.0.0/0", "::/0"]);
    for (constraints, names, holds) in [
        (&broker, &["www.example.com"][..], true),
        (&broker, &["www.example.com", "10.20.1.5"], true),
        (&broker, &["www.example.org"], false),
        (&broker, &["www.example.com", "10.30.1.5"], false),
        (&broker, &["secret.example.com"], false),
        (&no_addresses, &["www.example.com"], true),
        (&no_addresses, &["www.example.com", "10.20.1.5"], false),
        (&no_addresses, &["www.example.com", "fd00::5"], false),
    ] {
        match (openssl_verifies(constraints, names), holds) {
            (Ok(()), true) => {}
            (Err(said), false) if said.contains("subtree violation") => {}
            (verdict, _) => panic!("{names:?}: {verdict:?}"),
        }
    }
}
