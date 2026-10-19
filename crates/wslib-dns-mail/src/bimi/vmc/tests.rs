use std::io::Write;
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, date_time_ymd,
};

use super::*;

const LOGO: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><title>Example</title></svg>"#;

/// 2026-06-01, inside every fixture's validity.
fn june() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_272_000)
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let length = content.len();
    let mut out = vec![tag];
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = (length as u32).to_be_bytes();
        let significant: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
        out.push(0x80 | significant.len() as u8);
        out.extend(significant);
    }
    out.extend_from_slice(content);
    out
}

/// RFC 3709's subjectLogo with one image whose URI is `url`.
fn logotype(url: &str) -> Vec<u8> {
    let details = der(
        0x30,
        &[
            der(0x16, b"image/svg+xml"),
            der(0x30, &[]),
            der(0x30, &der(0x16, url.as_bytes())),
        ]
        .concat(),
    );
    let image = der(0x30, &details);
    let data = der(0x30, &der(0x30, &image));
    der(0x30, &der(0xa2, &der(0xa0, &data)))
}

/// An RFC 6962 SignedCertificateTimestampList with `count` placeholder SCTs.
fn scts(count: usize) -> Vec<u8> {
    let sct: Vec<u8> = [
        vec![0u8],
        vec![7; 32],
        1_780_000_000_000u64.to_be_bytes().to_vec(),
        vec![0, 0],
        vec![4, 3, 0, 1, 0],
    ]
    .concat();
    let mut list = Vec::new();
    for _ in 0..count {
        list.extend((sct.len() as u16).to_be_bytes());
        list.extend(&sct);
    }
    der(
        0x04,
        &[(list.len() as u16).to_be_bytes().to_vec(), list].concat(),
    )
}

struct Mark {
    names: Vec<&'static str>,
    mark_type: Option<&'static str>,
    purposes: Vec<ExtendedKeyUsagePurpose>,
    logotype: Option<String>,
    scts: usize,
    year: i32,
}

impl Default for Mark {
    fn default() -> Self {
        Self {
            names: vec!["example.com", "default._bimi.example.com"],
            mark_type: Some("Registered Mark"),
            purposes: vec![ExtendedKeyUsagePurpose::Other(vec![
                1, 3, 6, 1, 5, 5, 7, 3, 31,
            ])],
            logotype: Some(format!(
                "data:image/svg+xml;base64,{}",
                base64(&gzip(LOGO.as_bytes()))
            )),
            scts: 2,
            year: 2026,
        }
    }
}

/// A root, and a mark certificate it signs, as PEM: the chain, and the root.
fn issue(mark: Mark) -> (String, String) {
    let root_key = KeyPair::generate().unwrap();
    let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    root.distinguished_name
        .push(DnType::CommonName, "Example Mark Root");
    root.not_before = date_time_ymd(2025, 1, 1);
    root.not_after = date_time_ymd(2035, 1, 1);
    let root_certificate = root.self_signed(&root_key).unwrap();
    let issuer = Issuer::new(root, root_key);

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(
        mark.names
            .iter()
            .map(|n| (*n).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Example Pty Ltd");
    if let Some(mark_type) = mark.mark_type {
        params.distinguished_name.push(
            DnType::CustomDnType(vec![1, 3, 6, 1, 4, 1, 53087, 1, 13]),
            mark_type,
        );
    }
    params.extended_key_usages = mark.purposes;
    params.not_before = date_time_ymd(mark.year, 1, 1);
    params.not_after = date_time_ymd(mark.year, 12, 31);
    if let Some(url) = mark.logotype {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 12],
                logotype(&url),
            ));
    }
    if mark.scts > 0 {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
                scts(mark.scts),
            ));
    }
    let certificate = params.signed_by(&key, &issuer).unwrap();
    (
        format!("{}{}", certificate.pem(), root_certificate.pem()),
        root_certificate.pem(),
    )
}

fn options(root: &str) -> VmcOptions {
    let mut options = VmcOptions::new(
        VmcTrustAnchors::from_pem(root.as_bytes()).unwrap(),
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .all,
    );
    options.now = Some(june());
    options
}

fn verify(mark: Mark) -> VmcVerification {
    let (chain, root) = issue(mark);
    verify_vmc(
        chain.as_bytes(),
        "example.com",
        "default",
        Some(LOGO.as_bytes()),
        &options(&root),
    )
}

#[test]
fn a_conformant_vmc_verifies() {
    let verification = verify(Mark::default());
    assert!(verification.is_valid(), "{:?}", verification.problems);
    assert_eq!(verification.kind, Some(MarkCertificateKind::Vmc));
    assert_eq!(verification.mark_type.as_deref(), Some("Registered Mark"));
    assert_eq!(verification.sct_count, 2);
    assert_eq!(verification.logo_matches, Some(true));
    assert!(
        verification
            .logo
            .as_ref()
            .is_some_and(LogoValidation::is_conformant)
    );
    assert_eq!(
        verification.names,
        ["example.com", "default._bimi.example.com"]
    );
}

#[test]
fn every_cmc_mark_type_is_a_cmc() {
    for mark_type in [
        "Prior Use Mark",
        "Modified Registered Mark",
        "Provisional Mark",
    ] {
        let verification = verify(Mark {
            mark_type: Some(mark_type),
            ..Mark::default()
        });
        assert_eq!(
            verification.kind,
            Some(MarkCertificateKind::Cmc),
            "{mark_type}"
        );
        assert!(
            verification.is_valid(),
            "{mark_type}: {:?}",
            verification.problems
        );
    }
}

#[test]
fn each_problem_is_reported() {
    for (mark, expected) in [
        (
            Mark {
                year: 2024,
                ..Mark::default()
            },
            VmcProblem::Expired,
        ),
        (
            Mark {
                year: 2027,
                ..Mark::default()
            },
            VmcProblem::NotYetValid,
        ),
        (
            Mark {
                purposes: vec![ExtendedKeyUsagePurpose::ServerAuth],
                ..Mark::default()
            },
            VmcProblem::WrongEku,
        ),
        (
            Mark {
                purposes: vec![
                    ExtendedKeyUsagePurpose::Other(vec![1, 3, 6, 1, 5, 5, 7, 3, 31]),
                    ExtendedKeyUsagePurpose::ServerAuth,
                ],
                ..Mark::default()
            },
            VmcProblem::WrongEku,
        ),
        (
            Mark {
                names: vec!["example.net"],
                ..Mark::default()
            },
            VmcProblem::SanMismatch,
        ),
        (
            Mark {
                names: vec!["other._bimi.example.com"],
                ..Mark::default()
            },
            VmcProblem::SanMismatch,
        ),
        (
            Mark {
                mark_type: None,
                ..Mark::default()
            },
            VmcProblem::UnknownMarkType { value: None },
        ),
        (
            Mark {
                logotype: None,
                ..Mark::default()
            },
            VmcProblem::NoLogotype,
        ),
        (
            Mark {
                logotype: Some(format!(
                    "data:image/svg+xml;base64,{}",
                    base64(LOGO.as_bytes())
                )),
                ..Mark::default()
            },
            VmcProblem::LogotypeNotCompressed,
        ),
        (
            Mark {
                scts: 0,
                ..Mark::default()
            },
            VmcProblem::MissingSct,
        ),
    ] {
        let verification = verify(mark);
        assert!(
            verification.problems.contains(&expected),
            "{expected:?}: {:?}",
            verification.problems
        );
    }
}

#[test]
fn a_name_under_the_organisational_domain_covers_a_subdomain() {
    let (chain, root) = issue(Mark {
        names: vec!["default._bimi.example.com.au"],
        ..Mark::default()
    });
    let verification = verify_vmc(
        chain.as_bytes(),
        "mail.example.com.au",
        "default",
        None,
        &options(&root),
    );
    assert!(
        !verification.problems.contains(&VmcProblem::SanMismatch),
        "{:?}",
        verification.problems
    );
    assert_eq!(verification.logo_matches, None);
}

#[test]
fn a_different_l_logo_is_a_mismatch() {
    let (chain, root) = issue(Mark::default());
    let other = LOGO.replace("Example", "Other");
    let verification = verify_vmc(
        chain.as_bytes(),
        "example.com",
        "default",
        Some(other.as_bytes()),
        &options(&root),
    );
    assert_eq!(verification.logo_matches, Some(false));
}

#[test]
fn an_untrusted_root_fails_the_chain() {
    let (chain, _) = issue(Mark::default());
    let (_, stranger) = issue(Mark::default());
    let verification = verify_vmc(
        chain.as_bytes(),
        "example.com",
        "default",
        None,
        &options(&stranger),
    );
    assert!(
        verification
            .problems
            .iter()
            .any(|p| matches!(p, VmcProblem::Chain { .. })),
        "{:?}",
        verification.problems
    );
}

#[test]
fn garbage_is_a_parse_problem() {
    let (_, root) = issue(Mark::default());
    let verification = verify_vmc(
        b"not a certificate",
        "example.com",
        "default",
        None,
        &options(&root),
    );
    assert!(
        matches!(verification.problems[..], [VmcProblem::Parse { .. }]),
        "{:?}",
        verification.problems
    );
    assert!(VmcTrustAnchors::from_pem(b"").is_err());
}
