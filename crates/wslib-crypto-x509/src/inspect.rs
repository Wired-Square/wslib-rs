use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use wslib_crypto::Fingerprint;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;

use crate::{Error, SubjectAltName, pem};

/// What a certificate says, copied out of it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CertificateView {
    pub subject: String,
    pub issuer: String,
    /// Lowercase hex, as encoded.
    pub serial: String,
    /// DNS names, addresses, emails and URIs; other kinds are left out.
    pub sans: Vec<SubjectAltName>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// Of the whole certificate's DER.
    pub fingerprint: Fingerprint,
    pub key: KeyDescription,
    /// The DER SubjectPublicKeyInfo, for [`wslib_crypto::key_matches`].
    pub spki: Vec<u8>,
    /// The subject is the issuer.
    pub self_signed: bool,
    /// `CA:TRUE` in the basic constraints.
    pub ca: bool,
    /// `None` without the extension.
    pub key_usages: Option<Vec<KeyUsage>>,
    /// `None` without the extension, which allows any purpose.
    pub extended_key_usages: Option<Vec<ExtendedKeyUsage>>,
}

/// The public key, as `RSA 2048`, `ECDSA P-256`, `Ed25519` or the algorithm's OID.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyDescription {
    Rsa {
        bits: Option<u32>,
    },
    /// `P-256`, `P-384`, `P-521` or the curve's OID.
    Ecdsa {
        curve: Option<String>,
    },
    Ed25519,
    Other {
        oid: String,
    },
}

impl fmt::Display for KeyDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa { bits: Some(bits) } => write!(f, "RSA {bits}"),
            Self::Rsa { bits: None } => f.write_str("RSA"),
            Self::Ecdsa { curve: Some(curve) } => write!(f, "ECDSA {curve}"),
            Self::Ecdsa { curve: None } => f.write_str("ECDSA"),
            Self::Ed25519 => f.write_str("Ed25519"),
            Self::Other { oid } => f.write_str(oid),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExtendedKeyUsage {
    Any,
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    /// By its dotted OID.
    Other(String),
}

/// Reads a certificate's DER.
pub fn inspect(der: &[u8]) -> Result<CertificateView, Error> {
    let certificate = match X509Certificate::from_der(der) {
        Ok(([], certificate)) => certificate,
        Ok(_) => {
            return Err(Error::Malformed(
                "trailing bytes after the certificate".into(),
            ));
        }
        Err(e) => return Err(Error::Malformed(e.to_string())),
    };
    let subject = certificate.subject().to_string();
    let issuer = certificate.issuer().to_string();
    let validity = certificate.validity();
    Ok(CertificateView {
        self_signed: subject == issuer,
        subject,
        issuer,
        serial: certificate
            .raw_serial()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        sans: sans(&certificate),
        not_before: instant(validity.not_before)?,
        not_after: instant(validity.not_after)?,
        fingerprint: Fingerprint::of(der),
        key: key_description(&certificate),
        spki: certificate.public_key().raw.to_vec(),
        ca: matches!(certificate.basic_constraints(), Ok(Some(basic)) if basic.value.ca),
        key_usages: key_usages(&certificate),
        extended_key_usages: extended_key_usages(&certificate),
    })
}

/// Reads the leaf, the first certificate, of some PEM text; see [`pem::certificates`] for what is refused.
pub fn inspect_pem(pem: &str) -> Result<CertificateView, Error> {
    inspect(&pem::certificates(pem)?[0])
}

fn instant(time: ASN1Time) -> Result<SystemTime, Error> {
    let seconds = time.timestamp();
    let offset = Duration::from_secs(seconds.unsigned_abs());
    if seconds < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(offset)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(offset)
    }
    .ok_or_else(|| Error::Malformed(format!("a validity date out of range ({seconds})")))
}

// An extension that does not parse is read as absent throughout: nothing
// here refuses a certificate over what it can only warn about.
fn sans(certificate: &X509Certificate<'_>) -> Vec<SubjectAltName> {
    let Ok(Some(san)) = certificate.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(SubjectAltName::Dns(name.to_string())),
            GeneralName::RFC822Name(email) => Some(SubjectAltName::Email(email.to_string())),
            GeneralName::URI(uri) => Some(SubjectAltName::Uri(uri.to_string())),
            GeneralName::IPAddress(bytes) => match *bytes {
                &[a, b, c, d] => Some(SubjectAltName::Ip(IpAddr::from([a, b, c, d]))),
                sixteen => <[u8; 16]>::try_from(sixteen)
                    .ok()
                    .map(|octets| SubjectAltName::Ip(IpAddr::from(octets))),
            },
            _ => None,
        })
        .collect()
}

fn key_description(certificate: &X509Certificate<'_>) -> KeyDescription {
    let spki = certificate.public_key();
    match spki.algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => KeyDescription::Rsa {
            bits: match spki.parsed() {
                Ok(PublicKey::RSA(key)) => modulus_bits(key.modulus),
                _ => None,
            },
        },
        "1.3.101.112" => KeyDescription::Ed25519,
        "1.2.840.10045.2.1" => KeyDescription::Ecdsa {
            curve: spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .map(|curve| match curve.to_id_string().as_str() {
                    "1.2.840.10045.3.1.7" => "P-256".to_string(),
                    "1.3.132.0.34" => "P-384".to_string(),
                    "1.3.132.0.35" => "P-521".to_string(),
                    other => other.to_string(),
                }),
        },
        other => KeyDescription::Other {
            oid: other.to_string(),
        },
    }
}

/// The modulus as encoded may carry a leading zero byte to keep it positive.
fn modulus_bits(modulus: &[u8]) -> Option<u32> {
    let start = modulus.iter().position(|&byte| byte != 0)?;
    let bytes = u32::try_from(modulus.len() - start).ok()?;
    Some((bytes - 1) * 8 + (8 - modulus[start].leading_zeros()))
}

fn key_usages(certificate: &X509Certificate<'_>) -> Option<Vec<KeyUsage>> {
    let usage = certificate.key_usage().ok()??.value;
    Some(
        [
            (usage.digital_signature(), KeyUsage::DigitalSignature),
            (usage.non_repudiation(), KeyUsage::NonRepudiation),
            (usage.key_encipherment(), KeyUsage::KeyEncipherment),
            (usage.data_encipherment(), KeyUsage::DataEncipherment),
            (usage.key_agreement(), KeyUsage::KeyAgreement),
            (usage.key_cert_sign(), KeyUsage::KeyCertSign),
            (usage.crl_sign(), KeyUsage::CrlSign),
            (usage.encipher_only(), KeyUsage::EncipherOnly),
            (usage.decipher_only(), KeyUsage::DecipherOnly),
        ]
        .into_iter()
        .filter_map(|(set, usage)| set.then_some(usage))
        .collect(),
    )
}

fn extended_key_usages(certificate: &X509Certificate<'_>) -> Option<Vec<ExtendedKeyUsage>> {
    let usage = certificate.extended_key_usage().ok()??.value;
    let known = [
        (usage.any, ExtendedKeyUsage::Any),
        (usage.server_auth, ExtendedKeyUsage::ServerAuth),
        (usage.client_auth, ExtendedKeyUsage::ClientAuth),
        (usage.code_signing, ExtendedKeyUsage::CodeSigning),
        (usage.email_protection, ExtendedKeyUsage::EmailProtection),
        (usage.time_stamping, ExtendedKeyUsage::TimeStamping),
        (usage.ocsp_signing, ExtendedKeyUsage::OcspSigning),
    ];
    let other = usage
        .other
        .iter()
        .map(|oid| ExtendedKeyUsage::Other(oid.to_id_string()));
    Some(
        known
            .into_iter()
            .filter_map(|(set, usage)| set.then_some(usage))
            .chain(other)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{certificate, signer};
    use wslib_crypto::KeyAlgorithm;

    #[test]
    fn a_certificate_reads_as_its_names_key_usages_and_fingerprint() {
        let pem = certificate(|params| {
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        });
        let view = inspect_pem(&pem).expect("reads");
        assert_eq!(view.sans, [SubjectAltName::Dns("widget-01.local".into())]);
        assert_eq!(view.key.to_string(), "ECDSA P-256");
        assert!(view.self_signed);
        assert!(!view.ca);
        assert_eq!(view.key_usages, Some(vec![KeyUsage::DigitalSignature]));
        assert_eq!(
            view.extended_key_usages,
            Some(vec![ExtendedKeyUsage::ServerAuth])
        );
        assert_eq!(view.spki, signer(KeyAlgorithm::EcP256).spki());
        assert_eq!(view.serial.len(), 32);
        assert_eq!(
            view.fingerprint,
            Fingerprint::of(&pem::certificates(&pem).unwrap()[0])
        );
    }

    #[test]
    fn rsa_keys_are_described_by_their_bits() {
        for (algorithm, described) in [
            (KeyAlgorithm::Rsa2048, "RSA 2048"),
            (KeyAlgorithm::EcP384, "ECDSA P-384"),
        ] {
            let pem = crate::testing::certificate_by(&signer(algorithm), |_| {});
            assert_eq!(inspect_pem(&pem).unwrap().key.to_string(), described);
        }
    }

    #[test]
    fn a_modulus_is_measured_by_its_bits_and_not_its_bytes() {
        let mut modulus = [0x42u8; 257];
        modulus[0] = 0;
        modulus[1] = 0x80;
        assert_eq!(modulus_bits(&modulus), Some(2048));
        modulus[1] = 0x7f;
        assert_eq!(modulus_bits(&modulus), Some(2047));
        assert_eq!(modulus_bits(&modulus[1..]), Some(2047));
        assert_eq!(modulus_bits(&[0, 0]), None);
    }

    #[test]
    fn an_address_in_a_certificate_reads_as_an_address() {
        let pem = certificate(|params| {
            params.subject_alt_names = vec![
                rcgen::SanType::IpAddress("192.168.1.10".parse().unwrap()),
                rcgen::SanType::IpAddress("::1".parse().unwrap()),
            ];
        });
        let sans: Vec<String> = inspect_pem(&pem)
            .unwrap()
            .sans
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(sans, ["192.168.1.10", "::1"]);
    }

    #[test]
    fn a_peers_der_inspects_the_same_as_the_pem() {
        let pem = certificate(|_| {});
        let der = pem::certificates(&pem).unwrap().remove(0);
        assert_eq!(inspect(&der).unwrap(), inspect_pem(&pem).unwrap());
        let mut trailing = der.to_vec();
        trailing.push(0);
        assert!(matches!(inspect(&trailing), Err(Error::Malformed(_))));
    }
}
