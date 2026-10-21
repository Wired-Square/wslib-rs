use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use wslib_crypto::Fingerprint;
use x509_parser::asn1_rs::ToDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::error::X509Error;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;
use x509_parser::x509::{AttributeTypeAndValue, X509Name};

use crate::{Error, SubjectAltName, pem};

/// What a certificate says, copied out of it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CertificateView {
    /// In RFC 4514 form, most specific first: `CN=R3,O=Let's Encrypt,C=US`.
    pub subject: String,
    /// As the subject.
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
    let subject = rfc_4514(certificate.subject());
    let issuer = rfc_4514(certificate.issuer());
    let validity = certificate.validity();
    Ok(CertificateView {
        self_signed: subject == issuer,
        subject,
        issuer,
        serial: hex(certificate.raw_serial()),
        sans: sans(&certificate),
        not_before: instant(validity.not_before)?,
        not_after: instant(validity.not_after)?,
        fingerprint: Fingerprint::of(der),
        key: key_description(&certificate),
        spki: certificate.public_key().raw.to_vec(),
        ca: matches!(certificate.basic_constraints(), Ok(Some(basic)) if basic.value.ca),
        key_usages: key_usages(&certificate).ok().flatten(),
        extended_key_usages: extended_key_usages(&certificate),
    })
}

/// Reads the leaf, the first certificate, of some PEM text; see [`pem::certificates`] for what is refused.
pub fn inspect_pem(pem: &str) -> Result<CertificateView, Error> {
    let leaf = pem::certificates(pem)?.into_iter().next();
    inspect(&leaf.ok_or_else(pem::none_decodes)?)
}

fn rfc_4514(name: &X509Name<'_>) -> String {
    let rdns: Vec<_> = name.iter_rdn().collect();
    rdns.iter()
        .rev()
        .map(|rdn| rdn.iter().map(attribute).collect::<Vec<_>>().join("+"))
        .collect::<Vec<_>>()
        .join(",")
}

fn attribute(attribute: &AttributeTypeAndValue<'_>) -> String {
    let oid = attribute.attr_type().to_id_string();
    let short = match oid.as_str() {
        "2.5.4.3" => Some("CN"),
        "2.5.4.6" => Some("C"),
        "2.5.4.7" => Some("L"),
        "2.5.4.8" => Some("ST"),
        "2.5.4.9" => Some("STREET"),
        "2.5.4.10" => Some("O"),
        "2.5.4.11" => Some("OU"),
        "0.9.2342.19200300.100.1.1" => Some("UID"),
        "0.9.2342.19200300.100.1.25" => Some("DC"),
        _ => None,
    };
    match (short, attribute.as_str()) {
        (Some(short), Ok(value)) => format!("{short}={}", escaped(value)),
        (short, _) => {
            let der = attribute.attr_value().to_der_vec().unwrap_or_default();
            format!("{}=#{}", short.unwrap_or(&oid), hex(&der))
        }
    }
}

fn escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (at, c) in value.char_indices() {
        if c == '\0' {
            out.push_str("\\00");
            continue;
        }
        let leading = at == 0 && matches!(c, ' ' | '#');
        let trailing = at + c.len_utf8() == value.len() && c == ' ';
        if leading || trailing || "\"+,;<>\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

pub(crate) fn key_usages(
    certificate: &X509Certificate<'_>,
) -> Result<Option<Vec<KeyUsage>>, X509Error> {
    let Some(usage) = certificate.key_usage()? else {
        return Ok(None);
    };
    let usage = usage.value;
    Ok(Some(
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
    ))
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
    fn an_indented_certificate_reads_rather_than_panicking() {
        let pem = certificate(|_| {});
        let indented: String = pem.lines().map(|line| format!("    {line}\n")).collect();
        assert_eq!(inspect_pem(&indented), inspect_pem(&pem));
    }

    #[test]
    fn names_read_in_rfc_4514_form_most_specific_first() {
        let pem = certificate(|params| {
            let mut name = rcgen::DistinguishedName::new();
            name.push(rcgen::DnType::CountryName, "US");
            name.push(rcgen::DnType::OrganizationName, "Let's Encrypt");
            name.push(rcgen::DnType::CommonName, "R3");
            params.distinguished_name = name;
        });
        assert_eq!(
            inspect_pem(&pem).unwrap().subject,
            "CN=R3,O=Let's Encrypt,C=US"
        );
    }

    #[test]
    fn a_value_with_special_characters_is_escaped_and_an_unknown_type_is_hex() {
        let pem = certificate(|params| {
            let mut name = rcgen::DistinguishedName::new();
            name.push(
                rcgen::DnType::OrganizationName,
                "#Widgets, Inc. <1+1>; \\\"x\" ",
            );
            name.push(
                rcgen::DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]),
                "ops@widget-01.local",
            );
            params.distinguished_name = name;
        });
        assert_eq!(
            inspect_pem(&pem).unwrap().subject,
            "1.2.840.113549.1.9.1=#0c136f7073407769646765742d30312e6c6f63616c,\
             O=\\#Widgets\\, Inc. \\<1\\+1\\>\\; \\\\\\\"x\\\"\\ "
        );
    }

    #[test]
    fn a_multi_valued_rdn_joins_with_a_plus_and_dc_has_its_short_name() {
        let der = [
            0x30, 0x2b, 0x31, 0x14, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, b'a',
            0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x01, b'b', 0x31, 0x13, 0x30, 0x11,
            0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x03,
            b'c', b'o', b'm',
        ];
        let (_, name) = X509Name::from_der(&der).expect("parses");
        assert_eq!(rfc_4514(&name), "DC=com,CN=a+O=b");
        assert_eq!(escaped(" a\0 "), "\\ a\\00\\ ");
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
