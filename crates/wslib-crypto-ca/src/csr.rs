use std::net::IpAddr;

use const_oid::ObjectIdentifier;
use const_oid::db::rfc3280::EMAIL_ADDRESS;
use const_oid::db::rfc4519::{C, CN, L, O, OU, ST};
use rcgen::CertificateParams;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateSigningRequestDer, SignatureVerificationAlgorithm};
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_x509::{SubjectAltName, signature};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509CertificationRequest};
use x509_parser::x509::X509Name;

use crate::Error;
use crate::der::{self, SEQUENCE, tlv};

/// The PEM label of a certificate signing request.
pub const CERTIFICATE_REQUEST: &str = "CERTIFICATE REQUEST";

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// A certificate signing request whose self-signature has been verified.
///
/// Only its subject, public key and requested subject alternative names are
/// kept: every other requested extension is the profile's to decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Csr {
    der: Vec<u8>,
    subject: Vec<u8>,
    common_name: Option<String>,
    spki: Vec<u8>,
    names: Vec<SubjectAltName>,
}

impl Csr {
    /// Parses a DER request and verifies its signature with those of `algorithms` that fit.
    pub fn from_der(
        der: &[u8],
        algorithms: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<Self, Error> {
        let request = der::whole(X509CertificationRequest::from_der(der))?;
        let [signed, algorithm, _] = der::elements(der)?[..] else {
            return Err(Error::Malformed("not a certificate signing request".into()));
        };
        let info = &request.certification_request_info;
        signature::verify(
            info.subject_pki.raw,
            algorithm,
            signed,
            &request.signature_value.data,
            algorithms,
        )?;
        Ok(Self {
            der: der.to_vec(),
            subject: info.subject.as_raw().to_vec(),
            common_name: common_name(&info.subject),
            spki: info.subject_pki.raw.to_vec(),
            names: requested_names(&request),
        })
    }

    /// The one `CERTIFICATE REQUEST` section of `pem`, as [`Csr::from_der`] reads it.
    pub fn from_pem(
        pem: &str,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<Self, Error> {
        let limit = wslib_crypto_x509::pem::MAX_LEN;
        if pem.len() > limit {
            return Err(Error::Malformed(format!("PEM over {limit} bytes")));
        }
        let der = CertificateSigningRequestDer::from_pem_slice(pem.as_bytes())
            .map_err(|e| Error::Malformed(e.to_string()))?;
        Self::from_der(&der, algorithms)
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The subject as DER, copied into an issued certificate byte for byte.
    pub fn subject(&self) -> &[u8] {
        &self.subject
    }

    /// The first common name, when it is a string.
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// The DER SubjectPublicKeyInfo.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// The key's algorithm, when it is one `wslib-crypto` signs with.
    pub fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        KeyAlgorithm::of_spki(&self.spki)
    }

    /// Whether the key is RSA, of any size: only RSA keys may claim key encipherment.
    pub fn has_rsa_key(&self) -> bool {
        x509_parser::x509::SubjectPublicKeyInfo::from_der(&self.spki)
            .is_ok_and(|(_, info)| info.algorithm.algorithm.as_bytes() == RSA_ENCRYPTION.as_bytes())
    }

    /// The DNS names, addresses, emails and URIs asked for; other kinds are dropped.
    pub fn names(&self) -> &[SubjectAltName] {
        &self.names
    }
}

pub(crate) fn common_name(name: &X509Name<'_>) -> Option<String> {
    name.iter_common_name()
        .next()
        .and_then(|attribute| attribute.as_str().ok())
        .map(str::to_string)
}

fn requested_names(request: &X509CertificationRequest<'_>) -> Vec<SubjectAltName> {
    request
        .requested_extensions()
        .into_iter()
        .flatten()
        .filter_map(|extension| match extension {
            ParsedExtension::SubjectAlternativeName(names) => Some(&names.general_names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(SubjectAltName::Dns(dns.to_string())),
            GeneralName::RFC822Name(email) => Some(SubjectAltName::Email(email.to_string())),
            GeneralName::URI(uri) => Some(SubjectAltName::Uri(uri.to_string())),
            GeneralName::IPAddress(bytes) => address(bytes).map(SubjectAltName::Ip),
            _ => None,
        })
        .collect()
}

fn address(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}

/// A distinguished name of the attributes most requests carry, written in the order CN, C, ST, L, O, OU, emailAddress.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subject {
    pub common_name: String,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub organisation: Option<String>,
    pub organisational_unit: Option<String>,
    pub email: Option<String>,
}

impl Subject {
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            common_name: common_name.into(),
            ..Self::default()
        }
    }

    /// The name as DER, with OpenSSL's string types: PrintableString for the
    /// country, IA5String for the email and UTF8String for the rest.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        if self.common_name.is_empty() {
            return Err(name_error("", "the common name is empty"));
        }
        let mut attributes = vec![attribute(CN, UTF8_STRING, &self.common_name)];
        if let Some(country) = &self.country {
            if country.len() != 2 || !country.bytes().all(is_printable) {
                return Err(name_error(
                    country,
                    "a country is two PrintableString letters",
                ));
            }
            attributes.push(attribute(C, PRINTABLE_STRING, country));
        }
        for (oid, value) in [
            (ST, &self.state),
            (L, &self.locality),
            (O, &self.organisation),
            (OU, &self.organisational_unit),
        ] {
            if let Some(value) = value {
                attributes.push(attribute(oid, UTF8_STRING, value));
            }
        }
        if let Some(email) = &self.email {
            if !email.is_ascii() {
                return Err(name_error(email, "not ASCII"));
            }
            attributes.push(attribute(EMAIL_ADDRESS, IA5_STRING, email));
        }
        Ok(tlv(SEQUENCE, &attributes.concat()))
    }
}

const UTF8_STRING: u8 = 0x0c;
const PRINTABLE_STRING: u8 = 0x13;
const IA5_STRING: u8 = 0x16;

/// One single-valued relative distinguished name.
fn attribute(oid: ObjectIdentifier, string_type: u8, value: &str) -> Vec<u8> {
    let pair = [der::oid(oid), tlv(string_type, value.as_bytes())].concat();
    tlv(0x31, &tlv(SEQUENCE, &pair))
}

fn is_printable(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&byte)
}

fn name_error(name: &str, reason: &'static str) -> Error {
    Error::Name {
        name: name.to_string(),
        reason,
    }
}

/// A request for `subject` and `names`, signed by `signer`; the names go in a non-critical extension request.
pub fn build_csr(
    signer: &Signer,
    subject: &Subject,
    names: &[SubjectAltName],
) -> Result<CertificateSigningRequestDer<'static>, Error> {
    let subject = subject.to_der()?;
    let mut params = CertificateParams::default();
    if !names.is_empty() {
        params.custom_extensions = vec![der::subject_alt_name(names, false)?];
    }
    let draft = params
        .serialize_request(&der::Draft(signer))
        .map_err(der::encode)?;
    der::signed(signer, draft.der(), &[(1, &subject)]).map(Into::into)
}
