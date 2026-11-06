use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use rcgen::{CertificateParams, Issuer, SerialNumber};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::CertificateDer;
use sha1::{Digest, Sha1};
use wslib_crypto::{Signer, random_serial};
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate, X509Name};
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::Error;
use crate::csr::{Csr, common_name};
use crate::der::{self, Draft};
use crate::profile::{Profile, Requested};

/// How a certificate's key identifier is computed from its public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyIdentifierMethod {
    /// RFC 5280 4.2.1.2 method 1, the SHA-1 of the subjectPublicKey bits, as OpenSSL computes it.
    Sha1,
    /// `wslib_crypto::key_identifier`: the first 20 bytes of the SHA-256 of the SubjectPublicKeyInfo.
    Sha256,
}

impl KeyIdentifierMethod {
    /// The identifier of a DER SubjectPublicKeyInfo.
    pub fn of(self, spki: &[u8]) -> Result<[u8; 20], Error> {
        match self {
            Self::Sha1 => {
                let (_, info) = SubjectPublicKeyInfo::from_der(spki)
                    .map_err(|e| Error::Malformed(e.to_string()))?;
                Ok(Sha1::digest(&info.subject_public_key.data).into())
            }
            Self::Sha256 => Ok(wslib_crypto::key_identifier(spki)),
        }
    }
}

/// A certificate serial number: positive, at most 20 octets as DER writes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Serial(Vec<u8>);

impl Serial {
    /// 16 random bytes from the provider, as `wslib_crypto::random_serial` makes them.
    pub fn random(provider: &CryptoProvider) -> Result<Self, Error> {
        Ok(Self(random_serial(provider)?.to_vec()))
    }

    /// The big-endian magnitude, with no leading zero bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn unchecked(bytes: &[u8]) -> Self {
        let leading = bytes.iter().take_while(|&&b| b == 0).count();
        Self(bytes[leading..].to_vec())
    }
}

impl TryFrom<&[u8]> for Serial {
    type Error = Error;

    /// A big-endian magnitude; leading zero bytes are dropped.
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let serial = Self::unchecked(bytes);
        let encoded = serial.0.len() + usize::from(serial.0.first().is_some_and(|b| b & 0x80 != 0));
        if serial.0.is_empty() || encoded > 20 {
            return Err(Error::Serial);
        }
        Ok(serial)
    }
}

impl TryFrom<u64> for Serial {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Error> {
        Self::try_from(&value.to_be_bytes()[..])
    }
}

impl TryFrom<i64> for Serial {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self, Error> {
        u64::try_from(value).map_err(|_| Error::Serial)?.try_into()
    }
}

/// Decimal digits, as serials are often stored.
impl FromStr for Serial {
    type Err = Error;

    fn from_str(decimal: &str) -> Result<Self, Error> {
        if decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::NotDecimal(decimal.to_string()));
        }
        let mut magnitude: Vec<u8> = Vec::new();
        for digit in decimal.bytes().map(|b| b - b'0') {
            let mut carry = u16::from(digit);
            for byte in magnitude.iter_mut().rev() {
                let value = u16::from(*byte) * 10 + carry;
                *byte = value as u8;
                carry = value >> 8;
            }
            if carry > 0 {
                magnitude.insert(0, carry as u8);
            }
            if magnitude.len() > 21 {
                return Err(Error::Serial);
            }
        }
        Self::try_from(magnitude.as_slice())
    }
}

/// Decimal, as [`FromStr`] reads it.
impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut magnitude = self.0.clone();
        let mut digits = Vec::new();
        while magnitude.iter().any(|&b| b != 0) {
            let mut remainder = 0u16;
            for byte in &mut magnitude {
                let value = remainder << 8 | u16::from(*byte);
                *byte = (value / 10) as u8;
                remainder = value % 10;
            }
            digits.push(char::from(b'0' + remainder as u8));
        }
        if digits.is_empty() {
            digits.push('0');
        }
        f.write_str(&digits.iter().rev().collect::<String>())
    }
}

impl Ord for Serial {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

/// A CA certificate and its signer, issuing under profiles the caller builds.
///
/// Issued certificates carry the CA's subject as their issuer byte for byte,
/// and its subject key identifier as their authority key identifier.
#[derive(Debug)]
pub struct Authority {
    certificate: CertificateDer<'static>,
    pub(crate) subject: Vec<u8>,
    pub(crate) key_identifier: Vec<u8>,
    serial: Serial,
    self_signed: bool,
    pub(crate) signer: Signer,
    method: KeyIdentifierMethod,
}

impl Authority {
    /// An authority over an existing CA certificate, such as one made by OpenSSL.
    ///
    /// The certificate must say `CA:TRUE` and be `signer`'s key's. When it has
    /// no subject key identifier, `method` stands in for one.
    pub fn new(
        certificate: CertificateDer<'static>,
        signer: Signer,
        method: KeyIdentifierMethod,
    ) -> Result<Self, Error> {
        let (subject, key_identifier, serial, self_signed) = {
            let parsed = der::whole(X509Certificate::from_der(&certificate))?;
            if !parsed.is_ca() {
                return Err(Error::NotAnAuthority);
            }
            if parsed.public_key().raw != signer.spki() {
                return Err(Error::KeyMismatch);
            }
            let key_identifier = parsed.extensions().iter().find_map(|extension| {
                match extension.parsed_extension() {
                    ParsedExtension::SubjectKeyIdentifier(identifier) => {
                        Some(identifier.0.to_vec())
                    }
                    _ => None,
                }
            });
            let key_identifier = match key_identifier {
                Some(identifier) => identifier,
                None => method.of(signer.spki())?.to_vec(),
            };
            let subject = parsed.subject().as_raw();
            (
                subject.to_vec(),
                key_identifier,
                Serial::unchecked(parsed.raw_serial()),
                parsed.issuer().as_raw() == subject,
            )
        };
        Ok(Self {
            certificate,
            subject,
            key_identifier,
            serial,
            self_signed,
            signer,
            method,
        })
    }

    /// A new self-signed CA certificate for `subject` (DER, as [`Subject::to_der`](crate::Subject::to_der) writes it).
    ///
    /// The profile must say `CA:TRUE`; its SAN policy sees the subject's common
    /// name and no requested names.
    pub fn self_signed(
        signer: Signer,
        subject: &[u8],
        profile: &Profile,
        serial: &Serial,
        validity: Validity,
        method: KeyIdentifierMethod,
    ) -> Result<Self, Error> {
        if !profile.is_authority() {
            return Err(Error::NotAnAuthority);
        }
        let key_identifier = method.of(signer.spki())?.to_vec();
        let certificate =
            self_signed_certificate(&signer, subject, &key_identifier, profile, serial, validity)?;
        Ok(Self {
            certificate,
            subject: subject.to_vec(),
            key_identifier,
            serial: serial.clone(),
            self_signed: true,
            signer,
            method,
        })
    }

    /// Replaces a self-signed CA certificate with a new one, keeping its subject, key and key identifier.
    pub fn re_sign(
        &mut self,
        profile: &Profile,
        serial: &Serial,
        validity: Validity,
    ) -> Result<&CertificateDer<'static>, Error> {
        if !self.self_signed {
            return Err(Error::NotSelfSigned);
        }
        if !profile.is_authority() {
            return Err(Error::NotAnAuthority);
        }
        self.certificate = self_signed_certificate(
            &self.signer,
            &self.subject,
            &self.key_identifier,
            profile,
            serial,
            validity,
        )?;
        self.serial = serial.clone();
        Ok(&self.certificate)
    }

    /// A certificate for the request's subject and key, with `profile`'s extensions.
    pub fn issue(
        &self,
        csr: &Csr,
        profile: &Profile,
        serial: &Serial,
        validity: Validity,
    ) -> Result<CertificateDer<'static>, Error> {
        self.issue_with_subject(csr, csr.subject(), profile, serial, validity)
    }

    /// As [`issue`](Self::issue), but for a DER `subject` the caller chooses; `[0x30, 0x00]` is the empty name.
    pub fn issue_with_subject(
        &self,
        csr: &Csr,
        subject: &[u8],
        profile: &Profile,
        serial: &Serial,
        validity: Validity,
    ) -> Result<CertificateDer<'static>, Error> {
        let common_name = subject_common_name(subject)?;
        let requested = Requested {
            common_name: common_name.as_deref(),
            names: csr.names(),
            name_is_empty: is_empty_name(subject),
        };
        let extensions = profile.extensions(
            &self.method.of(csr.spki())?,
            &self.key_identifier,
            &requested,
        )?;
        certificate(
            &self.signer,
            &self.subject,
            subject,
            csr.spki(),
            serial,
            validity,
            extensions,
        )
    }

    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    /// The CA certificate's serial, for a re-sign that keeps it.
    pub fn serial(&self) -> &Serial {
        &self.serial
    }

    /// The subject key identifier that issued certificates name as their authority's.
    pub fn key_identifier(&self) -> &[u8] {
        &self.key_identifier
    }

    pub fn signer(&self) -> &Signer {
        &self.signer
    }
}

fn is_empty_name(name: &[u8]) -> bool {
    name == [0x30, 0]
}

fn subject_common_name(subject: &[u8]) -> Result<Option<String>, Error> {
    match X509Name::from_der(subject) {
        Ok(([], name)) => Ok(common_name(&name)),
        _ => Err(Error::Malformed("the subject is not a DER Name".into())),
    }
}

fn self_signed_certificate(
    signer: &Signer,
    subject: &[u8],
    key_identifier: &[u8],
    profile: &Profile,
    serial: &Serial,
    validity: Validity,
) -> Result<CertificateDer<'static>, Error> {
    let common_name = subject_common_name(subject)?;
    let requested = Requested {
        common_name: common_name.as_deref(),
        names: &[],
        name_is_empty: is_empty_name(subject),
    };
    let extensions = profile.extensions(key_identifier, key_identifier, &requested)?;
    certificate(
        signer,
        subject,
        subject,
        signer.spki(),
        serial,
        validity,
        extensions,
    )
}

/// TBSCertificate positions: version, serial, signature, issuer, validity, subject, subjectPublicKeyInfo, extensions.
const ISSUER: usize = 3;
const SUBJECT: usize = 5;
const SPKI: usize = 6;

fn certificate(
    signer: &Signer,
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    serial: &Serial,
    validity: Validity,
    extensions: Vec<rcgen::CustomExtension>,
) -> Result<CertificateDer<'static>, Error> {
    if validity.not_after <= validity.not_before {
        return Err(Error::Validity);
    }
    let mut params = CertificateParams::default();
    params.serial_number = Some(SerialNumber::from_slice(serial.as_bytes()));
    params.not_before = validity.not_before.into();
    params.not_after = validity.not_after.into();
    params.custom_extensions = extensions;
    let draft_issuer = Issuer::new(CertificateParams::default(), Draft(signer));
    let draft = params
        .signed_by(&Draft(signer), &draft_issuer)
        .map_err(der::encode)?;
    der::signed(
        signer,
        draft.der(),
        &[(ISSUER, issuer), (SUBJECT, subject), (SPKI, spki)],
    )
    .map(Into::into)
}
