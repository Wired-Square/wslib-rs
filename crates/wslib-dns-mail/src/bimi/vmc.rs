//! Mark certificates (VMC and CMC) from a BIMI record's `a=`: their chain,
//! dates, names, Certificate Transparency and embedded logo
//! (draft-fetch-validation-vmc-wchuang; the BIMI Group's Mark Certificate
//! Requirements).

use std::time::SystemTime;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use super::{LogoValidation, validate_logo};

/// `id-kp-BrandIndicatorforMessageIdentification`, DER-encoded.
const BIMI_EKU: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x1f];
const BIMI_EKU_ID: &str = "1.3.6.1.5.5.7.3.31";
const MARK_TYPE: &str = "1.3.6.1.4.1.53087.1.13";
const LOGOTYPE: &str = "1.3.6.1.5.5.7.1.12";

/// A compressed embedded logo is refused once it inflates past this.
const LOGOTYPE_INFLATE_LIMIT: usize = 256 * 1024;

/// The roots a caller trusts to issue mark certificates. None are built in:
/// which CAs qualify changes, and the choice is the caller's.
#[derive(Clone, Debug)]
pub struct VmcTrustAnchors(Vec<TrustAnchor<'static>>);

impl VmcTrustAnchors {
    /// Every certificate in a PEM bundle, as a trust anchor.
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let mut anchors = Vec::new();
        for der in CertificateDer::pem_slice_iter(pem) {
            let der = der.map_err(|error| error.to_string())?;
            let anchor =
                webpki::anchor_from_trusted_cert(&der).map_err(|error| error.to_string())?;
            anchors.push(anchor.to_owned());
        }
        if anchors.is_empty() {
            return Err("no certificates in the bundle".into());
        }
        Ok(Self(anchors))
    }
}

/// How to verify mark certificates. The signature algorithms come from the
/// caller's crypto provider, as rustls's do, so this crate takes none.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VmcOptions {
    pub trust_anchors: VmcTrustAnchors,
    pub algorithms: &'static [&'static dyn SignatureVerificationAlgorithm],
    /// The time to check validity at; now when unset.
    pub now: Option<SystemTime>,
}

impl VmcOptions {
    pub fn new(
        trust_anchors: VmcTrustAnchors,
        algorithms: &'static [&'static dyn SignatureVerificationAlgorithm],
    ) -> Self {
        Self {
            trust_anchors,
            algorithms,
            now: None,
        }
    }
}

/// Which kind of mark certificate, from `subject:markType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MarkCertificateKind {
    /// A Verified Mark Certificate: a registered or government mark.
    Vmc,
    /// A Common Mark Certificate: prior use, modified or provisional.
    Cmc,
}

/// What a mark certificate says and everything wrong with it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct VmcVerification {
    pub kind: Option<MarkCertificateKind>,
    /// `subject:markType` as written.
    pub mark_type: Option<String>,
    /// The `dNSName`s in the subject alternative names.
    pub names: Vec<String>,
    /// Seconds since the epoch.
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub sct_count: usize,
    /// The embedded logo, checked against SVG Tiny PS.
    pub logo: Option<LogoValidation>,
    /// SHA-256 of the decompressed embedded logo, in hex.
    pub logo_sha256: Option<String>,
    /// Whether the embedded logo is the `l=` logo, byte for byte once both
    /// are decompressed; unset when there was no `l=` logo to compare.
    pub logo_matches: Option<bool>,
    pub problems: Vec<VmcProblem>,
}

impl VmcVerification {
    pub fn is_valid(&self) -> bool {
        self.problems.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
#[non_exhaustive]
pub enum VmcProblem {
    /// Not a PEM chain of X.509 certificates.
    Parse {
        message: String,
    },
    /// The chain doesn't lead to a trusted root, in the verifier's words.
    Chain {
        message: String,
    },
    Expired,
    NotYetValid,
    /// The BIMI purpose is missing, or not the only one.
    WrongEku,
    /// No subject name covers the BIMI domain or selector.
    SanMismatch,
    /// `subject:markType` missing or not a known value.
    UnknownMarkType {
        value: Option<String>,
    },
    NoLogotype,
    /// The embedded logo isn't compressed, as the requirements say it must be.
    LogotypeNotCompressed,
    /// The embedded logo couldn't be decoded, or breaks SVG Tiny PS.
    LogotypeInvalid {
        message: String,
    },
    MissingSct,
}

/// Neutral wording; consumers may write their own.
impl std::fmt::Display for VmcProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse { message } => write!(f, "not a PEM certificate chain: {message}"),
            Self::Chain { message } => {
                write!(f, "the chain doesn't lead to a trusted root: {message}")
            }
            Self::Expired => f.write_str("the certificate has expired"),
            Self::NotYetValid => f.write_str("the certificate is not yet valid"),
            Self::WrongEku => f.write_str("the extended key usage must be BIMI's alone"),
            Self::SanMismatch => f.write_str("no subject name covers the BIMI domain or selector"),
            Self::UnknownMarkType { value: Some(value) } => {
                write!(f, "unknown mark type {value:?}")
            }
            Self::UnknownMarkType { value: None } => f.write_str("no mark type"),
            Self::NoLogotype => f.write_str("no embedded logo"),
            Self::LogotypeNotCompressed => f.write_str("the embedded logo isn't compressed"),
            Self::LogotypeInvalid { message } => write!(f, "embedded logo: {message}"),
            Self::MissingSct => f.write_str("no Certificate Transparency timestamps"),
        }
    }
}

/// Verifies the mark certificate chain in `pem` for the BIMI record at
/// `<selector>._bimi.<domain>`. `logo` is the decompressed `l=` logo, when
/// it was fetched, to compare with the embedded one.
pub fn verify_vmc(
    pem: &[u8],
    domain: &str,
    selector: &str,
    logo: Option<&[u8]>,
    options: &VmcOptions,
) -> VmcVerification {
    let mut verification = VmcVerification::default();
    let certificates: Vec<CertificateDer<'static>> =
        match CertificateDer::pem_slice_iter(pem).collect() {
            Ok(certificates) => certificates,
            Err(error) => {
                return failed(VmcProblem::Parse {
                    message: error.to_string(),
                });
            }
        };
    let Some((end_entity, intermediates)) = certificates.split_first() else {
        return failed(VmcProblem::Parse {
            message: "no certificates".into(),
        });
    };
    let certificate = match X509Certificate::from_der(end_entity) {
        Ok((_, certificate)) => certificate,
        Err(error) => {
            return failed(VmcProblem::Parse {
                message: error.to_string(),
            });
        }
    };
    let now = options.now.unwrap_or_else(SystemTime::now);
    let seconds = |time: SystemTime| {
        time.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
            })
    };

    verification.not_before = Some(certificate.validity().not_before.timestamp());
    verification.not_after = Some(certificate.validity().not_after.timestamp());
    if seconds(now) < certificate.validity().not_before.timestamp() {
        verification.problem(VmcProblem::NotYetValid);
    }
    if seconds(now) > certificate.validity().not_after.timestamp() {
        verification.problem(VmcProblem::Expired);
    }
    if !sole_bimi_purpose(&certificate) {
        verification.problem(VmcProblem::WrongEku);
    }

    verification.mark_type = certificate
        .subject()
        .iter_attributes()
        .find(|attribute| attribute.attr_type().to_id_string() == MARK_TYPE)
        .and_then(|attribute| attribute.as_str().ok())
        .map(str::to_owned);
    verification.kind = match verification.mark_type.as_deref() {
        Some("Registered Mark" | "Government Mark") => Some(MarkCertificateKind::Vmc),
        Some("Prior Use Mark" | "Modified Registered Mark" | "Provisional Mark") => {
            Some(MarkCertificateKind::Cmc)
        }
        _ => None,
    };
    if verification.kind.is_none() {
        let value = verification.mark_type.clone();
        verification.problem(VmcProblem::UnknownMarkType { value });
    }

    if let Ok(Some(names)) = certificate.subject_alternative_name() {
        verification.names = names
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(name) => Some(wslib_dns::normalise(name)),
                _ => None,
            })
            .collect();
    }
    if !names_cover(&verification.names, domain, selector) {
        verification.problem(VmcProblem::SanMismatch);
    }

    for extension in certificate.extensions() {
        if let ParsedExtension::SCT(timestamps) = extension.parsed_extension() {
            verification.sct_count += timestamps.len();
        }
    }
    if verification.sct_count == 0 {
        verification.problem(VmcProblem::MissingSct);
    }

    embedded_logo(&certificate, logo, &mut verification);

    let anchors = &options.trust_anchors.0;
    let chained = webpki::EndEntityCert::try_from(end_entity).and_then(|certificate| {
        certificate
            .verify_for_usage(
                options.algorithms,
                anchors,
                intermediates,
                UnixTime::since_unix_epoch(
                    now.duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default(),
                ),
                webpki::KeyUsage::required(BIMI_EKU),
                None,
                None,
            )
            .map(drop)
    });
    if let Err(error) = chained {
        #[allow(deprecated)]
        let problem = match error {
            webpki::Error::CertExpired { .. } => VmcProblem::Expired,
            webpki::Error::CertNotValidYet { .. } => VmcProblem::NotYetValid,
            webpki::Error::RequiredEkuNotFound | webpki::Error::RequiredEkuNotFoundContext(_) => {
                VmcProblem::WrongEku
            }
            error => VmcProblem::Chain {
                message: format!("{error:?}"),
            },
        };
        verification.problem(problem);
    }
    verification
}

impl VmcVerification {
    fn problem(&mut self, problem: VmcProblem) {
        if !self.problems.contains(&problem) {
            self.problems.push(problem);
        }
    }
}

fn failed(problem: VmcProblem) -> VmcVerification {
    VmcVerification {
        problems: vec![problem],
        ..VmcVerification::default()
    }
}

/// The requirements allow no purpose but BIMI's.
fn sole_bimi_purpose(certificate: &X509Certificate<'_>) -> bool {
    let Ok(Some(usage)) = certificate.extended_key_usage() else {
        return false;
    };
    let usage = usage.value;
    let other_purposes = usage.any
        || usage.server_auth
        || usage.client_auth
        || usage.code_signing
        || usage.email_protection
        || usage.time_stamping
        || usage.ocsp_signing;
    !other_purposes && usage.other.len() == 1 && usage.other[0].to_id_string() == BIMI_EKU_ID
}

/// draft-fetch-validation-vmc-wchuang §5.2: a name under `_bimi` must be the
/// record's own, `<selector>._bimi.<domain>` or under the organisational
/// domain; any other name must be the domain or the organisational domain.
fn names_cover(names: &[String], domain: &str, selector: &str) -> bool {
    let domain = wslib_dns::normalise(domain);
    let organisation = wslib_dns::registrable_domain(&domain).unwrap_or_else(|| domain.clone());
    let selector = selector.to_ascii_lowercase();
    names.iter().any(|name| {
        if name.split('.').any(|label| label == "_bimi") {
            [&domain, &organisation]
                .iter()
                .any(|base| *name == format!("{selector}._bimi.{base}"))
        } else {
            *name == domain || *name == organisation
        }
    })
}

/// Finds the `data:` URL in the logotype extension, decodes and inflates
/// it, checks it against SVG Tiny PS and compares it with `l=`.
fn embedded_logo(
    certificate: &X509Certificate<'_>,
    logo: Option<&[u8]>,
    verification: &mut VmcVerification,
) {
    let extension = certificate
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == LOGOTYPE);
    let Some(url) = extension.and_then(|extension| data_url(extension.value)) else {
        verification.problem(VmcProblem::NoLogotype);
        return;
    };
    let invalid = |message: &str| VmcProblem::LogotypeInvalid {
        message: message.to_owned(),
    };
    let Some((header, payload)) = url.split_once(',') else {
        verification.problem(invalid("the data: URL has no comma"));
        return;
    };
    let decoded = if header.ends_with(";base64") {
        match crate::dkim::key::decode_base64(payload) {
            Some(decoded) => decoded,
            None => {
                verification.problem(invalid("the data: URL isn't valid base64"));
                return;
            }
        }
    } else {
        payload.as_bytes().to_vec()
    };
    let svg = if crate::inflate::is_gzip(&decoded) {
        match crate::inflate::gunzip(&decoded, LOGOTYPE_INFLATE_LIMIT) {
            Ok(svg) => svg,
            Err(_) => {
                verification.problem(invalid(
                    "the embedded logo doesn't inflate within the limit",
                ));
                return;
            }
        }
    } else {
        verification.problem(VmcProblem::LogotypeNotCompressed);
        decoded
    };
    let validation = validate_logo(&svg);
    if !validation.is_conformant() {
        verification.problem(invalid("the embedded logo breaks SVG Tiny PS"));
    }
    let hash = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let embedded = hash(&svg);
    verification.logo_matches = logo.map(|logo| hash(logo) == embedded);
    verification.logo_sha256 = Some(embedded);
    verification.logo = Some(validation);
}

/// The first IA5String starting `data:` anywhere in a DER structure, which
/// is where RFC 3709 puts a logotype's URI.
fn data_url(der: &[u8]) -> Option<String> {
    let mut rest = der;
    while let Some((tag, content, next)) = tlv(rest) {
        if tag == 0x16 && content.starts_with(b"data:") {
            return std::str::from_utf8(content).ok().map(str::to_owned);
        }
        let constructed = tag & 0x20 != 0;
        if (constructed || tag == 0x04)
            && let Some(found) = data_url(content)
        {
            return Some(found);
        }
        rest = next;
    }
    None
}

/// One tag, content and what follows, for short-form tags.
fn tlv(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&length, rest) = rest.split_first()?;
    let (length, rest) = if length < 0x80 {
        (usize::from(length), rest)
    } else {
        let octets = usize::from(length & 0x7f);
        if octets == 0 || octets > 4 || rest.len() < octets {
            return None;
        }
        let (bytes, rest) = rest.split_at(octets);
        (
            bytes.iter().fold(0usize, |n, &b| (n << 8) | usize::from(b)),
            rest,
        )
    };
    (rest.len() >= length).then(|| {
        let (content, next) = rest.split_at(length);
        (tag, content, next)
    })
}

#[cfg(test)]
mod tests;
