//! Whether a certificate chains to a trusted root, for a purpose, at a time,
//! with the signature algorithms of the caller's crypto provider.

use std::fmt;
use std::time::SystemTime;

use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::KeyUsage;
use crate::inspect::key_usages;

/// An extended key usage every certificate below the anchor must name, and
/// optionally a key usage the end-entity certificate must allow.
///
/// [`Purpose::required_if_present`] also passes a certificate without the
/// extension, as browsers do for server and client authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Purpose {
    oid: &'static [u8],
    if_present: bool,
    leaf_key_usage: Option<KeyUsage>,
}

impl Purpose {
    pub const SERVER_AUTH: Self = Self::required_if_present(&[0x2b, 6, 1, 5, 5, 7, 3, 1]);
    pub const CLIENT_AUTH: Self = Self::required_if_present(&[0x2b, 6, 1, 5, 5, 7, 3, 2]);
    pub const CODE_SIGNING: Self = Self::required(&[0x2b, 6, 1, 5, 5, 7, 3, 3])
        .with_leaf_key_usage(KeyUsage::DigitalSignature);

    /// By the DER contents of its OID.
    pub const fn required(oid: &'static [u8]) -> Self {
        Self {
            oid,
            if_present: false,
            leaf_key_usage: None,
        }
    }

    pub const fn required_if_present(oid: &'static [u8]) -> Self {
        Self {
            oid,
            if_present: true,
            leaf_key_usage: None,
        }
    }

    /// The end-entity certificate must allow `usage` when it has a key usage extension at all.
    pub const fn with_leaf_key_usage(self, usage: KeyUsage) -> Self {
        Self {
            leaf_key_usage: Some(usage),
            ..self
        }
    }

    fn key_usage(self) -> webpki::KeyUsage {
        if self.if_present {
            webpki::KeyUsage::required_if_present(self.oid)
        } else {
            webpki::KeyUsage::required(self.oid)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainError {
    Expired,
    NotYetValid,
    /// A certificate in the chain does not name the purpose.
    WrongPurpose,
    /// The end-entity certificate's key usage leaves out what the purpose needs.
    WrongKeyUsage,
    /// Not issued under the anchors: no known issuer, or a signature that does not verify.
    Untrusted(String),
    /// Anything else, in the verifier's words.
    Invalid(String),
}

/// The detail is the verifier's own words, unchanged.
impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => f.write_str("the certificate has expired"),
            Self::NotYetValid => f.write_str("the certificate is not valid yet"),
            Self::WrongPurpose => f.write_str("the certificate is not for that purpose"),
            Self::WrongKeyUsage => {
                f.write_str("the certificate's key usage does not allow that purpose")
            }
            Self::Untrusted(detail) | Self::Invalid(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for ChainError {}

fn refused(error: webpki::Error) -> ChainError {
    #[allow(deprecated)]
    match error {
        webpki::Error::CertExpired { .. } => ChainError::Expired,
        webpki::Error::CertNotValidYet { .. } => ChainError::NotYetValid,
        webpki::Error::RequiredEkuNotFound | webpki::Error::RequiredEkuNotFoundContext(_) => {
            ChainError::WrongPurpose
        }
        webpki::Error::UnknownIssuer | webpki::Error::InvalidSignatureForPublicKey => {
            ChainError::Untrusted(error.to_string())
        }
        error => ChainError::Invalid(error.to_string()),
    }
}

/// A trusted root from its certificate's DER.
pub fn trust_anchor(der: &CertificateDer<'_>) -> Result<TrustAnchor<'static>, ChainError> {
    webpki::anchor_from_trusted_cert(der)
        .map(|anchor| anchor.to_owned())
        .map_err(refused)
}

/// Verifies `end_entity`, through any of `intermediates`, to one of `anchors` at `at`.
///
/// `algorithms` are the caller's provider's, as
/// `provider.signature_verification_algorithms.all`. Revocation is not
/// checked, nor are the anchor's own validity and key usage.
pub fn verify(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &[TrustAnchor<'_>],
    purpose: Purpose,
    at: SystemTime,
    algorithms: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), ChainError> {
    let at = UnixTime::since_unix_epoch(
        at.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default(),
    );
    webpki::EndEntityCert::try_from(end_entity)
        .and_then(|certificate| {
            certificate
                .verify_for_usage(
                    algorithms,
                    anchors,
                    intermediates,
                    at,
                    purpose.key_usage(),
                    None,
                    None,
                )
                .map(drop)
        })
        .map_err(refused)?;
    purpose
        .leaf_key_usage
        .map_or(Ok(()), |usage| allows(end_entity, usage))
}

fn allows(certificate: &CertificateDer<'_>, usage: KeyUsage) -> Result<(), ChainError> {
    let invalid = |e: &dyn fmt::Display| ChainError::Invalid(e.to_string());
    let (_, certificate) = X509Certificate::from_der(certificate).map_err(|e| invalid(&e))?;
    match key_usages(&certificate).map_err(|e| invalid(&e))? {
        Some(usages) if !usages.contains(&usage) => Err(ChainError::WrongKeyUsage),
        _ => Ok(()),
    }
}
