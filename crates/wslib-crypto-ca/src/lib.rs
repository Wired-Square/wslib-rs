//! A certificate authority on `wslib-crypto-x509`: requests read and built,
//! certificates issued under a profile, and revocation lists.
//!
//! rcgen encodes, x509-parser reads, and signing and signature checks go
//! through the caller's rustls provider, so no crypto provider is enabled here.

mod authority;
mod crl;
mod csr;
mod der;
mod profile;

pub use authority::{Authority, KeyIdentifierMethod, Serial, Validity};
pub use crl::{CrlView, Reason, Revocation, X509_CRL};
pub use csr::{CERTIFICATE_REQUEST, Csr, CsrView, Subject, build_csr};
pub use profile::{BasicConstraints, Extension, Profile, SanPolicy};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Decodes, but not as what was wanted, in this crate's words.
    #[error("does not decode: {0}")]
    Malformed(String),
    /// The decoder's error.
    #[error("does not decode")]
    Decode(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("the signature does not hold")]
    Signature(#[from] wslib_crypto_x509::signature::SignatureError),
    #[error("{name:?} cannot go in a certificate: {reason}")]
    Name { name: String, reason: &'static str },
    /// rcgen's error.
    #[error("encoding or signing failed")]
    Encode(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("rcgen's draft has an unexpected shape")]
    UnexpectedDraft,
    #[error(transparent)]
    Key(#[from] wslib_crypto::Error),
    #[error("the certificate does not say CA:TRUE")]
    NotAnAuthority,
    #[error("only a self-signed certificate can be re-signed")]
    NotSelfSigned,
    #[error("the signer's key is not the certificate's")]
    KeyMismatch,
    #[error("a certificate must end after it begins")]
    Validity,
    #[error("a serial number is positive and at most 20 octets")]
    Serial,
    #[error("{0:?} is not a decimal number")]
    NotDecimal(String),
    #[error("an empty {0} extension")]
    EmptyExtension(&'static str),
    #[error("a CRL's next update cannot come before its this update")]
    CrlValidity,
    #[error("the CRL's issuer is not the certificate's subject")]
    IssuerMismatch,
}
