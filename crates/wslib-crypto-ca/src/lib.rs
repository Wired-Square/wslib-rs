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
pub use csr::{CERTIFICATE_REQUEST, Csr, Subject, build_csr};
pub use profile::{BasicConstraints, Extension, Profile, SanPolicy};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("does not decode: {0}")]
    Malformed(String),
    #[error("the signature does not hold: {0}")]
    Signature(#[from] wslib_crypto_x509::signature::SignatureError),
    #[error("{name:?} cannot go in a certificate: {reason}")]
    Name { name: String, reason: &'static str },
    #[error("encoding or signing: {0}")]
    Encode(String),
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
    #[error("an empty {0} extension")]
    EmptyExtension(&'static str),
    #[error("the CRL's issuer is not the certificate's subject")]
    IssuerMismatch,
}
