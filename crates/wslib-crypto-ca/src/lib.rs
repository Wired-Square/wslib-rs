//! A certificate authority on `wslib-crypto-x509`: requests read and built,
//! certificates issued under a profile, and revocation lists.
//!
//! rcgen encodes, x509-parser reads, and signing and signature checks go
//! through the caller's rustls provider, so no crypto provider is enabled here.

mod csr;
mod der;

pub use csr::{CERTIFICATE_REQUEST, Csr, Subject, build_csr};

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
}
