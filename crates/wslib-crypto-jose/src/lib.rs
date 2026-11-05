//! The JWS an ACME server (RFC 8555) receives: flattened JSON, a protected
//! header naming its key by `jwk` or `kid`, and a signature verified through
//! the caller's rustls [`CryptoProvider`](rustls::crypto::CryptoProvider).
//! No crypto provider is enabled here.

mod base64url;
mod jwk;
mod jws;
#[cfg(test)]
mod tests;
mod verify;

pub use jwk::{Jwk, JwkError};
pub use jws::{Algorithm, FlattenedJws, KeyChange, KeyRef, ProtectedHeader};

/// Why a JWS was refused; no message carries key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("the {what} is not JSON")]
    Json {
        what: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("the {0} is malformed")]
    Malformed(&'static str),
    #[error("the {0} member is missing")]
    Missing(&'static str),
    /// A JWS member other than `protected`, `payload` and `signature`, such as an unprotected `header`.
    #[error("the JWS member {0:?} is not allowed")]
    UnexpectedMember(String),
    #[error("the header names a critical extension")]
    Critical,
    #[error("the algorithm {0:?} is not supported")]
    UnsupportedAlgorithm(String),
    #[error("the header has both jwk and kid")]
    BothJwkAndKid,
    #[error("the header has neither jwk nor kid")]
    NeitherJwkNorKid,
    #[error(transparent)]
    Key(#[from] JwkError),
    #[error("{0} does not suit the key")]
    KeyMismatch(Algorithm),
    /// The server's fault, not the client's: its provider cannot verify an algorithm this crate accepts.
    #[error("the crypto provider has no {0} verifier")]
    NoVerifier(Algorithm),
    #[error("the signature does not verify with the key")]
    BadSignature,
    #[error("the key change's inner JWS has a nonce")]
    InnerNonce,
    #[error("the key change's inner JWS names its key by kid")]
    InnerKid,
    #[error("the key change's inner and outer url differ")]
    UrlMismatch,
    #[error("the key change's oldKey is not the account's key")]
    OldKeyMismatch,
}

/// The RFC 8555 §6.7 error type a refusal answers with, short of its `urn:ietf:params:acme:error:` prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    Malformed,
    BadSignatureAlgorithm,
    BadPublicKey,
    BadSignature,
    /// No ACME error type: the server is misconfigured and answers 500.
    ServerConfiguration,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::UnsupportedAlgorithm(_) | Self::KeyMismatch(_) => {
                ErrorKind::BadSignatureAlgorithm
            }
            Self::Key(_) | Self::OldKeyMismatch => ErrorKind::BadPublicKey,
            Self::BadSignature => ErrorKind::BadSignature,
            Self::NoVerifier(_) => ErrorKind::ServerConfiguration,
            Self::Json { .. }
            | Self::Malformed(_)
            | Self::Missing(_)
            | Self::UnexpectedMember(_)
            | Self::Critical
            | Self::BothJwkAndKid
            | Self::NeitherJwkNorKid
            | Self::InnerNonce
            | Self::InnerKid
            | Self::UrlMismatch => ErrorKind::Malformed,
        }
    }
}

type Members = serde_json::Map<String, serde_json::Value>;

/// A JSON member's fault, as a JWS or a JWK reports it.
enum Fault {
    NotJson(&'static str, serde_json::Error),
    Missing(&'static str),
    Malformed(&'static str),
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::NotJson(what, source) => Self::Json { what, source },
            Fault::Missing(name) => Self::Missing(name),
            Fault::Malformed(name) => Self::Malformed(name),
        }
    }
}

fn object(json: &[u8], what: &'static str) -> Result<Members, Fault> {
    match serde_json::from_slice(json) {
        Ok(serde_json::Value::Object(members)) => Ok(members),
        Ok(_) => Err(Fault::Malformed(what)),
        Err(source) => Err(Fault::NotJson(what, source)),
    }
}

fn optional_string<'a>(members: &'a Members, name: &'static str) -> Result<Option<&'a str>, Fault> {
    members
        .get(name)
        .map(|value| value.as_str().ok_or(Fault::Malformed(name)))
        .transpose()
}

fn string<'a>(members: &'a Members, name: &'static str) -> Result<&'a str, Fault> {
    optional_string(members, name)?.ok_or(Fault::Missing(name))
}

fn base64url_member(members: &Members, name: &'static str) -> Result<Vec<u8>, Fault> {
    base64url::decode(string(members, name)?).ok_or(Fault::Malformed(name))
}
