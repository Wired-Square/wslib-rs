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

pub use jwk::Jwk;
pub use jws::{Algorithm, FlattenedJws, KeyRef, ProtectedHeader};

/// Why a JWS or JWK was refused; no message carries key material.
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
    #[error("the key type {0:?} is not supported")]
    UnsupportedKey(String),
    #[error("the JWK carries private key members")]
    PrivateKey,
    #[error("the header has both jwk and kid")]
    BothJwkAndKid,
    #[error("the header has neither jwk nor kid")]
    NeitherJwkNorKid,
    #[error("{0} does not suit the key")]
    KeyMismatch(Algorithm),
    #[error("the RSA key has {0} bits; 2048 is the least")]
    RsaTooSmall(usize),
    #[error("the crypto provider has no {0} verifier")]
    NoVerifier(Algorithm),
    #[error("the signature does not verify with the key")]
    BadSignature,
}

type Members = serde_json::Map<String, serde_json::Value>;

fn object(json: &[u8], what: &'static str) -> Result<Members, Error> {
    match serde_json::from_slice(json) {
        Ok(serde_json::Value::Object(members)) => Ok(members),
        Ok(_) => Err(Error::Malformed(what)),
        Err(source) => Err(Error::Json { what, source }),
    }
}

fn optional_string<'a>(members: &'a Members, name: &'static str) -> Result<Option<&'a str>, Error> {
    members
        .get(name)
        .map(|value| value.as_str().ok_or(Error::Malformed(name)))
        .transpose()
}

fn string<'a>(members: &'a Members, name: &'static str) -> Result<&'a str, Error> {
    optional_string(members, name)?.ok_or(Error::Missing(name))
}

fn base64url_member(members: &Members, name: &'static str) -> Result<Vec<u8>, Error> {
    base64url::decode(string(members, name)?).ok_or(Error::Malformed(name))
}
