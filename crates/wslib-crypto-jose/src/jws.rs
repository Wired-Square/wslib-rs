use std::fmt;

use rustls::crypto::CryptoProvider;

use crate::{Error, Jwk, base64url_member, object, optional_string, string, verify};

/// The signature algorithms ACME accounts use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    Es256,
    Es384,
    Rs256,
    EdDsa,
}

impl Algorithm {
    /// The `alg` value: `ES256`, `ES384`, `RS256` or `EdDSA`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Rs256 => "RS256",
            Self::EdDsa => "EdDSA",
        }
    }

    fn from_name(name: &str) -> Result<Self, Error> {
        [Self::Es256, Self::Es384, Self::Rs256, Self::EdDsa]
            .into_iter()
            .find(|algorithm| algorithm.as_str() == name)
            .ok_or_else(|| Error::UnsupportedAlgorithm(name.to_owned()))
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The key a JWS is signed with: carried whole, or an account URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRef {
    Jwk(Jwk),
    Kid(String),
}

/// The protected header members ACME reads; any others are ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProtectedHeader {
    pub alg: Algorithm,
    /// Absent from a key change's inner JWS; whether it must be there is the caller's rule.
    pub nonce: Option<String>,
    pub url: String,
    pub key: KeyRef,
}

impl ProtectedHeader {
    fn parse(json: &[u8]) -> Result<Self, Error> {
        let members = object(json, "protected header")?;
        if members.contains_key("crit") {
            return Err(Error::Critical);
        }
        let alg = Algorithm::from_name(string(&members, "alg")?)?;
        let key = match (members.get("jwk"), optional_string(&members, "kid")?) {
            (Some(jwk), None) => KeyRef::Jwk(Jwk::from_value(jwk)?),
            (None, Some(kid)) => KeyRef::Kid(kid.to_owned()),
            (Some(_), Some(_)) => return Err(Error::BothJwkAndKid),
            (None, None) => return Err(Error::NeitherJwkNorKid),
        };
        Ok(Self {
            alg,
            nonce: optional_string(&members, "nonce")?.map(str::to_owned),
            url: string(&members, "url")?.to_owned(),
            key,
        })
    }
}

/// A JWS in flattened JSON serialisation as RFC 8555 §6.2 allows it: one signature, no unprotected header.
#[derive(Clone, Debug)]
pub struct FlattenedJws {
    header: ProtectedHeader,
    payload: Vec<u8>,
    signing_input: String,
    signature: Vec<u8>,
}

impl FlattenedJws {
    /// Parses a request body; an empty payload is a POST-as-GET.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let members = object(json, "JWS")?;
        if let Some(name) = members
            .keys()
            .find(|name| !matches!(name.as_str(), "protected" | "payload" | "signature"))
        {
            return Err(Error::UnexpectedMember(name.clone()));
        }
        let protected = string(&members, "protected")?;
        let payload = string(&members, "payload")?;
        Ok(Self {
            header: ProtectedHeader::parse(&base64url_member(&members, "protected")?)?,
            payload: base64url_member(&members, "payload")?,
            signing_input: format!("{protected}.{payload}"),
            signature: base64url_member(&members, "signature")?,
        })
    }

    pub fn header(&self) -> &ProtectedHeader {
        &self.header
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Checks the header's `alg` suits `key` (RFC 8555 §6.2), then the signature, with the provider's verifiers.
    pub fn verify(&self, key: &Jwk, provider: &CryptoProvider) -> Result<(), Error> {
        verify::signature(
            self.header.alg,
            key,
            self.signing_input.as_bytes(),
            &self.signature,
            provider.signature_verification_algorithms.all,
        )
    }
}
