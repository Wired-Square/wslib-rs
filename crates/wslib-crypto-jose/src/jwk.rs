use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::base64url::encode;
use crate::{Algorithm, Fault, Members, base64url_member, object, string, verify};

/// Why a JWK was refused; an ACME server answers each with badPublicKey.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwkError {
    #[error("the JWK is not JSON")]
    Json(#[source] serde_json::Error),
    #[error("the JWK's {0} is malformed")]
    Malformed(&'static str),
    #[error("the JWK's {0} member is missing")]
    Missing(&'static str),
    #[error("the JWK carries private key members")]
    PrivateKey,
    #[error("the key type {0:?} is not supported")]
    Unsupported(String),
    #[error("the RSA key has {0} bits; 2048 is the least")]
    RsaTooSmall(usize),
}

impl From<Fault> for JwkError {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::NotJson(_, source) => Self::Json(source),
            Fault::Missing(name) => Self::Missing(name),
            Fault::Malformed(name) => Self::Malformed(name),
        }
    }
}

/// A public JSON Web Key: EC P-256 or P-384, RSA, or OKP Ed25519, equal by its RFC 7638 members.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Jwk(pub(crate) Key);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    Ec {
        curve: Curve,
        x: Vec<u8>,
        y: Vec<u8>,
    },
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ed25519([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Curve {
    P256,
    P384,
}

impl Curve {
    fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Self::P256 => Algorithm::Es256,
            Self::P384 => Algorithm::Es384,
        }
    }

    fn coordinate_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }
}

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

impl Jwk {
    /// Parses a public key, ignoring optional members such as `kid` and `use`; RSA needs 2048 bits or more.
    pub fn from_json(json: &str) -> Result<Self, JwkError> {
        Self::from_members(&object(json.as_bytes(), "JWK")?)
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, JwkError> {
        Self::from_members(value.as_object().ok_or(JwkError::Malformed("JWK"))?)
    }

    fn from_members(members: &Members) -> Result<Self, JwkError> {
        if PRIVATE_MEMBERS
            .iter()
            .any(|name| members.contains_key(*name))
        {
            return Err(JwkError::PrivateKey);
        }
        let key = match string(members, "kty")? {
            "EC" => {
                let curve = match string(members, "crv")? {
                    "P-256" => Curve::P256,
                    "P-384" => Curve::P384,
                    other => return Err(JwkError::Unsupported(format!("EC {other}"))),
                };
                let coordinate = |name| {
                    let bytes = base64url_member(members, name)?;
                    (bytes.len() == curve.coordinate_len())
                        .then_some(bytes)
                        .ok_or(JwkError::Malformed(name))
                };
                Key::Ec {
                    curve,
                    x: coordinate("x")?,
                    y: coordinate("y")?,
                }
            }
            "RSA" => {
                let integer = |name| {
                    let bytes = base64url_member(members, name)?;
                    bytes
                        .first()
                        .is_some_and(|&first| first != 0)
                        .then_some(bytes)
                        .ok_or(JwkError::Malformed(name))
                };
                let n = integer("n")?;
                let bits = n.len() * 8 - n[0].leading_zeros() as usize;
                if bits < 2048 {
                    return Err(JwkError::RsaTooSmall(bits));
                }
                Key::Rsa {
                    n,
                    e: integer("e")?,
                }
            }
            "OKP" => match string(members, "crv")? {
                "Ed25519" => Key::Ed25519(
                    base64url_member(members, "x")?
                        .try_into()
                        .map_err(|_| JwkError::Malformed("x"))?,
                ),
                other => return Err(JwkError::Unsupported(format!("OKP {other}"))),
            },
            other => return Err(JwkError::Unsupported(other.to_owned())),
        };
        Ok(Self(key))
    }

    /// The one algorithm that suits the key (RFC 8555 §6.2).
    pub fn algorithm(&self) -> Algorithm {
        match &self.0 {
            Key::Ec { curve, .. } => curve.algorithm(),
            Key::Rsa { .. } => Algorithm::Rs256,
            Key::Ed25519(_) => Algorithm::EdDsa,
        }
    }

    /// The RFC 5280 SubjectPublicKeyInfo DER, to compare with a CSR's key.
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        verify::subject_public_key_info(self)
    }

    /// The RFC 7638 form: required members only, in lexicographic order, no whitespace; also the form to store.
    pub fn to_canonical_json(&self) -> String {
        match &self.0 {
            Key::Ec { curve, x, y } => format!(
                r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                curve.name(),
                encode(x),
                encode(y)
            ),
            Key::Rsa { n, e } => {
                format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, encode(e), encode(n))
            }
            Key::Ed25519(x) => format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, encode(x)),
        }
    }

    /// The RFC 7638 SHA-256 thumbprint in unpadded base64url.
    pub fn thumbprint(&self) -> String {
        encode(&Sha256::digest(self.to_canonical_json()))
    }
}

impl<'de> Deserialize<'de> for Jwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_value(&Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
