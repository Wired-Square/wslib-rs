//! Keys for X.509 through the caller's rustls [`CryptoProvider`](rustls::crypto::CryptoProvider):
//! this crate generates keys in pure Rust, and the provider signs with them,
//! verifies and supplies randomness. No provider is enabled here.
//!
//! **RSA generation blocks** for seconds (RSA-4096 has taken over eight); on an
//! async runtime call [`KeyAlgorithm::generate`] from `spawn_blocking`.

use std::fmt;
use std::str::FromStr;

use pkcs8::der::Decode;
use pkcs8::spki::SubjectPublicKeyInfoRef;
use pkcs8::{EncodePrivateKey, ObjectIdentifier};
use rand_core::OsRng;
use rustls::SignatureScheme;
use rustls_pki_types::PrivatePkcs8KeyDer;

mod fingerprint;
mod random;
mod signer;

pub use fingerprint::Fingerprint;
pub use random::{random, random_default, random_serial};
pub use signer::{Signer, key_identifier, key_matches};

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The keys this crate generates and signs with, each with one signature scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    EcP256,
    EcP384,
    Rsa2048,
    Rsa4096,
}

impl KeyAlgorithm {
    pub const ALL: [Self; 4] = [Self::EcP256, Self::EcP384, Self::Rsa2048, Self::Rsa4096];

    /// `ec-p256`, `ec-p384`, `rsa-2048` or `rsa-4096`, as [`FromStr`] reads it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcP256 => "ec-p256",
            Self::EcP384 => "ec-p384",
            Self::Rsa2048 => "rsa-2048",
            Self::Rsa4096 => "rsa-4096",
        }
    }

    /// The one scheme a [`Signer`] offers: ECDSA with SHA-256 or SHA-384 by curve, RSA PKCS#1 with SHA-256.
    pub fn signature_scheme(self) -> SignatureScheme {
        match self {
            Self::EcP256 => SignatureScheme::ECDSA_NISTP256_SHA256,
            Self::EcP384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            Self::Rsa2048 | Self::Rsa4096 => SignatureScheme::RSA_PKCS1_SHA256,
        }
    }

    fn rcgen(self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            Self::EcP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            Self::EcP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            Self::Rsa2048 | Self::Rsa4096 => &rcgen::PKCS_RSA_SHA256,
        }
    }

    /// A new private key, as PKCS#8 DER. Blocks: RSA takes seconds.
    pub fn generate(self) -> Result<PrivatePkcs8KeyDer<'static>, Error> {
        let failed = |e: &dyn fmt::Display| Error::Generate(e.to_string());
        let rsa = |bits| rsa::RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| failed(&e));
        let document = match self {
            Self::EcP256 => p256::SecretKey::random(&mut OsRng).to_pkcs8_der(),
            Self::EcP384 => p384::SecretKey::random(&mut OsRng).to_pkcs8_der(),
            Self::Rsa2048 => rsa(2048)?.to_pkcs8_der(),
            Self::Rsa4096 => rsa(4096)?.to_pkcs8_der(),
        }
        .map_err(|e| failed(&e))?;
        Ok(PrivatePkcs8KeyDer::from(document.as_bytes().to_vec()))
    }

    /// The algorithm of a DER SubjectPublicKeyInfo, when it is one of these four.
    pub fn of_spki(spki: &[u8]) -> Option<Self> {
        let info = SubjectPublicKeyInfoRef::from_der(spki).ok()?;
        let oid = info.algorithm.oid;
        if oid == EC_PUBLIC_KEY {
            let curve = info.algorithm.parameters_oid().ok()?;
            return [(SECP256R1, Self::EcP256), (SECP384R1, Self::EcP384)]
                .into_iter()
                .find_map(|(known, algorithm)| (curve == known).then_some(algorithm));
        }
        if oid != RSA_ENCRYPTION {
            return None;
        }
        let key = rsa::pkcs1::RsaPublicKey::from_der(info.subject_public_key.as_bytes()?).ok()?;
        match modulus_bits(key.modulus.as_bytes())? {
            2048 => Some(Self::Rsa2048),
            4096 => Some(Self::Rsa4096),
            _ => None,
        }
    }
}

fn modulus_bits(modulus: &[u8]) -> Option<u32> {
    let first = *modulus.first()?;
    Some((u32::try_from(modulus.len()).ok()? - 1) * 8 + (8 - first.leading_zeros()))
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KeyAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| Error::UnknownAlgorithm(s.to_string()))
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Generating a key failed.
    Generate(String),
    /// The provider would not load the key.
    Load(rustls::Error),
    /// Not a P-256, P-384, RSA-2048 or RSA-4096 key.
    Unsupported,
    /// The provider's key does not offer the scheme its algorithm signs with.
    NoScheme(KeyAlgorithm),
    /// The provider gives no public key, and the key is not a PKCS#8 one this crate can read it from.
    NoPublicKey,
    /// The provider's random number generator failed.
    Random,
    /// No process-default provider is installed.
    NoProvider,
    UnknownAlgorithm(String),
    NotAFingerprint,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generate(e) => write!(f, "generating a key: {e}"),
            Self::Load(e) => write!(f, "the crypto provider will not load the key: {e}"),
            Self::Unsupported => f.write_str("not a P-256, P-384, RSA-2048 or RSA-4096 key"),
            Self::NoScheme(algorithm) => write!(
                f,
                "the key does not offer {:?}, which {algorithm} signs with",
                algorithm.signature_scheme()
            ),
            Self::NoPublicKey => {
                f.write_str("neither the crypto provider nor the key gives its public key")
            }
            Self::Random => f.write_str("the crypto provider's random number generator failed"),
            Self::NoProvider => f.write_str("no default crypto provider is installed"),
            Self::UnknownAlgorithm(s) => write!(
                f,
                "unknown key algorithm {s:?}; expected ec-p256, ec-p384, rsa-2048 or rsa-4096"
            ),
            Self::NotAFingerprint => {
                f.write_str("a SHA-256 fingerprint is 64 hex digits, colons optional")
            }
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_modulus_is_measured_in_bits_not_bytes() {
        let mut modulus = [0x42u8; 256];
        modulus[0] = 0x80;
        assert_eq!(modulus_bits(&modulus), Some(2048));
        modulus[0] = 0x7f;
        assert_eq!(modulus_bits(&modulus), Some(2047));
        assert_eq!(modulus_bits(&[]), None);
    }

    #[test]
    fn names_round_trip_in_any_case() {
        for algorithm in KeyAlgorithm::ALL {
            assert_eq!(
                algorithm.to_string().parse::<KeyAlgorithm>().unwrap(),
                algorithm
            );
        }
        assert_eq!(
            "EC-P384".parse::<KeyAlgorithm>().unwrap(),
            KeyAlgorithm::EcP384
        );
        assert!("ed25519".parse::<KeyAlgorithm>().is_err());
    }
}
