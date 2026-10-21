//! Whether a signature over a message is a public key's, with the signature
//! algorithms of the caller's crypto provider.

use std::fmt;

use rustls_pki_types::SignatureVerificationAlgorithm;
use x509_parser::asn1_rs::{Any, BitString, FromDer, Tag};

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureError {
    /// None of the algorithms is for this key with this signature algorithm.
    NoAlgorithm,
    /// The signature is not the key's over the message.
    BadSignature,
    /// The SubjectPublicKeyInfo or AlgorithmIdentifier does not decode.
    Malformed(&'static str),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAlgorithm => {
                f.write_str("no signature algorithm offered is for this key and signature")
            }
            Self::BadSignature => f.write_str("the signature does not verify with the key"),
            Self::Malformed(what) => write!(f, "the {what} does not decode"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Verifies `signature` over `message` with the key of `spki` by `signature_algorithm`.
///
/// `spki` is a DER SubjectPublicKeyInfo, such as [`CertificateView::spki`](crate::CertificateView::spki);
/// `signature_algorithm` a DER AlgorithmIdentifier, compared byte for byte.
/// Those of `algorithms` (as `provider.signature_verification_algorithms.all`)
/// for both the key's algorithm and the signature algorithm are tried.
pub fn verify(
    spki: &[u8],
    signature_algorithm: &[u8],
    message: &[u8],
    signature: &[u8],
    algorithms: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), SignatureError> {
    let malformed_key = SignatureError::Malformed("SubjectPublicKeyInfo");
    let Some((info, [])) = sequence(spki) else {
        return Err(malformed_key);
    };
    let Some((key_algorithm, key)) = sequence(info) else {
        return Err(malformed_key);
    };
    let key = match BitString::from_der(key) {
        Ok(([], key)) if key.unused_bits == 0 => key.data,
        _ => return Err(malformed_key),
    };
    let Some((signature_algorithm, [])) = sequence(signature_algorithm) else {
        return Err(SignatureError::Malformed("AlgorithmIdentifier"));
    };

    let mut matching = algorithms
        .iter()
        .filter(|algorithm| {
            algorithm.public_key_alg_id().as_ref() == key_algorithm
                && algorithm.signature_alg_id().as_ref() == signature_algorithm
        })
        .peekable();
    if matching.peek().is_none() {
        return Err(SignatureError::NoAlgorithm);
    }
    if matching.any(|algorithm| algorithm.verify_signature(&key, message, signature).is_ok()) {
        Ok(())
    } else {
        Err(SignatureError::BadSignature)
    }
}

/// The contents of the DER SEQUENCE at the start of `der`, and what follows it.
fn sequence(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (rest, any) = Any::from_der(der).ok()?;
    (any.tag() == Tag::Sequence).then_some((any.data, rest))
}
