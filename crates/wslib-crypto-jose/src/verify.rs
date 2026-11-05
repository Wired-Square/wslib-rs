use rustls::pki_types::{AlgorithmIdentifier, SignatureVerificationAlgorithm, alg_id};

use crate::jwk::Key;
use crate::{Algorithm, Error, Jwk};

/// Verifies a JWS signature as `alg` has it, passing the key and signature to webpki-style verifiers in their DER forms.
pub(crate) fn signature(
    alg: Algorithm,
    key: &Jwk,
    message: &[u8],
    signature: &[u8],
    algorithms: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    if key.algorithm() != alg {
        return Err(Error::KeyMismatch(alg));
    }
    let signature = match &key.0 {
        Key::Ec { x, .. } => ecdsa_sig_value(signature, x.len())?,
        _ => signature.to_vec(),
    };
    let public_key = public_key(key);
    let (key_id, signature_id) = ids(alg);
    let mut matching = algorithms
        .iter()
        .filter(|verifier| {
            verifier.public_key_alg_id().as_ref() == key_id.as_ref()
                && verifier.signature_alg_id().as_ref() == signature_id.as_ref()
        })
        .peekable();
    if matching.peek().is_none() {
        return Err(Error::NoVerifier(alg));
    }
    if matching.any(|verifier| {
        verifier
            .verify_signature(&public_key, message, &signature)
            .is_ok()
    }) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

pub(crate) fn subject_public_key_info(key: &Jwk) -> Vec<u8> {
    let (key_id, _) = ids(key.algorithm());
    sequence(&[
        tlv(0x30, key_id.as_ref()),
        tlv(0x03, &[&[0][..], &public_key(key)].concat()),
    ])
}

/// The key as a SubjectPublicKeyInfo's BIT STRING holds it.
fn public_key(key: &Jwk) -> Vec<u8> {
    match &key.0 {
        Key::Ec { x, y, .. } => [&[0x04][..], x, y].concat(),
        Key::Rsa { n, e } => sequence(&[integer(n), integer(e)]),
        Key::Ed25519(x) => x.to_vec(),
    }
}

fn ids(alg: Algorithm) -> (AlgorithmIdentifier, AlgorithmIdentifier) {
    match alg {
        Algorithm::Es256 => (alg_id::ECDSA_P256, alg_id::ECDSA_SHA256),
        Algorithm::Es384 => (alg_id::ECDSA_P384, alg_id::ECDSA_SHA384),
        Algorithm::Rs256 => (alg_id::RSA_ENCRYPTION, alg_id::RSA_PKCS1_SHA256),
        Algorithm::EdDsa => (alg_id::ED25519, alg_id::ED25519),
    }
}

/// RFC 7518 §3.4's R || S as RFC 3279's ECDSA-Sig-Value.
fn ecdsa_sig_value(raw: &[u8], coordinate_len: usize) -> Result<Vec<u8>, Error> {
    if raw.len() != 2 * coordinate_len {
        return Err(Error::BadSignature);
    }
    let (r, s) = raw.split_at(coordinate_len);
    Ok(sequence(&[integer(r), integer(s)]))
}

fn integer(unsigned: &[u8]) -> Vec<u8> {
    let start = unsigned
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(unsigned.len());
    let trimmed = &unsigned[start..];
    let sign = if trimmed.first().is_none_or(|byte| byte & 0x80 != 0) {
        &[0][..]
    } else {
        &[]
    };
    tlv(0x02, &[sign, trimmed].concat())
}

fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(content.len()) {
        Ok(len) if len < 0x80 => out.push(len),
        _ => {
            let len = content.len().to_be_bytes();
            let start = len.iter().position(|&byte| byte != 0).unwrap_or(len.len());
            out.push(0x80 | (len.len() - start) as u8);
            out.extend_from_slice(&len[start..]);
        }
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_minimal_and_positive() {
        assert_eq!(integer(&[0, 0, 0x7f]), [0x02, 1, 0x7f]);
        assert_eq!(integer(&[0x80]), [0x02, 2, 0, 0x80]);
        assert_eq!(integer(&[0, 0]), [0x02, 1, 0]);
    }

    #[test]
    fn long_lengths_take_the_long_form() {
        assert_eq!(tlv(0x30, &[0; 0x7f])[..2], [0x30, 0x7f]);
        assert_eq!(tlv(0x30, &[0; 0x80])[..3], [0x30, 0x81, 0x80]);
        assert_eq!(tlv(0x30, &[0; 0x101])[..4], [0x30, 0x82, 0x01, 0x01]);
    }
}
