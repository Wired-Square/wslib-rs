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
    let (public_key, signature) = match (alg, &key.0) {
        (_, Key::Ec { curve, x, y }) if curve.algorithm() == alg => {
            (ec_point(x, y), ecdsa_sig_value(signature, x.len())?)
        }
        (Algorithm::Rs256, Key::Rsa { n, e }) => {
            let bits = n.len() * 8 - n[0].leading_zeros() as usize;
            if bits < 2048 {
                return Err(Error::RsaTooSmall(bits));
            }
            (sequence(&[integer(n), integer(e)]), signature.to_vec())
        }
        (Algorithm::EdDsa, Key::Ed25519(x)) => (x.to_vec(), signature.to_vec()),
        _ => return Err(Error::KeyMismatch(alg)),
    };
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

fn ids(alg: Algorithm) -> (AlgorithmIdentifier, AlgorithmIdentifier) {
    match alg {
        Algorithm::Es256 => (alg_id::ECDSA_P256, alg_id::ECDSA_SHA256),
        Algorithm::Es384 => (alg_id::ECDSA_P384, alg_id::ECDSA_SHA384),
        Algorithm::Rs256 => (alg_id::RSA_ENCRYPTION, alg_id::RSA_PKCS1_SHA256),
        Algorithm::EdDsa => (alg_id::ED25519, alg_id::ED25519),
    }
}

fn ec_point(x: &[u8], y: &[u8]) -> Vec<u8> {
    [&[0x04][..], x, y].concat()
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
