//! A credential's public key as COSE_Key (RFC 9052, 9053): ES256 on P-256 or
//! EdDSA on Ed25519, the two algorithms a registration offers.

use super::cbor::{Malformed, Value};

pub(crate) const ES256: i32 = -7;
pub(crate) const EDDSA: i32 = -8;

const KTY: Value = Value::Int(1);
const ALG: Value = Value::Int(3);
const CRV: Value = Value::Int(-1);
const X: Value = Value::Int(-2);
const Y: Value = Value::Int(-3);
const D: Value = Value::Int(-4);

const KTY_OKP: i128 = 1;
const KTY_EC2: i128 = 2;
const CRV_P256: i128 = 1;
const CRV_ED25519: i128 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PublicKey {
    Es256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    /// A key of one of the two algorithms, whole, and a point on its curve.
    pub(crate) fn from_cose(key: &Value<'_>) -> Result<Self, Malformed> {
        let int = |label| match key.get(label) {
            Some(Value::Int(n)) => Ok(*n),
            _ => Err(Malformed("a COSE key without an integer kty, alg or crv")),
        };
        let coordinate = |label| match key.get(label) {
            Some(Value::Bytes(b)) => <[u8; 32]>::try_from(*b)
                .map_err(|_| Malformed("a COSE coordinate that is not 32 bytes")),
            _ => Err(Malformed("a COSE key without its coordinates")),
        };
        if !matches!(key, Value::Map(_)) {
            return Err(Malformed("a COSE key that is not a map"));
        }
        if key.get(&D).is_some() {
            return Err(Malformed("a COSE key that carries its private half"));
        }
        match (int(&KTY)?, int(&ALG)?, int(&CRV)?) {
            (KTY_EC2, alg, CRV_P256) if alg == i128::from(ES256) => {
                let mut point = [0x04; 65];
                point[1..33].copy_from_slice(&coordinate(&X)?);
                point[33..].copy_from_slice(&coordinate(&Y)?);
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map(Self::Es256)
                    .map_err(|_| Malformed("a P-256 point that is not on the curve"))
            }
            (KTY_OKP, alg, CRV_ED25519) if alg == i128::from(EDDSA) => {
                if key.get(&Y).is_some() {
                    return Err(Malformed("an Ed25519 key with a y coordinate"));
                }
                ed25519_dalek::VerifyingKey::from_bytes(&coordinate(&X)?)
                    .map(Self::Ed25519)
                    .map_err(|_| Malformed("an Ed25519 key that is not a point on the curve"))
            }
            _ => Err(Malformed(
                "a key that is neither ES256 on P-256 nor EdDSA on Ed25519",
            )),
        }
    }

    /// An ES256 signature is ASN.1 DER (WebAuthn §6.5.6); an Ed25519 one is
    /// checked strictly, refusing a non-canonical signature or a weak key.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Es256(key) => p256::ecdsa::DerSignature::try_from(signature)
                .and_then(|signature| {
                    p256::ecdsa::signature::Verifier::verify(key, message, &signature)
                })
                .is_ok(),
            Self::Ed25519(key) => ed25519_dalek::Signature::from_slice(signature)
                .and_then(|signature| key.verify_strict(message, &signature))
                .is_ok(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::cbor::{decode, encode};
    use super::*;

    fn ec2(alg: i64, crv: i64, x: &[u8], y: &[u8]) -> Vec<u8> {
        encode::map(&[
            (encode::int(1), encode::int(2)),
            (encode::int(3), encode::int(alg)),
            (encode::int(-1), encode::int(crv)),
            (encode::int(-2), encode::bytes(x)),
            (encode::int(-3), encode::bytes(y)),
        ])
    }

    fn okp(alg: i64, crv: i64, x: &[u8]) -> Vec<u8> {
        encode::map(&[
            (encode::int(1), encode::int(1)),
            (encode::int(3), encode::int(alg)),
            (encode::int(-1), encode::int(crv)),
            (encode::int(-2), encode::bytes(x)),
        ])
    }

    /// The Ed25519 base point, compressed.
    pub(crate) const ED25519_BASE: [u8; 32] = {
        let mut point = [0x66; 32];
        point[0] = 0x58;
        point
    };

    fn parsed(key: &[u8]) -> Result<PublicKey, &'static str> {
        PublicKey::from_cose(&decode(key).expect("CBOR")).map_err(|e| e.0)
    }

    /// The P-256 generator, a point that is certainly on the curve.
    const GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn an_es256_key_on_the_curve_is_taken() {
        let key = parsed(&ec2(-7, 1, &hex(GX), &hex(GY))).expect("the generator");
        let PublicKey::Es256(key) = key else {
            panic!("{key:?}")
        };
        let point = key.to_encoded_point(false);
        assert_eq!(point.x().map(|x| x.to_vec()), Some(hex(GX)));
    }

    #[test]
    fn a_point_off_the_curve_is_refused() {
        let mut y = hex(GY);
        y[31] ^= 1;
        assert_eq!(
            parsed(&ec2(-7, 1, &hex(GX), &y)),
            Err("a P-256 point that is not on the curve")
        );
    }

    #[test]
    fn an_unsupported_algorithm_or_curve_is_refused() {
        let wrong = Err("a key that is neither ES256 on P-256 nor EdDSA on Ed25519");
        assert_eq!(parsed(&ec2(-35, 2, &hex(GX), &hex(GY))), wrong, "ES384");
        assert_eq!(parsed(&ec2(-7, 2, &hex(GX), &hex(GY))), wrong, "P-384");
        assert_eq!(parsed(&okp(-8, 7, &[1; 32])), wrong, "Ed448");
        assert_eq!(parsed(&okp(-7, 6, &[1; 32])), wrong, "ES256 on Ed25519");
        let rsa = encode::map(&[
            (encode::int(1), encode::int(3)),
            (encode::int(3), encode::int(-257)),
            (encode::int(-1), encode::bytes(&[1; 256])),
        ]);
        assert_eq!(
            parsed(&rsa),
            Err("a COSE key without an integer kty, alg or crv")
        );
    }

    #[test]
    fn an_ed25519_key_is_a_point_on_the_curve() {
        let key = parsed(&okp(-8, 6, &ED25519_BASE)).expect("the base point");
        assert!(matches!(key, PublicKey::Ed25519(_)), "{key:?}");
        let off = (0..=u8::MAX)
            .map(|first| {
                let mut y = ED25519_BASE;
                y[0] = first;
                y
            })
            .find(|y| ed25519_dalek::VerifyingKey::from_bytes(y).is_err())
            .expect("about half of all y have no x");
        assert_eq!(
            parsed(&okp(-8, 6, &off)),
            Err("an Ed25519 key that is not a point on the curve")
        );
    }

    #[test]
    fn a_short_coordinate_or_a_private_half_is_refused() {
        assert_eq!(
            parsed(&ec2(-7, 1, &hex(GX)[1..], &hex(GY))),
            Err("a COSE coordinate that is not 32 bytes")
        );
        assert_eq!(
            parsed(&okp(-8, 6, &[1; 33])),
            Err("a COSE coordinate that is not 32 bytes")
        );
        let with_d = encode::map(&[
            (encode::int(1), encode::int(1)),
            (encode::int(3), encode::int(-8)),
            (encode::int(-1), encode::int(6)),
            (encode::int(-2), encode::bytes(&[1; 32])),
            (encode::int(-4), encode::bytes(&[2; 32])),
        ]);
        assert_eq!(
            parsed(&with_d),
            Err("a COSE key that carries its private half")
        );
    }
}
