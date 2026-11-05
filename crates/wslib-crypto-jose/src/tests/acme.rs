use std::collections::HashSet;
use std::sync::OnceLock;

use rustls::SignatureScheme;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::Signer;
use wslib_crypto::KeyAlgorithm;

use super::providers;
use super::rfc::{RFC_8037_A4_SIGNATURE, RFC_8037_A4_SIGNING_INPUT};
use crate::base64url::{decode, encode};
use crate::{Algorithm, Error, FlattenedJws, Jwk, KeyRef};

const ALGORITHMS: [Algorithm; 4] = [
    Algorithm::Es256,
    Algorithm::Es384,
    Algorithm::Rs256,
    Algorithm::EdDsa,
];

const URL: &str = "https://ca.test/acme/new-order";

/// RFC 8410's PKCS#8 for an Ed25519 seed, before the seed's 32 bytes.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const RFC_8037_A1_SEED: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

fn pkcs8(alg: Algorithm) -> PrivatePkcs8KeyDer<'static> {
    static KEYS: [OnceLock<Vec<u8>>; 4] = [const { OnceLock::new() }; 4];
    let generate =
        |algorithm: KeyAlgorithm| algorithm.generate().unwrap().secret_pkcs8_der().to_vec();
    let index = ALGORITHMS.iter().position(|each| *each == alg).unwrap();
    KEYS[index]
        .get_or_init(|| match alg {
            Algorithm::Es256 => generate(KeyAlgorithm::EcP256),
            Algorithm::Es384 => generate(KeyAlgorithm::EcP384),
            Algorithm::Rs256 => generate(KeyAlgorithm::Rsa2048),
            _ => [
                &ED25519_PKCS8_PREFIX[..],
                &decode(RFC_8037_A1_SEED).unwrap(),
            ]
            .concat(),
        })
        .clone()
        .into()
}

struct TestKey {
    alg: Algorithm,
    signer: Box<dyn Signer>,
    jwk: Jwk,
}

impl TestKey {
    fn new(alg: Algorithm, provider: &CryptoProvider) -> Self {
        let signing = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(pkcs8(alg)))
            .unwrap();
        let scheme = match alg {
            Algorithm::Es256 => SignatureScheme::ECDSA_NISTP256_SHA256,
            Algorithm::Es384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            Algorithm::Rs256 => SignatureScheme::RSA_PKCS1_SHA256,
            _ => SignatureScheme::ED25519,
        };
        Self {
            alg,
            jwk: jwk_of_spki(alg, &signing.public_key().unwrap()),
            signer: signing.choose_scheme(&[scheme]).unwrap(),
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signer.sign(message).unwrap();
        match self.alg {
            Algorithm::Es256 => raw_ecdsa(&signature, 32),
            Algorithm::Es384 => raw_ecdsa(&signature, 48),
            _ => signature,
        }
    }

    fn header(&self) -> String {
        format!(
            r#"{{"alg":"{}","nonce":"bm9uY2U","url":"{URL}","jwk":{}}}"#,
            self.alg,
            self.jwk.to_canonical_json()
        )
    }

    /// The base64url protected header, payload and signature.
    fn parts(&self, header: &str, payload: &[u8]) -> [String; 3] {
        let (protected, payload) = (encode(header.as_bytes()), encode(payload));
        let signature = encode(&self.sign(format!("{protected}.{payload}").as_bytes()));
        [protected, payload, signature]
    }

    fn jws(&self, header: &str, payload: &[u8]) -> String {
        assemble(&self.parts(header, payload))
    }
}

fn assemble([protected, payload, signature]: &[String; 3]) -> String {
    format!(r#"{{"protected":"{protected}","payload":"{payload}","signature":"{signature}"}}"#)
}

fn jwk_of_spki(alg: Algorithm, spki: &[u8]) -> Jwk {
    let (info, _) = der(spki);
    let (_, key) = der(info);
    let key = &der(key).0[1..];
    let json = match alg {
        Algorithm::Es256 | Algorithm::Es384 => {
            let (x, y) = key[1..].split_at(key.len() / 2);
            let crv = if alg == Algorithm::Es256 {
                "P-256"
            } else {
                "P-384"
            };
            format!(
                r#"{{"kty":"EC","crv":"{crv}","x":"{}","y":"{}"}}"#,
                encode(x),
                encode(y)
            )
        }
        Algorithm::Rs256 => {
            let (n, rest) = der(der(key).0);
            let (e, _) = der(rest);
            let (n, e) = (encode(unsigned(n)), encode(unsigned(e)));
            format!(r#"{{"kty":"RSA","n":"{n}","e":"{e}"}}"#)
        }
        _ => format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#, encode(key)),
    };
    Jwk::from_json(&json).unwrap()
}

/// The contents of the DER element at the start of `input`, and what follows it.
fn der(input: &[u8]) -> (&[u8], &[u8]) {
    let (len, header) = match input[1] {
        short @ 0..0x80 => (usize::from(short), 2),
        long => {
            let count = usize::from(long & 0x7f);
            let len = input[2..2 + count]
                .iter()
                .fold(0, |len, &byte| len << 8 | usize::from(byte));
            (len, 2 + count)
        }
    };
    input[header..].split_at(len)
}

fn unsigned(integer: &[u8]) -> &[u8] {
    &integer[integer
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(integer.len())..]
}

fn raw_ecdsa(signature: &[u8], coordinate_len: usize) -> Vec<u8> {
    let (r, rest) = der(der(signature).0);
    let (s, _) = der(rest);
    [r, s]
        .iter()
        .flat_map(|integer| {
            let integer = unsigned(integer);
            std::iter::repeat_n(0, coordinate_len - integer.len()).chain(integer.iter().copied())
        })
        .collect()
}

fn each_key(test: impl Fn(&TestKey, &CryptoProvider)) {
    for (signing_name, signing) in providers() {
        for alg in ALGORITHMS {
            let key = TestKey::new(alg, &signing);
            for (verifying_name, verifying) in providers() {
                eprintln!("{alg} signed by {signing_name}, verified by {verifying_name}");
                test(&key, &verifying);
            }
        }
    }
}

fn parse_with_header(header: &str) -> Result<FlattenedJws, Error> {
    let protected = encode(header.as_bytes());
    FlattenedJws::parse(assemble(&[protected, String::new(), "AAAA".into()]).as_bytes())
}

#[test]
fn each_algorithm_verifies_with_its_header_through_both_providers() {
    each_key(|key, provider| {
        let jws = FlattenedJws::parse(key.jws(&key.header(), br#"{"a":1}"#).as_bytes()).unwrap();
        let header = jws.header();
        assert_eq!(header.alg, key.alg);
        assert_eq!(header.nonce.as_deref(), Some("bm9uY2U"));
        assert_eq!(header.url, URL);
        assert_eq!(header.key, KeyRef::Jwk(key.jwk.clone()));
        assert_eq!(jws.payload(), br#"{"a":1}"#);
        jws.verify(&key.jwk, provider).unwrap();
    });
}

#[test]
fn a_tampered_protected_header_payload_or_signature_fails() {
    each_key(|key, provider| {
        let parts = key.parts(&key.header(), b"{}");
        let mut flipped = decode(&parts[2]).unwrap();
        flipped[10] ^= 1;
        let tampered = [
            [
                encode(key.header().replace("new-order", "new-acct").as_bytes()),
                parts[1].clone(),
                parts[2].clone(),
            ],
            [parts[0].clone(), encode(b"{ }"), parts[2].clone()],
            [parts[0].clone(), parts[1].clone(), encode(&flipped)],
        ];
        for parts in tampered {
            let jws = FlattenedJws::parse(assemble(&parts).as_bytes()).unwrap();
            assert!(matches!(
                jws.verify(&key.jwk, provider),
                Err(Error::BadSignature)
            ));
        }
    });
}

#[test]
fn an_algorithm_that_does_not_suit_the_key_is_refused() {
    let provider = ring::default_provider();
    let keys = ALGORITHMS.map(|alg| TestKey::new(alg, &provider));
    for signer in &keys {
        let jws = FlattenedJws::parse(signer.jws(&signer.header(), b"").as_bytes()).unwrap();
        for other in keys.iter().filter(|other| other.alg != signer.alg) {
            assert!(matches!(
                jws.verify(&other.jwk, &provider),
                Err(Error::KeyMismatch(alg)) if alg == signer.alg
            ));
        }
    }
}

#[test]
fn an_rsa_key_under_2048_bits_is_refused() {
    for (first, len, bits) in [(0xc0, 128, 1024), (0x7f, 256, 2047)] {
        let n = encode(&[vec![first], vec![0xff; len - 1]].concat());
        let header = format!(
            r#"{{"alg":"RS256","url":"{URL}","jwk":{{"kty":"RSA","n":"{n}","e":"AQAB"}}}}"#
        );
        let jws = parse_with_header(&header).unwrap();
        let KeyRef::Jwk(key) = &jws.header().key else {
            unreachable!()
        };
        assert!(matches!(
            jws.verify(key, &ring::default_provider()),
            Err(Error::RsaTooSmall(found)) if found == bits
        ));
    }
}

#[test]
fn a_provider_without_the_algorithm_is_told_apart() {
    let provider = CryptoProvider {
        signature_verification_algorithms: WebPkiSupportedAlgorithms {
            all: &[],
            mapping: &[],
        },
        ..ring::default_provider()
    };
    let key = TestKey::new(Algorithm::Es256, &ring::default_provider());
    let jws = FlattenedJws::parse(key.jws(&key.header(), b"").as_bytes()).unwrap();
    assert!(matches!(
        jws.verify(&key.jwk, &provider),
        Err(Error::NoVerifier(Algorithm::Es256))
    ));
}

#[test]
fn an_ecdsa_signature_of_the_wrong_length_fails() {
    let provider = ring::default_provider();
    let key = TestKey::new(Algorithm::Es256, &provider);
    let mut parts = key.parts(&key.header(), b"");
    parts[2] = encode(&[decode(&parts[2]).unwrap(), vec![0]].concat());
    let jws = FlattenedJws::parse(assemble(&parts).as_bytes()).unwrap();
    assert!(matches!(
        jws.verify(&key.jwk, &provider),
        Err(Error::BadSignature)
    ));
}

#[test]
fn an_empty_payload_is_a_post_as_get_that_verifies() {
    each_key(|key, provider| {
        let header = format!(
            r#"{{"alg":"{}","nonce":"bm9uY2U","url":"{URL}","kid":"https://ca.test/acme/acct/1"}}"#,
            key.alg
        );
        let jws = FlattenedJws::parse(key.jws(&header, b"").as_bytes()).unwrap();
        assert_eq!(jws.payload(), b"");
        assert_eq!(
            jws.header().key,
            KeyRef::Kid("https://ca.test/acme/acct/1".into())
        );
        jws.verify(&key.jwk, provider).unwrap();
    });
}

#[test]
fn the_ed25519_test_key_signs_as_rfc_8037_a4_does() {
    for (_, provider) in providers() {
        let key = TestKey::new(Algorithm::EdDsa, &provider);
        assert_eq!(
            key.sign(RFC_8037_A4_SIGNING_INPUT.as_bytes()),
            decode(RFC_8037_A4_SIGNATURE).unwrap()
        );
    }
}

#[test]
fn jwk_and_kid_together_or_neither_is_refused() {
    let jwk = TestKey::new(Algorithm::EdDsa, &ring::default_provider())
        .jwk
        .to_canonical_json();
    let both =
        format!(r#"{{"alg":"EdDSA","url":"{URL}","jwk":{jwk},"kid":"https://ca.test/a/1"}}"#);
    assert!(matches!(
        parse_with_header(&both),
        Err(Error::BothJwkAndKid)
    ));
    let neither = format!(r#"{{"alg":"EdDSA","url":"{URL}"}}"#);
    assert!(matches!(
        parse_with_header(&neither),
        Err(Error::NeitherJwkNorKid)
    ));
}

#[test]
fn none_hmac_and_unlisted_algorithms_are_refused() {
    for alg in ["none", "HS256", "PS256", "ES512", "es256"] {
        let header = format!(r#"{{"alg":"{alg}","url":"{URL}","kid":"https://ca.test/a/1"}}"#);
        assert!(matches!(
            parse_with_header(&header),
            Err(Error::UnsupportedAlgorithm(found)) if found == alg
        ));
    }
}

#[test]
fn a_critical_extension_is_refused() {
    let header = format!(r#"{{"alg":"ES256","url":"{URL}","kid":"k","crit":["b64"],"b64":false}}"#);
    assert!(matches!(parse_with_header(&header), Err(Error::Critical)));
}

#[test]
fn url_is_required_and_nonce_is_not() {
    let missing_url = r#"{"alg":"ES256","nonce":"bm9uY2U","kid":"k"}"#;
    assert!(matches!(
        parse_with_header(missing_url),
        Err(Error::Missing("url"))
    ));
    let inner = format!(r#"{{"alg":"ES256","url":"{URL}","kid":"k","typ":"ignored"}}"#);
    assert_eq!(parse_with_header(&inner).unwrap().header().nonce, None);
}

#[test]
fn padding_and_the_standard_alphabet_are_refused() {
    let key = TestKey::new(Algorithm::Es256, &ring::default_provider());
    let parts = key.parts(&key.header(), b"{}");
    for (index, member) in ["protected", "payload", "signature"]
        .into_iter()
        .enumerate()
    {
        for bad in [format!("{}=", parts[index]), format!("{}+/", parts[index])] {
            let mut tampered = parts.clone();
            tampered[index] = bad;
            assert!(matches!(
                FlattenedJws::parse(assemble(&tampered).as_bytes()),
                Err(Error::Malformed(found)) if found == member
            ));
        }
    }
}

#[test]
fn an_unprotected_header_or_general_serialisation_is_refused() {
    let key = TestKey::new(Algorithm::Es256, &ring::default_provider());
    let jws = key.jws(&key.header(), b"{}");
    for member in [r#""header":{}"#, r#""signatures":[]"#] {
        let json = jws.replacen('{', &format!("{{{member},"), 1);
        assert!(matches!(
            FlattenedJws::parse(json.as_bytes()),
            Err(Error::UnexpectedMember(_))
        ));
    }
}

#[test]
fn a_private_key_in_the_header_is_refused() {
    let jwk = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#;
    let header = format!(r#"{{"alg":"EdDSA","url":"{URL}","jwk":{jwk}}}"#);
    assert!(matches!(parse_with_header(&header), Err(Error::PrivateKey)));
}

#[test]
fn keys_equal_by_canonical_form_whatever_the_order_and_extra_members() {
    let key = TestKey::new(Algorithm::Es384, &ring::default_provider()).jwk;
    let canonical = key.to_canonical_json();
    let members: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&canonical).unwrap();
    let reordered = format!(
        r#"{{ "y": {}, "use": "sig", "x": {}, "kid": "k1", "kty": "EC", "key_ops": ["verify"], "crv": "P-384", "alg": "ES384" }}"#,
        members["y"], members["x"]
    );
    let other = Jwk::from_json(&reordered).unwrap();
    assert_eq!(other, key);
    assert_eq!(other.to_canonical_json(), canonical);
    assert_eq!(other.thumbprint(), key.thumbprint());
    assert_eq!(HashSet::from([key.clone(), other]).len(), 1);
    assert_eq!(Jwk::from_json(&canonical).unwrap(), key);
    assert_eq!(serde_json::from_str::<Jwk>(&canonical).unwrap(), key);
}

#[test]
fn malformed_key_members_are_refused() {
    let x32 = encode(&[1; 32]);
    let x31 = encode(&[1; 31]);
    for (json, member) in [
        (
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{x31}","y":"{x32}"}}"#),
            "x",
        ),
        (
            format!(r#"{{"kty":"EC","crv":"P-384","x":"{x32}","y":"{x32}"}}"#),
            "x",
        ),
        (r#"{"kty":"RSA","n":"AAEB","e":"AQAB"}"#.to_owned(), "n"),
        (r#"{"kty":"RSA","n":"AQAB","e":""}"#.to_owned(), "e"),
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x31}"}}"#),
            "x",
        ),
        (r#"{"kty":"OKP","crv":"Ed25519","x":7}"#.to_owned(), "x"),
    ] {
        assert!(
            matches!(Jwk::from_json(&json), Err(Error::Malformed(found)) if found == member),
            "{json}"
        );
    }
    assert!(matches!(
        Jwk::from_json(r#"{"kty":"oct"}"#),
        Err(Error::UnsupportedKey(_))
    ));
    assert!(matches!(
        Jwk::from_json(r#"{"kty":"OKP","crv":"Ed448","x":""}"#),
        Err(Error::UnsupportedKey(_))
    ));
}
