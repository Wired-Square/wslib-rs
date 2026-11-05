use super::providers;
use crate::{Algorithm, Error, FlattenedJws, Jwk, base64url, verify};

const RFC_7515_PAYLOAD: &str = concat!(
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
);

const RFC_7515_A2_N: &str = concat!(
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
    "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
    "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
    "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
    "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
    "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
);

const RFC_7515_A2_SIGNATURE: &str = concat!(
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7",
    "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4",
    "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K",
    "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv",
    "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB",
    "p0igcN_IoypGlUPQGe77Rw",
);

const RFC_7515_A3_JWK: &str = r#"{"kty":"EC","crv":"P-256",
    "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

const RFC_7515_A3_SIGNATURE: &str = concat!(
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA",
    "pmWQxfKTUJqPP3-Kg6NU1Q",
);

const RFC_8037_A2_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

pub(super) const RFC_8037_A4_SIGNING_INPUT: &str =
    "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";

pub(super) const RFC_8037_A4_SIGNATURE: &str = concat!(
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt",
    "9g7sVvpAr_MuM0KAg",
);

fn rfc_7515_a2_jwk() -> Jwk {
    Jwk::from_json(&format!(
        r#"{{"kty":"RSA","n":"{RFC_7515_A2_N}","e":"AQAB"}}"#
    ))
    .unwrap()
}

fn check(alg: Algorithm, key: &Jwk, input: &str, signature: &str) -> Vec<Result<(), Error>> {
    let signature = base64url::decode(signature).unwrap();
    providers()
        .iter()
        .map(|(_, provider)| {
            verify::signature(
                alg,
                key,
                input.as_bytes(),
                &signature,
                provider.signature_verification_algorithms.all,
            )
        })
        .collect()
}

#[test]
fn rfc_7515_a2_rs256_verifies() {
    let input = format!("eyJhbGciOiJSUzI1NiJ9.{RFC_7515_PAYLOAD}");
    for result in check(
        Algorithm::Rs256,
        &rfc_7515_a2_jwk(),
        &input,
        RFC_7515_A2_SIGNATURE,
    ) {
        result.unwrap();
    }
}

#[test]
fn rfc_7515_a3_es256_verifies() {
    let input = format!("eyJhbGciOiJFUzI1NiJ9.{RFC_7515_PAYLOAD}");
    let key = Jwk::from_json(RFC_7515_A3_JWK).unwrap();
    for result in check(Algorithm::Es256, &key, &input, RFC_7515_A3_SIGNATURE) {
        result.unwrap();
    }
}

#[test]
fn rfc_7515_vectors_fail_over_another_input() {
    let input = format!("eyJhbGciOiJFUzI1NiJ9.{RFC_7515_PAYLOAD}x");
    let key = Jwk::from_json(RFC_7515_A3_JWK).unwrap();
    for result in check(Algorithm::Es256, &key, &input, RFC_7515_A3_SIGNATURE) {
        assert!(matches!(result, Err(Error::BadSignature)));
    }
    let input = format!("eyJhbGciOiJSUzI1NiJ9.{RFC_7515_PAYLOAD}x");
    for result in check(
        Algorithm::Rs256,
        &rfc_7515_a2_jwk(),
        &input,
        RFC_7515_A2_SIGNATURE,
    ) {
        assert!(matches!(result, Err(Error::BadSignature)));
    }
}

#[test]
fn rfc_7515_a2_private_jwk_is_refused() {
    let json = format!(r#"{{"kty":"RSA","n":"{RFC_7515_A2_N}","e":"AQAB","d":"AQAB"}}"#);
    assert!(matches!(Jwk::from_json(&json), Err(Error::PrivateKey)));
}

#[test]
fn rfc_7515_a7_flattened_is_refused_for_its_unprotected_header() {
    let json = format!(
        r#"{{"payload":"{RFC_7515_PAYLOAD}","protected":"eyJhbGciOiJFUzI1NiJ9",
        "header":{{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}},
        "signature":"{RFC_7515_A3_SIGNATURE}"}}"#
    );
    assert!(matches!(
        FlattenedJws::parse(json.as_bytes()),
        Err(Error::UnexpectedMember(name)) if name == "header"
    ));
}

#[test]
fn rfc_7515_a4_es512_is_unsupported() {
    let json = concat!(
        r#"{"protected":"eyJhbGciOiJFUzUxMiJ9","payload":"UGF5bG9hZA","signature":""#,
        "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq",
        "wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp",
        r#"EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"}"#,
    );
    assert!(matches!(
        FlattenedJws::parse(json.as_bytes()),
        Err(Error::UnsupportedAlgorithm(alg)) if alg == "ES512"
    ));
    let p521 = concat!(
        r#"{"kty":"EC","crv":"P-521","x":""#,
        "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_",
        r#"NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":""#,
        "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl",
        r#"y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"}"#,
    );
    assert!(matches!(
        Jwk::from_json(p521),
        Err(Error::UnsupportedKey(kty)) if kty == "EC P-521"
    ));
}

#[test]
fn rfc_7638_3_1_thumbprint() {
    let json = concat!(
        r#"{"kty": "RSA", "n": ""#,
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt",
        "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6",
        "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD",
        "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9",
        "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH",
        "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        r#"", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}"#,
    );
    let key = Jwk::from_json(json).unwrap();
    assert!(
        key.to_canonical_json()
            .starts_with(r#"{"e":"AQAB","kty":"RSA","n":"0vx7agoe"#)
    );
    assert_eq!(
        key.thumbprint(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

#[test]
fn rfc_8037_a1_private_key_is_refused() {
    let json = r#"{"kty":"OKP","crv":"Ed25519",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    assert!(matches!(Jwk::from_json(json), Err(Error::PrivateKey)));
}

#[test]
fn rfc_8037_a3_canonical_form_and_thumbprint() {
    let key = Jwk::from_json(RFC_8037_A2_JWK).unwrap();
    assert_eq!(
        key.to_canonical_json(),
        r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
    );
    assert_eq!(
        key.thumbprint(),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}

#[test]
fn rfc_8037_a5_eddsa_verifies() {
    let key = Jwk::from_json(RFC_8037_A2_JWK).unwrap();
    for result in check(
        Algorithm::EdDsa,
        &key,
        RFC_8037_A4_SIGNING_INPUT,
        RFC_8037_A4_SIGNATURE,
    ) {
        result.unwrap();
    }
    let tampered = RFC_8037_A4_SIGNING_INPUT.replace("RXhh", "RXhi");
    for result in check(Algorithm::EdDsa, &key, &tampered, RFC_8037_A4_SIGNATURE) {
        assert!(matches!(result, Err(Error::BadSignature)));
    }
}
