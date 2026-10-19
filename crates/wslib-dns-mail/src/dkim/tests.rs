use super::*;

const RSA_1024: &str = include_str!("../../testdata/dkim/rsa1024.b64");
const RSA_2048: &str = include_str!("../../testdata/dkim/rsa2048.b64");
/// RFC 8463 §A.2.
const ED25519: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

fn codes(input: &str) -> Vec<FaultCode> {
    parse(input).faults.iter().map(|fault| fault.code).collect()
}

#[test]
fn an_rsa_key_reports_its_size() {
    let parsed = parse(&format!("v=DKIM1; k=rsa; h=sha256; t=s; p={RSA_2048}"));
    assert!(parsed.is_usable(), "{:?}", parsed.faults);
    assert_eq!(parsed.record.rsa_bits, Some(2048));
    assert_eq!(
        parsed.record.hash_algorithms,
        Some(vec!["sha256".to_owned()])
    );
    assert_eq!(parsed.record.flags, [KeyFlag::Strict]);
    assert_eq!(parse(&format!("p={RSA_1024}")).record.rsa_bits, Some(1024));
}

#[test]
fn a_key_split_across_strings_or_folded_with_spaces_still_decodes() {
    let (head, tail) = RSA_2048.split_at(200);
    let parsed = parse(&format!("v=DKIM1; p={head} {tail}"));
    assert!(parsed.is_usable(), "{:?}", parsed.faults);
    assert_eq!(parsed.record.rsa_bits, Some(2048));
}

#[test]
fn an_ed25519_key_is_32_bytes() {
    let parsed = parse(&format!("v=DKIM1; k=ed25519; p={ED25519}"));
    assert!(parsed.is_usable(), "{:?}", parsed.faults);
    assert_eq!(parsed.record.effective_key_type(), KeyType::Ed25519);
    assert_eq!(parsed.record.rsa_bits, None);
    assert_eq!(
        codes(&format!("k=ed25519; p={RSA_1024}")),
        [FaultCode::InvalidKey]
    );
}

#[test]
fn an_empty_p_is_a_revoked_key_not_a_fault() {
    let parsed = parse("v=DKIM1; p=");
    assert!(parsed.is_usable());
    assert!(parsed.record.is_revoked());
}

#[test]
fn testing_mode_is_the_y_flag() {
    assert!(
        parse(&format!("t=y:s; p={ED25519}; k=ed25519"))
            .record
            .is_testing()
    );
    assert!(!parse(&format!("t=s; p={RSA_1024}")).record.is_testing());
}

#[test]
fn every_fault_code() {
    for (input, code) in [
        (
            format!("k=rsa; v=DKIM1; p={RSA_1024}"),
            FaultCode::VersionNotFirst,
        ),
        (format!("v=DKIM2; p={RSA_1024}"), FaultCode::InvalidVersion),
        ("v=DKIM1; k=rsa".to_owned(), FaultCode::MissingTag),
        ("v=DKIM1; p=not*base64".to_owned(), FaultCode::InvalidBase64),
        ("v=DKIM1; p=Zm9vYmFy".to_owned(), FaultCode::InvalidKey),
        (
            format!("v=DKIM1; k=dsa; p={RSA_1024}"),
            FaultCode::UnknownKeyType,
        ),
        (
            format!("v=DKIM1; p={RSA_1024}; p="),
            FaultCode::DuplicateTag,
        ),
        (
            format!("v=DKIM1; junk; p={RSA_1024}"),
            FaultCode::MalformedTag,
        ),
    ] {
        let parsed = parse(&input);
        assert_eq!(codes(&input), [code], "{input}");
        assert!(!parsed.is_usable(), "{input}");
    }
}

#[test]
fn tag_names_are_case_sensitive_and_unknown_ones_are_ignored() {
    let parsed = parse(&format!("v=DKIM1; P=x; g=*; p={RSA_1024}"));
    assert_eq!(
        codes(&format!("v=DKIM1; P=x; g=*; p={RSA_1024}")),
        [FaultCode::UnknownTag, FaultCode::UnknownTag]
    );
    assert!(parsed.is_usable());
    assert_eq!(parsed.record.tags[1].name, "P");
}

#[test]
fn display_renders_the_tags_as_written() {
    assert_eq!(
        parse("v=DKIM1 ;k=ed25519;  p=").record.to_string(),
        "v=DKIM1; k=ed25519; p="
    );
}
