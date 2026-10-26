use wslib_pairing::{PairingCode, PairingUri, SpkiSha256, UriError};

const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CODE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn pin() -> SpkiSha256 {
    PIN.parse().unwrap()
}

fn code() -> PairingCode {
    CODE.parse().unwrap()
}

fn parse(text: &str) -> Result<PairingUri, UriError> {
    PairingUri::parse("example-enrol", text)
}

#[test]
fn each_host_form_round_trips() {
    for (host, written) in [
        ("broker.example.lan", "broker.example.lan"),
        ("192.0.2.10", "192.0.2.10"),
        ("2001:db8::1", "[2001:db8::1]"),
    ] {
        let uri = PairingUri::new("example-enrol", host, 8443, pin(), code()).unwrap();
        let text = uri.expose();
        assert_eq!(
            text,
            format!("example-enrol://{written}:8443#pin={PIN}&code={CODE}")
        );
        let back = parse(&text).unwrap();
        assert_eq!(back.host(), host);
        assert_eq!(back.port(), 8443);
        assert_eq!(back.pin(), pin());
        assert_eq!(back.code().expose(), CODE);
        assert_eq!(back.expose(), text);
    }
}

#[test]
fn a_colon_hex_pin_and_either_order_of_keys_are_read() {
    let colons = PIN
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap().to_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    let uri = parse(&format!(
        "EXAMPLE-ENROL://host:1#code={}&pin={colons}",
        CODE.to_lowercase()
    ))
    .unwrap();
    assert_eq!(uri.scheme(), "example-enrol");
    assert_eq!(uri.pin(), pin());
    assert_eq!(uri.code().expose(), CODE);
}

#[test]
fn the_debug_form_hides_the_code() {
    let uri = PairingUri::new("example-enrol", "host", 1, pin(), code()).unwrap();
    assert!(!format!("{uri:?}").contains(CODE));
}

#[test]
fn unknown_and_repeated_fragment_keys_are_refused() {
    let unknown = parse(&format!("example-enrol://h:1#pin={PIN}&code={CODE}&next=x"));
    assert!(matches!(unknown, Err(UriError::UnknownKey(key)) if key == "next"));
    let twice = parse(&format!(
        "example-enrol://h:1#pin={PIN}&code={CODE}&pin={PIN}"
    ));
    assert!(matches!(twice, Err(UriError::DuplicateKey(key)) if key == "pin"));
}

#[test]
fn a_missing_part_is_refused() {
    assert!(matches!(
        parse(&format!("example-enrol://h:1#pin={PIN}")),
        Err(UriError::Missing("code"))
    ));
    assert!(matches!(
        parse(&format!("example-enrol://h:1#code={CODE}")),
        Err(UriError::Missing("pin"))
    ));
    assert!(matches!(
        parse("example-enrol://h:1"),
        Err(UriError::Missing("pin"))
    ));
}

#[test]
fn malformed_uris_are_refused() {
    let fragment = format!("#pin={PIN}&code={CODE}");
    for bad in [
        format!("other://h:1{fragment}"),
        format!("example-enrol:h:1{fragment}"),
        format!("example-enrol://h{fragment}"),
        format!("example-enrol://h:0{fragment}"),
        format!("example-enrol://h:65536{fragment}"),
        format!("example-enrol://h:+1{fragment}"),
        format!("example-enrol://h:1/{fragment}"),
        format!("example-enrol://user@h:1{fragment}"),
        format!("example-enrol://2001:db8::1:1{fragment}"),
        format!("example-enrol://[2001:db8::1]{fragment}"),
        format!("example-enrol://[192.0.2.1]:1{fragment}"),
        format!("example-enrol://[fe80::1%25eth0]:1{fragment}"),
        format!("example-enrol://-h:1{fragment}"),
        format!("example-enrol://h..lan:1{fragment}"),
        format!("example-enrol://192.0.2.300:1{fragment}"),
        format!("example-enrol://:1{fragment}"),
        format!("example-enrol://h:1#pin={}&code={CODE}", &PIN[2..]),
        format!("example-enrol://h:1#pin={PIN}&code=ABC"),
    ] {
        assert!(parse(&bad).is_err(), "{bad}");
    }
}

#[test]
fn new_refuses_a_bracketed_host_and_a_bad_scheme() {
    assert!(PairingUri::new("example-enrol", "[::1]", 1, pin(), code()).is_err());
    assert!(PairingUri::new("1enrol", "h", 1, pin(), code()).is_err());
    assert!(PairingUri::new("example-enrol", "h", 0, pin(), code()).is_err());
}

#[test]
fn a_pin_is_spelt_as_a_wslib_crypto_fingerprint_is() {
    let fingerprint = wslib_crypto::Fingerprint::of(b"spki");
    let pin = SpkiSha256::from(*fingerprint.as_bytes());
    assert_eq!(pin.to_string(), fingerprint.to_string());
    assert_eq!(
        pin.to_string()
            .parse::<wslib_crypto::Fingerprint>()
            .unwrap(),
        fingerprint
    );
    assert_eq!(fingerprint.colons().parse::<SpkiSha256>().unwrap(), pin);
}
