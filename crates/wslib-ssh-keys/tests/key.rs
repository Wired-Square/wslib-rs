mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use wslib_ssh_keys::{Error, Fingerprint, Key, KeyType};

fn refused(line: &str) -> Error {
    Key::parse(line).unwrap_err()
}

fn wire(fields: &[&[u8]]) -> String {
    let blob: Vec<u8> = fields
        .iter()
        .flat_map(|f| {
            (f.len() as u32)
                .to_be_bytes()
                .into_iter()
                .chain(f.iter().copied())
        })
        .collect();
    STANDARD.encode(blob)
}

#[test]
fn fingerprints_and_sizes_match_ssh_keygen() {
    for (line, fingerprint, key_type, bits, comment) in [
        (ED25519, ED25519_FP, KeyType::Ed25519, 256, "admin@bench"),
        (ECDSA, ECDSA_FP, KeyType::EcdsaP256, 256, "operator@bench"),
        (ECDSA384, ECDSA384_FP, KeyType::EcdsaP384, 384, "p384@bench"),
        (ECDSA521, ECDSA521_FP, KeyType::EcdsaP521, 521, "p521@bench"),
        (RSA, RSA_FP, KeyType::Rsa, 2048, "admin@bench"),
        (
            SK_ED25519,
            SK_ED25519_FP,
            KeyType::SkEd25519,
            256,
            "yubikey@bench",
        ),
        (
            SK_ECDSA,
            SK_ECDSA_FP,
            KeyType::SkEcdsaP256,
            256,
            "yubikey@bench",
        ),
    ] {
        let key = Key::parse(line).unwrap_or_else(|e| panic!("{key_type}: {e}"));
        assert_eq!(key.fingerprint().to_string(), fingerprint, "{key_type}");
        assert_eq!((key.key_type(), key.bits()), (key_type, bits));
        assert_eq!(key.comment(), Some(comment));
        assert_eq!(key.line(), line);
        assert!(key.options().is_empty());
    }
}

#[test]
fn a_fingerprint_reads_back_from_what_it_prints() {
    let fingerprint: Fingerprint = ED25519_FP.parse().expect("parses");
    assert_eq!(fingerprint, Key::parse(ED25519).unwrap().fingerprint());
    for not in [
        "",
        "/7MVDOe0auFFSFk/9EBpTvK7defzpFI3ccbS8WyAmiU",
        "MD5:/7MVDOe0auFFSFk/9EBpTvK7defzpFI3ccbS8WyAmiU",
        "SHA256:/7MVDOe0auFFSFk/9EBpTvK7defzpFI3ccbS8WyAmi",
        "SHA256:/7MVDOe0auFFSFk/9EBpTvK7defzpFI3ccbS8WyAmiU=",
    ] {
        assert_eq!(
            not.parse::<Fingerprint>(),
            Err(Error::NotAFingerprint),
            "{not:?}"
        );
    }
}

#[test]
fn a_comment_is_optional_and_keeps_its_spacing() {
    let bare = ED25519.rsplit_once(' ').unwrap().0;
    assert_eq!(Key::parse(bare).unwrap().comment(), None);
    let spaced = format!("  {bare}\tthe  bench laptop \r");
    let key = Key::parse(&spaced).unwrap();
    assert_eq!(key.comment(), Some("the  bench laptop"));
    assert_eq!(key.line(), spaced.trim());
}

#[test]
fn options_are_read_as_sshd_reads_them() {
    let line =
        format!(r#"no-pty,from="10.0.0.0/8,192.168.1.1",command="echo \"hi there\"" {ED25519}"#);
    let key = Key::parse(&line).expect("parses");
    let options: Vec<_> = key
        .options()
        .iter()
        .map(|o| (o.name.as_str(), o.value.as_deref()))
        .collect();
    assert_eq!(
        options,
        [
            ("no-pty", None),
            ("from", Some("10.0.0.0/8,192.168.1.1")),
            ("command", Some(r#"echo "hi there""#)),
        ]
    );
    assert_eq!(key.fingerprint().to_string(), ED25519_FP);
    assert_eq!(key.to_string(), line, "written back as given");

    for accepted in [
        "restrict",
        "No-PTY",
        "cert-authority,principals=\"ops\"",
        "no-touch-required",
        "verify-required",
        "restrict,pty,X11-forwarding",
        "expiry-time=\"20300101\"",
        "environment=\"A=b c\"",
    ] {
        let key = Key::parse(&format!("{accepted} {ED25519}"));
        assert!(key.is_ok(), "{accepted}: {key:?}");
    }
}

#[test]
fn options_sshd_refuses_are_refused() {
    for options in [
        "frm=\"10.0.0.0/8\"",
        "from=10.0.0.0/8",
        "from=\"10.0.0.0/8",
        "no-pty,",
        "no-pty,,restrict",
        "pty=\"yes\"",
        "no-restrict",
        "no-pty,command",
    ] {
        let line = format!("{options} {ED25519}");
        assert!(matches!(refused(&line), Error::BadOptions(_)), "{options}");
    }
    assert_eq!(refused("no-pty"), Error::Empty);
    assert_eq!(
        refused(&format!("no-pty ssh-quantum {}", wire(&[b"ssh-quantum"]))),
        Error::UnsupportedType("ssh-quantum".into())
    );
}

#[test]
fn the_refusals_say_what_is_wrong() {
    let private = refused("-----BEGIN OPENSSH PRIVATE KEY-----").to_string();
    assert!(
        private.contains("private key") && private.contains(".pub"),
        "{private}"
    );
    assert!(
        refused("ssh-dss AAAAB3NzaC1kc3MAAACBAJ x")
            .to_string()
            .contains("DSA")
    );
    assert!(
        refused("ssh-quantum AAAA")
            .to_string()
            .contains("ssh-ed25519")
    );
    assert!(
        refused("ssh-ed25519 AAAAC3NzaC1lZDI1")
            .to_string()
            .contains("truncated")
    );
    assert_eq!(refused("ssh-ed25519 not-base-64!!"), Error::Base64);
    assert_eq!(refused("ssh-ed25519"), Error::MissingBlob(KeyType::Ed25519));
    assert_eq!(refused("  "), Error::Empty);
    assert_eq!(
        refused(&format!("{ED25519}\n{ECDSA}")),
        Error::MultipleLines
    );

    let blob = ED25519.split_whitespace().nth(1).unwrap();
    let spliced = refused(&format!("ssh-rsa {blob}"));
    assert_eq!(
        spliced,
        Error::TypeMismatch {
            line: KeyType::Rsa,
            blob: "ssh-ed25519".into()
        }
    );
    assert!(spliced.to_string().contains("incomplete"), "{spliced}");
}

#[test]
fn the_blob_must_be_one_sshd_would_load() {
    let ed25519 = |pk: &[u8], rest: &[&[u8]]| {
        let mut fields: Vec<&[u8]> = vec![b"ssh-ed25519", pk];
        fields.extend_from_slice(rest);
        format!("ssh-ed25519 {}", wire(&fields))
    };
    assert!(Key::parse(&ed25519(&[7; 32], &[])).is_ok());
    assert_eq!(refused(&ed25519(&[7; 31], &[])), Error::Malformed);
    assert_eq!(
        refused(&ed25519(&[7; 32], &[b"trailing"])),
        Error::Malformed
    );

    let point = [4u8; 65];
    let p256 = |curve: &[u8], point: &[u8]| {
        format!(
            "ecdsa-sha2-nistp256 {}",
            wire(&[b"ecdsa-sha2-nistp256", curve, point])
        )
    };
    assert!(Key::parse(&p256(b"nistp256", &point)).is_ok());
    assert_eq!(refused(&p256(b"nistp384", &point)), Error::Malformed);
    assert_eq!(refused(&p256(b"nistp256", &point[..33])), Error::Malformed);

    let rsa = |e: &[u8], n: &[u8]| format!("ssh-rsa {}", wire(&[b"ssh-rsa", e, n]));
    let modulus = |bytes: usize| [vec![0x00, 0xc1], vec![0xff; bytes - 1]].concat();
    assert_eq!(
        Key::parse(&rsa(&[1, 0, 1], &modulus(128))).unwrap().bits(),
        1024
    );
    assert_eq!(refused(&rsa(&[1, 0, 1], &modulus(96))), Error::RsaSize(768));
    assert_eq!(
        refused(&rsa(&[1, 0, 1], &modulus(128)[1..])),
        Error::Malformed
    );
    assert_eq!(refused(&rsa(&[0x81], &modulus(128))), Error::Malformed);

    let sk = |app: &[u8]| {
        let fields: [&[u8]; 3] = [b"sk-ssh-ed25519@openssh.com", &[7; 32], app];
        format!("sk-ssh-ed25519@openssh.com {}", wire(&fields))
    };
    assert!(Key::parse(&sk(b"ssh:")).is_ok());
    assert_eq!(refused(&sk(b"ssh:\0x")), Error::Malformed);
    let no_application = wire(&[b"sk-ssh-ed25519@openssh.com", &[7; 32]]);
    assert_eq!(
        refused(&format!("sk-ssh-ed25519@openssh.com {no_application}")),
        Error::Malformed
    );
}
