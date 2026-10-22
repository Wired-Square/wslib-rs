mod common;

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use common::*;
use wslib_ssh_keys::{AuthorisedKeys, Entry, Fingerprint, Key, Provenance};

fn at(stamp: &str) -> Option<DateTime<Utc>> {
    Some(
        DateTime::parse_from_rfc3339(stamp)
            .unwrap()
            .with_timezone(&Utc),
    )
}

fn fingerprint(line: &str) -> Fingerprint {
    Key::parse(line).unwrap().fingerprint()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wslib-ssh-keys-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn provenance_attaches_to_the_key_below_it_and_not_across_a_gap() {
    let file = AuthorisedKeys::parse(&format!(
        "# added by admin on 2026-08-15T22:10:00Z\n{ED25519}\n"
    ));
    assert_eq!(
        file.entries()[0].provenance,
        Some(Provenance::new("admin", at("2026-08-15T22:10:00Z")))
    );
    for separator in ["\n", "# something else\n"] {
        let file = AuthorisedKeys::parse(&format!(
            "# added by admin on 2026-08-15T22:10:00Z\n{separator}{ED25519}\n"
        ));
        assert_eq!(file.entries()[0].provenance, None, "{separator:?}");
    }
}

#[test]
fn provenance_reads_from_the_right_and_keeps_a_stamp_it_cannot_read_as_the_name() {
    let by = |comment: &str| {
        let file = AuthorisedKeys::parse(&format!("# {comment}\n{ED25519}\n"));
        file.entries()[0].provenance.clone().map(|p| (p.by, p.at))
    };
    assert_eq!(
        by("added by carry on wayward on 2026-08-15T22:10:00+10:00"),
        Some(("carry on wayward".into(), at("2026-08-15T12:10:00Z")))
    );
    assert_eq!(
        by("added by admin on Tuesday"),
        Some(("admin on Tuesday".into(), None))
    );
    assert_eq!(by("added by admin"), Some(("admin".into(), None)));
}

#[test]
fn a_line_this_crate_refuses_is_kept_and_the_file_round_trips() {
    let text = format!(
        "# added by admin on 2026-08-15T22:10:00Z\n{ED25519}\nssh-dss AAAAB3NzaC1kc3M= legacy\n\
         no-pty {ECDSA}\n"
    );
    let once = AuthorisedKeys::parse(&text);
    assert_eq!((once.entries().len(), once.unparsed().len()), (2, 1));
    assert_eq!(once.unparsed(), ["ssh-dss AAAAB3NzaC1kc3M= legacy"]);
    let headed = once.clone().with_header("Managed here.");
    assert_eq!(AuthorisedKeys::parse(&headed.to_string()), once);
}

#[test]
fn the_file_is_written_header_first_a_key_to_a_paragraph() {
    let mut file = AuthorisedKeys::parse("ssh-dss AAAA hand-written\n")
        .with_header("Managed by the operator's tools.\n\nEdit with care.");
    let ed25519 = Key::parse(ED25519).unwrap();
    let provenance = Provenance::new("admin", at("2026-08-15T22:10:00Z"));
    assert!(file.add(Entry::new(ed25519).with_provenance(provenance)));
    assert!(file.add(Key::parse(ECDSA).unwrap().into()));
    assert_eq!(
        file.to_string(),
        format!(
            "# Managed by the operator's tools.\n#\n# Edit with care.\n\
             \n# added by admin on 2026-08-15T22:10:00+00:00\n{ED25519}\n\
             \n{ECDSA}\n\
             ssh-dss AAAA hand-written\n"
        )
    );
    let bare = AuthorisedKeys::parse(ED25519);
    assert_eq!(bare.to_string(), format!("{ED25519}\n"));
    assert_eq!(AuthorisedKeys::default().to_string(), "");
}

#[test]
fn a_name_cannot_write_a_line_of_its_own() {
    let mut file = AuthorisedKeys::default();
    let provenance = Provenance::new(format!("admin\n{ECDSA}\r"), None);
    file.add(Entry::new(Key::parse(ED25519).unwrap()).with_provenance(provenance));
    let back = AuthorisedKeys::parse(&file.to_string());
    assert_eq!(back.entries().len(), 1);
    assert!(back.unparsed().is_empty());
}

#[test]
fn the_same_key_is_added_once_and_removed_by_fingerprint() {
    let mut file = AuthorisedKeys::default();
    assert!(file.add(Key::parse(ED25519).unwrap().into()));
    let restricted = Key::parse(&format!("restrict {ED25519}")).unwrap();
    assert!(!file.add(restricted.into()), "same blob, same key");
    assert!(file.add(Key::parse(ECDSA).unwrap().into()));

    let gone = file.remove(&fingerprint(ED25519)).expect("removed");
    assert_eq!(gone.key.line(), ED25519);
    assert!(file.remove(&fingerprint(ED25519)).is_none());
    assert!(file.get(&ECDSA_FP.parse().unwrap()).is_some());
    assert_eq!(file.entries().len(), 1);
}

#[test]
fn a_file_written_is_the_file_read_and_a_missing_one_is_empty() {
    let dir = scratch("write");
    let path = dir.join("authorized_keys");
    assert_eq!(
        AuthorisedKeys::read(&path).unwrap(),
        AuthorisedKeys::default()
    );

    let mut file = AuthorisedKeys::default().with_header("Managed.");
    file.add(Key::parse(ED25519).unwrap().into());
    file.write(&path).expect("written");
    assert_eq!(
        AuthorisedKeys::read(&path).unwrap().entries(),
        file.entries()
    );
    assert!(!Path::new(&format!("{}.new", path.display())).exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "sshd reads it as the account logging in");
    }
    std::fs::remove_dir_all(dir).unwrap();
}
