//! A field *named* like a credential is captured as `[redacted]` whatever its
//! value printed as. A backstop: `%x` and `?x` both reach a capture layer as
//! text, so the name is all it has, and the guarantee stays a type that will
//! not print itself.

/// Field names whose values are never captured.
const SECRET_NAMES: &[&str] = &[
    "password",
    "passphrase",
    "secret",
    "token",
    "psk",
    "cookie",
    "authorization",
    // SNMP's word for a password, which an appliance that polls one writes
    // into an event as readily as any other.
    "community",
];

/// Matched as suffixes too, so `operator_password` is caught without listing
/// every compound anybody might write. Not bare `key`: that is a settings
/// table's column, used innocently all over a store.
const SECRET_SUFFIXES: &[&str] = &[
    "_password",
    "_passphrase",
    "_secret",
    "_token",
    "_key",
    "_community",
];

pub(crate) fn is_secret(name: &str) -> bool {
    SECRET_NAMES.contains(&name) || SECRET_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Cuts `text` to at most `max` bytes and appends `marker` when it cut.
///
/// On a character boundary, not a byte one: a hostname in a non-Latin script
/// would otherwise panic here — on the failure path, or inside the logger,
/// which are the two worst places to find a panic.
pub fn truncate(mut text: String, max: usize, marker: &str) -> String {
    if text.len() > max {
        let mut cut = max;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str(marker);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_denylist_catches_compounds_without_catching_settings_keys() {
        for name in [
            "password",
            "passphrase",
            "api_key",
            "operator_password",
            "cookie",
            "community",
        ] {
            assert!(is_secret(name), "{name} should be redacted");
        }
        for name in ["key", "username", "device", "error", "monkey"] {
            assert!(!is_secret(name), "{name} should not be redacted");
        }
    }

    #[test]
    fn truncation_lands_on_a_character_boundary_and_is_marked() {
        assert_eq!(truncate("é".repeat(3), 3, "…"), "é…");
        assert_eq!(truncate("short".into(), 5, "…"), "short");
    }
}
