//! A field *named* like a credential is captured as `[redacted]` whatever its
//! value printed as. A backstop: `%x` and `?x` both reach a capture layer as
//! text, so the name is all it has, and the guarantee stays a type that will
//! not print itself.

use std::fmt;

/// Field names whose values are never captured.
#[cfg(feature = "ring")]
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
#[cfg(feature = "ring")]
const SECRET_SUFFIXES: &[&str] = &[
    "_password",
    "_passphrase",
    "_secret",
    "_token",
    "_key",
    "_community",
];

#[cfg(feature = "ring")]
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

/// Renders somebody else's error for a log line: URL credentials stripped and
/// the length capped, which is not a filter that makes arbitrary text safe.
pub fn foreign_error(error: &dyn fmt::Display) -> String {
    truncate(strip_userinfo(&error.to_string()), 512, "…")
}

/// Replaces `scheme://user:password@host` with `scheme://redacted@host`.
///
/// The host is kept deliberately: "which endpoint failed" is the whole reason
/// somebody is reading the line.
pub fn strip_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(scheme_end) = rest.find("://") {
        let after = scheme_end + "://".len();
        out.push_str(&rest[..after]);
        rest = &rest[after..];
        // An `@` past the authority is an address in a path or a message.
        let authority_end = rest
            .find(|c: char| {
                matches!(c, '/' | '?' | '#' | ')' | '"' | '\'' | ',') || c.is_whitespace()
            })
            .unwrap_or(rest.len());
        match rest[..authority_end].rfind('@') {
            Some(at) => {
                out.push_str("redacted@");
                rest = &rest[at + 1..];
            }
            None => {
                out.push_str(&rest[..authority_end]);
                rest = &rest[authority_end..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ring")]
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

    #[test]
    fn a_credential_in_a_url_is_stripped_and_the_host_kept() {
        let stripped = strip_userinfo(
            "error sending request for url (https://hook:s3cr3t@example.invalid/notify)",
        );
        assert_eq!(
            stripped,
            "error sending request for url (https://redacted@example.invalid/notify)"
        );
    }

    #[test]
    fn a_url_with_no_credentials_is_left_alone() {
        for text in [
            "connecting to https://example.invalid/notify failed",
            "https://example.invalid",
            "no url here at all",
            "",
        ] {
            assert_eq!(strip_userinfo(text), text);
        }
    }

    #[test]
    fn an_at_sign_outside_the_authority_is_not_userinfo() {
        let text = "https://example.invalid/contact?to=user@example.invalid";
        assert_eq!(strip_userinfo(text), text);
    }

    #[test]
    fn every_url_in_one_message_is_covered() {
        assert_eq!(
            strip_userinfo("tried https://a:1@one.invalid/x then https://b:2@two.invalid/y"),
            "tried https://redacted@one.invalid/x then https://redacted@two.invalid/y"
        );
    }

    #[test]
    fn a_bare_username_with_no_password_is_still_userinfo() {
        assert_eq!(
            strip_userinfo("https://user@example.invalid/x"),
            "https://redacted@example.invalid/x"
        );
    }

    #[test]
    fn a_foreign_error_loses_its_url_credentials_and_keeps_the_host() {
        let rendered = foreign_error(
            &"error sending request for url (https://hook:s3cr3t@example.invalid/notify)",
        );
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(rendered.contains("example.invalid"), "{rendered}");
    }

    #[test]
    fn a_foreign_error_carrying_a_response_body_is_capped() {
        let rendered = foreign_error(&format!("upstream said: {}", "é".repeat(4096)));
        assert!(rendered.len() <= 512 + '…'.len_utf8(), "{}", rendered.len());
        assert!(rendered.ends_with('…'));
    }
}
