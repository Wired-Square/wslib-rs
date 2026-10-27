//! The sanctioned rendering of a library's error, whose `Display` may embed a URL with
//! credentials. Not a general filter: a secret never in a URL is one this does not see.

use std::fmt;

use wslib_telemetry::{strip_userinfo, truncate};

const MAX_LEN: usize = 512;

/// Render a foreign error for a log line, with URL credentials removed and the length bounded.
pub fn foreign(error: &dyn fmt::Display) -> String {
    truncate(strip_userinfo(&error.to_string()), MAX_LEN, "…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_in_a_url_does_not_reach_the_journal() {
        let rendered =
            foreign(&"error sending request for url (https://hook:s3cr3t@example.invalid/notify)");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(
            rendered.contains("example.invalid"),
            "the host is what makes the line useful: {rendered}"
        );
    }

    #[test]
    fn an_error_carrying_a_response_body_cannot_take_the_journal_with_it() {
        let huge = format!("upstream said: {}", "a".repeat(4096));
        let rendered = foreign(&huge);
        assert!(
            rendered.len() <= MAX_LEN + '…'.len_utf8(),
            "{}",
            rendered.len()
        );
        assert!(rendered.ends_with('…'));
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        let rendered = foreign(&"é".repeat(MAX_LEN));
        assert!(rendered.ends_with('…'));
    }
}
