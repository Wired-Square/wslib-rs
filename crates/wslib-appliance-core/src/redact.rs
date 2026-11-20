//! The sanctioned renderings of an error at a text boundary: an operator's
//! sentence in a response body, and the journal's copy, whose `Display`s may
//! embed a URL with credentials. Not a general filter: a secret never in a URL
//! is one this does not see.

use std::error::Error;

use wslib_telemetry::{strip_userinfo, truncate};

const MAX_LEN: usize = 512;

const CAUSE_SEPARATOR: &str = ": ";

/// `error` and each cause its `source()` gives, in order, for an operator.
pub fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |&e| e.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(CAUSE_SEPARATOR)
}

/// Render an error and its causes for a log line, with URL credentials removed
/// and the length bounded.
pub fn foreign(error: &(dyn Error + 'static)) -> String {
    truncate(strip_userinfo(&chain(error)), MAX_LEN, "…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);

    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for Layer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.1.as_deref().map(|cause| cause as _)
        }
    }

    fn said(text: impl Into<String>) -> std::io::Error {
        std::io::Error::other(text.into())
    }

    #[test]
    fn every_cause_is_written_once_in_order() {
        let error = Layer(
            "could not notify",
            Some(Box::new(Layer(
                "the request failed",
                Some(Box::new(Layer("connection refused", None))),
            ))),
        );
        assert_eq!(
            chain(&error),
            "could not notify: the request failed: connection refused"
        );
        assert_eq!(foreign(&error), chain(&error));
    }

    #[test]
    fn a_credential_in_a_url_does_not_reach_the_journal() {
        let rendered = foreign(&said(
            "error sending request for url (https://hook:s3cr3t@example.invalid/notify)",
        ));
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(
            rendered.contains("example.invalid"),
            "the host is what makes the line useful: {rendered}"
        );
    }

    #[test]
    fn an_error_carrying_a_response_body_cannot_take_the_journal_with_it() {
        let huge = format!("upstream said: {}", "a".repeat(4096));
        let rendered = foreign(&said(huge));
        assert!(
            rendered.len() <= MAX_LEN + '…'.len_utf8(),
            "{}",
            rendered.len()
        );
        assert!(rendered.ends_with('…'));
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        let rendered = foreign(&said("é".repeat(MAX_LEN)));
        assert!(rendered.ends_with('…'));
    }
}
