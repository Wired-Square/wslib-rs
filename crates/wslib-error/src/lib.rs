//! An error and its causes as one line.

use std::error::Error;
use std::fmt;
use std::iter::successors;

const SEPARATOR: &str = ": ";

/// `error`, then each cause its `source()` gives, with `: ` between them. A
/// cause is left out when it says nothing, or when the line so far is that
/// cause or ends with `: ` and it, so an error that writes its cause and also
/// returns it reads once.
#[derive(Clone, Copy, Debug)]
pub struct Chain<'a>(&'a (dyn Error + 'static));

impl<'a> Chain<'a> {
    pub fn new(error: &'a (dyn Error + 'static)) -> Self {
        Self(error)
    }
}

impl fmt::Display for Chain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut line = self.0.to_string();
        for cause in successors(self.0.source(), |&cause| cause.source()) {
            let said = cause.to_string();
            let written = line
                .strip_suffix(&said)
                .is_some_and(|before| before.is_empty() || before.ends_with(SEPARATOR));
            if !said.is_empty() && !written {
                if !line.is_empty() {
                    line.push_str(SEPARATOR);
                }
                line.push_str(&said);
            }
        }
        f.write_str(&line)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<dyn Error + Send + Sync>>);

    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for Layer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.1.as_deref().map(|cause| cause as _)
        }
    }

    fn over(said: &'static str, cause: impl Error + Send + Sync + 'static) -> Layer {
        Layer(said, Some(Box::new(cause)))
    }

    #[test]
    fn an_error_with_no_cause_is_its_own_sentence() {
        assert_eq!(
            Chain::new(&Layer("it failed", None)).to_string(),
            "it failed"
        );
    }

    #[test]
    fn each_cause_follows_the_layer_above_it() {
        let error = over(
            "the flash failed",
            over(
                "the port did not open",
                io::Error::other("permission denied"),
            ),
        );
        assert_eq!(
            Chain::new(&error).to_string(),
            "the flash failed: the port did not open: permission denied"
        );
    }

    #[test]
    fn a_cause_the_layer_above_already_wrote_reads_once() {
        let error = over(
            "the write failed",
            over(
                "IO error while using serial port: connection reset",
                io::Error::other("connection reset"),
            ),
        );
        assert_eq!(
            Chain::new(&error).to_string(),
            "the write failed: IO error while using serial port: connection reset"
        );
    }

    #[test]
    fn a_layer_that_forwards_its_cause_whole_reads_once_and_its_causes_follow() {
        let error = over(
            "the request failed",
            over(
                "the body was cut short",
                over("the body was cut short", Layer("reset", None)),
            ),
        );
        assert_eq!(
            Chain::new(&error).to_string(),
            "the request failed: the body was cut short: reset"
        );
    }

    #[test]
    fn a_cause_that_only_happens_to_end_the_line_is_kept() {
        let counted = over("got 10", Layer("0", None));
        assert_eq!(Chain::new(&counted).to_string(), "got 10: 0");
        let relay = over(
            "the relay timed out",
            io::Error::from(io::ErrorKind::TimedOut),
        );
        assert_eq!(
            Chain::new(&relay).to_string(),
            "the relay timed out: timed out"
        );
    }

    #[test]
    fn a_cause_already_written_reads_once_through_a_layer_that_says_nothing() {
        let error = over(
            "IO error: connection reset",
            over("", Layer("connection reset", None)),
        );
        assert_eq!(Chain::new(&error).to_string(), "IO error: connection reset");
    }

    #[test]
    fn a_layer_that_says_nothing_leaves_no_gap() {
        let error = over("the read failed", over("", Layer("reset", None)));
        assert_eq!(Chain::new(&error).to_string(), "the read failed: reset");
        let silent_on_top = over("", Layer("reset", None));
        assert_eq!(Chain::new(&silent_on_top).to_string(), "reset");
    }

    #[test]
    fn a_cause_repeated_further_up_but_not_by_the_layer_above_is_kept() {
        let error = over(
            "timed out",
            over("the read failed", Layer("timed out", None)),
        );
        assert_eq!(
            Chain::new(&error).to_string(),
            "timed out: the read failed: timed out"
        );
    }
}
