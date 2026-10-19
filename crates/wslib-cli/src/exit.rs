//! How a command line ends.
//!
//! | Code    | Meaning                                                    |
//! | ------- | ---------------------------------------------------------- |
//! | 0       | Success                                                    |
//! | 1       | Any failure without a code of its own                      |
//! | 2       | Bad usage: arguments or config (clap exits 2 for its own)  |
//! | 3–123   | The tool's own, documented in its `--help`                 |
//! | 124     | Gave up waiting, as `timeout(1)` does                      |
//! | 130     | Interrupted by Ctrl-C, as a shell reports SIGINT           |

use std::error::Error;
use std::io;
use std::process::ExitCode;

use crate::Output;

/// A process exit code from the shared set, or one of the tool's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Exit(u8);

impl Exit {
    pub const SUCCESS: Self = Self(0);
    pub const FAILURE: Self = Self(1);
    pub const USAGE: Self = Self(2);
    pub const TIMEOUT: Self = Self(124);
    pub const INTERRUPTED: Self = Self(130);

    /// One of the tool's own codes, which should lie in 3–123.
    pub const fn new(code: u8) -> Self {
        Self(code)
    }

    /// The exit for `error`: the first in its source chain that `classify`
    /// names, else [`TIMEOUT`](Self::TIMEOUT) for a timed-out I/O error, else
    /// [`FAILURE`](Self::FAILURE).
    pub fn of(
        error: &(dyn Error + 'static),
        classify: impl Fn(&(dyn Error + 'static)) -> Option<Exit>,
    ) -> Self {
        chain(error)
            .find_map(&classify)
            .or_else(|| {
                chain(error)
                    .filter_map(|e| e.downcast_ref::<io::Error>())
                    .any(|e| e.kind() == io::ErrorKind::TimedOut)
                    .then_some(Self::TIMEOUT)
            })
            .unwrap_or(Self::FAILURE)
    }
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        Self::from(exit.0)
    }
}

/// Reports `error` on stderr, as JSON for [`Output::Json`], and returns `exit`.
pub fn fail(output: Output, error: &(dyn Error + 'static), exit: Exit) -> ExitCode {
    eprintln!("{}", failure_message(output, error, exit));
    exit.into()
}

fn failure_message(output: Output, error: &(dyn Error + 'static), exit: Exit) -> String {
    let message = chain(error)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    match output {
        Output::Human => format!("error: {message}"),
        Output::Json => serde_json::json!({ "error": message, "exit": exit.0 }).to_string(),
    }
}

fn chain<'a>(error: &'a (dyn Error + 'static)) -> impl Iterator<Item = &'a (dyn Error + 'static)> {
    std::iter::successors(Some(error), |&e| e.source())
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    #[derive(Debug)]
    struct Context(&'static str, Box<dyn Error>);

    impl fmt::Display for Context {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for Context {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&*self.1)
        }
    }

    #[derive(Debug)]
    struct Busy;

    impl fmt::Display for Busy {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("device busy")
        }
    }

    impl Error for Busy {}

    const EXIT_BUSY: Exit = Exit::new(4);

    fn busy(e: &(dyn Error + 'static)) -> Option<Exit> {
        e.is::<Busy>().then_some(EXIT_BUSY)
    }

    #[test]
    fn the_classifier_finds_a_cause_behind_context() {
        let error = Context("flash", Box::new(Busy));
        assert_eq!(Exit::of(&error, busy), EXIT_BUSY);
    }

    #[test]
    fn a_timed_out_io_error_is_a_timeout() {
        let error = Context("wait", Box::new(io::Error::from(io::ErrorKind::TimedOut)));
        assert_eq!(Exit::of(&error, |_| None), Exit::TIMEOUT);
    }

    #[test]
    fn anything_else_is_a_failure() {
        let error = io::Error::other("nope");
        assert_eq!(Exit::of(&error, busy), Exit::FAILURE);
    }

    #[test]
    fn a_failure_names_the_whole_chain() {
        let error = Context("flash", Box::new(Busy));
        assert_eq!(
            failure_message(Output::Human, &error, EXIT_BUSY),
            "error: flash: device busy"
        );
        assert_eq!(
            failure_message(Output::Json, &error, EXIT_BUSY),
            r#"{"error":"flash: device busy","exit":4}"#
        );
    }
}
