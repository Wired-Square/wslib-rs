//! 1Password secret references (`op://vault/item/field`), read with the `op`
//! command line.

use std::ffi::OsString;
use std::process::{Command, Stdio};
use std::{fmt, io};

/// Whether `value` is a secret reference rather than a value.
pub fn is_reference(value: &str) -> bool {
    value.starts_with("op://")
}

/// Something that reads a secret reference: [`OpCli`], or a fake in tests.
pub trait ReadReference {
    fn read(&self, reference: &str) -> Result<String, OpError>;
}

impl<F: Fn(&str) -> Result<String, OpError>> ReadReference for F {
    fn read(&self, reference: &str) -> Result<String, OpError> {
        self(reference)
    }
}

/// `value` itself, or what it refers to when it is a secret reference.
pub fn resolve(reader: &impl ReadReference, value: &str) -> Result<String, OpError> {
    if is_reference(value) {
        reader.read(value)
    } else {
        Ok(value.to_owned())
    }
}

/// Runs `op read`.
#[derive(Clone, Debug)]
pub struct OpCli {
    program: OsString,
}

impl Default for OpCli {
    fn default() -> Self {
        Self::new("op")
    }
}

impl OpCli {
    /// Runs `program` in place of `op` from `PATH`.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl ReadReference for OpCli {
    fn read(&self, reference: &str) -> Result<String, OpError> {
        // Stdin is the terminal's, so `op` can ask to be unlocked.
        let out = Command::new(&self.program)
            .args(["read", "--no-newline", reference])
            .stdin(Stdio::inherit())
            .output()
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => OpError::NotInstalled,
                _ => OpError::Run(e),
            })?;
        if !out.status.success() {
            return Err(OpError::Failed {
                reference: reference.to_owned(),
                message: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }
        String::from_utf8(out.stdout).map_err(|_| OpError::NotUtf8 {
            reference: reference.to_owned(),
        })
    }
}

/// Why a secret reference couldn't be read.
#[derive(Debug)]
pub enum OpError {
    /// There is no `op` to run.
    NotInstalled,
    Run(io::Error),
    /// `op` ran and refused, with what it said on stderr.
    Failed {
        reference: String,
        message: String,
    },
    NotUtf8 {
        reference: String,
    },
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled => f.write_str("the 1Password CLI `op` is not installed"),
            Self::Run(_) => f.write_str("run `op`"),
            Self::Failed { reference, message } => write!(f, "op read {reference}: {message}"),
            Self::NotUtf8 { reference } => write!(f, "op read {reference}: not UTF-8"),
        }
    }
}

impl std::error::Error for OpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Run(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(reference: &str) -> Result<String, OpError> {
        match reference {
            "op://ci/forge/token" => Ok("s3cret".to_owned()),
            _ => Err(OpError::Failed {
                reference: reference.to_owned(),
                message: "isn't an item".to_owned(),
            }),
        }
    }

    #[test]
    fn a_reference_is_read() {
        assert_eq!(resolve(&vault, "op://ci/forge/token").unwrap(), "s3cret");
    }

    #[test]
    fn a_plain_value_is_passed_through_unread() {
        let never = |_: &str| -> Result<String, OpError> { panic!("read a plain value") };
        assert_eq!(resolve(&never, "hunter2").unwrap(), "hunter2");
    }

    #[test]
    fn a_failed_read_names_the_reference() {
        let error = resolve(&vault, "op://ci/gone/token").unwrap_err();
        assert_eq!(
            error.to_string(),
            "op read op://ci/gone/token: isn't an item"
        );
    }

    #[test]
    fn a_missing_program_is_not_installed() {
        let error = OpCli::new("wslib-cli-no-such-op")
            .read("op://a/b/c")
            .unwrap_err();
        assert!(matches!(error, OpError::NotInstalled));
    }
}
