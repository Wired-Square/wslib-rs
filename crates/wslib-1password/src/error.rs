use std::{fmt, io};

use crate::runner::Output;
use crate::types::is_item_id;

/// Why an `op` call failed.
///
/// The variants holding a `String` carry what `op` said, with any assignment
/// value it echoed redacted.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// There is no `op` to run.
    CliNotFound,
    /// `op` is not signed in to the account, and signing in failed.
    NotSignedIn(String),
    /// `op` has no accounts: also what an app that can't reach the desktop
    /// app's integration (an ad-hoc-signed bundle, say) is told.
    NoAccountsConfigured(String),
    /// Nobody approved the prompt (Touch ID, the desktop app) in time.
    NotApproved(String),
    PermissionDenied(String),
    VaultNotFound(String),
    ItemNotFound(String),
    /// The item already exists, a name is a duplicate, or the item is archived.
    ItemConflict(String),
    /// 1Password's server refused a write that raced another (HTTP 409); the
    /// write did not happen, so it can be retried.
    WriteConflict(String),
    /// More than one item has the title; `ids` are theirs, as `op` listed them.
    Ambiguous {
        title: String,
        ids: Vec<String>,
    },
    /// An [`ItemRef::Id`](crate::ItemRef::Id) that is not 26 lowercase letters and digits.
    InvalidItemId(String),
    /// Any other refusal.
    Cli {
        message: String,
        code: Option<i32>,
    },
    /// `op` did not answer before the runner's timeout.
    TimedOut,
    /// An assignment `op` would not take, or one the call cannot send.
    InvalidAssignment(String),
    /// `op`'s output was not what the command answers, at this line and column.
    Unexpected {
        command: String,
        line: usize,
        column: usize,
    },
    /// The value is not UTF-8, and the call answers text.
    NotUtf8,
    /// The async runtime shut down before `op` answered.
    Cancelled,
    /// The testing fake was called with nothing scripted; this is the call.
    Unscripted(String),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CliNotFound => f.write_str("the 1Password CLI `op` is not installed"),
            Self::NotSignedIn(m) => write!(f, "not signed in to 1Password: {m}"),
            Self::NoAccountsConfigured(m) => write!(f, "op has no accounts it can use: {m}"),
            Self::NotApproved(m) => write!(f, "1Password access was not approved: {m}"),
            Self::PermissionDenied(m) => write!(f, "1Password permission denied: {m}"),
            Self::VaultNotFound(m) => write!(f, "vault not found: {m}"),
            Self::ItemNotFound(m) => write!(f, "item not found: {m}"),
            Self::ItemConflict(m) => write!(f, "item conflict: {m}"),
            Self::WriteConflict(m) => write!(f, "1Password write conflict: {m}"),
            Self::Ambiguous { title, ids } => {
                write!(
                    f,
                    "{} items are titled {title:?}: {}",
                    ids.len(),
                    ids.join(", ")
                )
            }
            Self::InvalidItemId(id) => write!(f, "{id:?} is not an item id"),
            Self::Cli { message, .. } => write!(f, "op: {message}"),
            Self::TimedOut => f.write_str("op did not answer in time"),
            Self::InvalidAssignment(m) => write!(f, "invalid assignment: {m}"),
            Self::Unexpected {
                command,
                line,
                column,
            } => {
                write!(
                    f,
                    "unexpected output from `op {command}` at {line}:{column}"
                )
            }
            Self::NotUtf8 => f.write_str("the value is not UTF-8"),
            Self::Cancelled => f.write_str("the runtime shut down before op answered"),
            Self::Unscripted(call) => write!(f, "nothing scripted for `{call}`"),
            Self::Io(_) => f.write_str("run op"),
        }
    }
}

impl Error {
    /// Whether the same call may succeed if made again unchanged; the crate never retries by itself.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::WriteConflict(_))
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => Self::CliNotFound,
            io::ErrorKind::TimedOut => Self::TimedOut,
            _ => e.downcast::<Self>().unwrap_or_else(Self::Io),
        }
    }
}

/// The error a failed `op` answer means, read from its stderr, or its stdout
/// when stderr is empty.
pub fn map_cli_error(out: &Output) -> Error {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let message = match out.stderr.trim() {
        "" => stdout.trim(),
        stderr => stderr,
    }
    .to_owned();
    let low = message.to_lowercase();
    let has = |s: &str| low.contains(s);

    if has("more than one item matches") {
        ambiguous(&message)
    } else if has("(409) (conflict)") {
        Error::WriteConflict(message)
    } else if has("no accounts configured") {
        Error::NoAccountsConfigured(message)
    } else if has("authorization timeout") || has("authorization prompt dismissed") {
        Error::NotApproved(message)
    } else if has("isn't a vault") || (has("vault") && has("not found")) {
        Error::VaultNotFound(message)
    } else if has("sign in")
        || has("not currently signed in")
        || has("unauthenticated")
        || has("not authenticated")
    {
        Error::NotSignedIn(message)
    } else if has("permission") || has("denied") || has("forbidden") {
        Error::PermissionDenied(message)
    } else if has("already exists") || has("duplicate") || has("archived") {
        Error::ItemConflict(message)
    } else if has("isn't an item") || (has("item") && has("not found")) {
        Error::ItemNotFound(message)
    } else {
        Error::Cli {
            message,
            code: out.code,
        }
    }
}

/// `More than one item matches "X". Try again and specify the item by its ID:`,
/// then a line per match, read for the one id-shaped word in each.
fn ambiguous(message: &str) -> Error {
    let mut lines = message.lines();
    let first = lines.next().unwrap_or_default();
    let title = first
        .split_once('"')
        .and_then(|(_, rest)| rest.rsplit_once('"'))
        .map_or_else(String::new, |(title, _)| title.to_owned());
    let ids = lines
        .filter_map(|line| {
            line.split(|c: char| !c.is_ascii_alphanumeric())
                .rfind(|word| is_item_id(word))
                .map(str::to_owned)
        })
        .collect();
    Error::Ambiguous { title, ids }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(stderr: &str) -> Error {
        map_cli_error(&Output::fail(stderr))
    }

    #[test]
    fn isnt_a_vault_is_vault_not_found() {
        let e = mapped("[ERROR] 2026/09/24 23:15:37 \"Ops\" isn't a vault in this account.");
        assert!(matches!(e, Error::VaultNotFound(_)));
    }

    #[test]
    fn vault_not_found_is_vault_not_found() {
        assert!(matches!(
            mapped("[ERROR] vault \"Foo\" not found"),
            Error::VaultNotFound(_)
        ));
    }

    #[test]
    fn sign_in_is_not_signed_in() {
        assert!(matches!(
            mapped("[ERROR] You are not currently sign in"),
            Error::NotSignedIn(_)
        ));
    }

    #[test]
    fn ops_own_signed_out_message_is_not_signed_in() {
        let e = mapped("[ERROR] You are not currently signed in. Please run `op signin --help`");
        assert!(matches!(e, Error::NotSignedIn(_)));
    }

    #[test]
    fn unauthenticated_is_not_signed_in() {
        assert!(matches!(
            mapped("[ERROR] 401: unauthenticated"),
            Error::NotSignedIn(_)
        ));
    }

    #[test]
    fn not_authenticated_is_not_signed_in() {
        assert!(matches!(
            mapped("session not authenticated"),
            Error::NotSignedIn(_)
        ));
    }

    #[test]
    fn permission_is_permission_denied() {
        let e = mapped("[ERROR] You do not have permission to perform this action");
        assert!(matches!(e, Error::PermissionDenied(_)));
    }

    #[test]
    fn denied_is_permission_denied() {
        assert!(matches!(
            mapped("[ERROR] access denied"),
            Error::PermissionDenied(_)
        ));
    }

    #[test]
    fn forbidden_is_permission_denied() {
        assert!(matches!(
            mapped("[ERROR] 403: Forbidden"),
            Error::PermissionDenied(_)
        ));
    }

    #[test]
    fn already_exists_is_a_conflict() {
        assert!(matches!(
            mapped("[ERROR] item already exists"),
            Error::ItemConflict(_)
        ));
    }

    #[test]
    fn duplicate_is_a_conflict() {
        assert!(matches!(
            mapped("[ERROR] duplicate item title"),
            Error::ItemConflict(_)
        ));
    }

    #[test]
    fn archived_is_a_conflict() {
        assert!(matches!(
            mapped("[ERROR] the item is archived"),
            Error::ItemConflict(_)
        ));
    }

    #[test]
    fn a_server_409_is_a_retryable_write_conflict() {
        let e = mapped(
            "unable to process line 1: Network: (DB: (409) (Conflict), Internal server conflict.)",
        );
        assert!(matches!(e, Error::WriteConflict(_)), "{e:?}");
        assert!(e.is_retryable());
    }

    #[test]
    fn a_title_mentioning_a_conflict_is_not_a_409() {
        let e = mapped(r#"[ERROR] "Merge (conflict) notes" isn't an item"#);
        assert!(matches!(e, Error::ItemNotFound(_)), "{e:?}");
    }

    #[test]
    fn only_a_write_conflict_is_retryable() {
        for e in [
            mapped("[ERROR] item already exists"),
            mapped("[ERROR] authorization timeout"),
            mapped("[ERROR] boom"),
            Error::TimedOut,
        ] {
            assert!(!e.is_retryable(), "{e:?}");
        }
    }

    #[test]
    fn isnt_an_item_is_item_not_found() {
        let e = mapped(
            "[ERROR] 2026/09/24 23:15:34 \"Db\" isn't an item in the \"Ops\" vault. Specify the item with its UUID, name, or domain.",
        );
        assert!(matches!(e, Error::ItemNotFound(_)));
    }

    #[test]
    fn item_not_found_is_item_not_found() {
        assert!(matches!(
            mapped("[ERROR] item \"CA\" not found"),
            Error::ItemNotFound(_)
        ));
    }

    #[test]
    fn no_accounts_configured_is_not_read_as_signed_out() {
        let e = mapped(
            "[ERROR] 2026/10/01 09:00:00 No accounts configured for use with 1Password CLI.",
        );
        assert!(matches!(e, Error::NoAccountsConfigured(_)));
    }

    #[test]
    fn an_unapproved_prompt_is_not_approved() {
        let e = mapped("[ERROR] 2026/10/01 09:00:00 authorization timeout");
        assert!(matches!(e, Error::NotApproved(_)));
        let e = mapped("[ERROR] authorization prompt dismissed, please try again");
        assert!(matches!(e, Error::NotApproved(_)));
    }

    #[test]
    fn anything_else_is_a_cli_error_with_its_code() {
        let out = Output {
            stdout: Vec::new(),
            stderr: "[ERROR] boom".into(),
            code: Some(6),
        };
        match map_cli_error(&out) {
            Error::Cli { message, code } => {
                assert_eq!(message, "[ERROR] boom");
                assert_eq!(code, Some(6));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn two_items_of_one_title_are_ambiguous_with_their_ids() {
        let e = mapped(
            "[ERROR] 2026/10/23 10:00:00 More than one item matches \"CA_Lock\". Try again and specify the item by its ID:\n\
             \t* for the item \"CA_Lock\" in vault Scratch: 4ld6tdxnvj5kgsbjbb4e3opyua\n\
             \t* for the item \"CA_Lock\" in vault Scratch: ubvcz6g3xb4bkmrkbs2xq6cfzi\n",
        );
        match e {
            Error::Ambiguous { title, ids } => {
                assert_eq!(title, "CA_Lock");
                assert_eq!(
                    ids,
                    ["4ld6tdxnvj5kgsbjbb4e3opyua", "ubvcz6g3xb4bkmrkbs2xq6cfzi"]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_exact_ambiguous_text_maps_with_ids_in_any_line_layout() {
        let e = mapped(
            "More than one item matches \"X\". Try again and specify the item by its ID:\n\
             4ld6tdxnvj5kgsbjbb4e3opyua\n\
             - X (ubvcz6g3xb4bkmrkbs2xq6cfzi)\n",
        );
        assert!(
            matches!(&e, Error::Ambiguous { title, ids } if title == "X" && ids.len() == 2),
            "{e:?}"
        );
    }

    #[test]
    fn stdout_is_read_when_stderr_is_empty() {
        let out = Output {
            stdout: b"vault not found".to_vec(),
            stderr: " \n".into(),
            code: Some(1),
        };
        assert!(matches!(map_cli_error(&out), Error::VaultNotFound(_)));
    }
}
