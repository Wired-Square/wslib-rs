use std::fs::{self, File};
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use wslib_secret::{Encoding, Secret, TokenHash};

const CODE_LEN: usize = 26;

/// A pairing code: 128 random bits as unpadded base32, redacted in `Debug`.
#[derive(Clone, Debug)]
pub struct PairingCode(Secret);

impl PairingCode {
    /// The code as a person copies it.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

/// Either case, as a person may type it.
impl FromStr for PairingCode {
    type Err = NotACode;

    fn from_str(s: &str) -> Result<Self, NotACode> {
        let code = s.trim().to_ascii_uppercase();
        if code.len() != CODE_LEN || !code.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7')) {
            return Err(NotACode);
        }
        Ok(Self(Secret::new(code)))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("not a pairing code: {CODE_LEN} characters of A-Z and 2-7")]
pub struct NotACode;

/// A one-time code kept as its hash in an owner-only state file, never the
/// code itself: spent by its first right use, or when wrong attempts reach the
/// limit.
///
/// The file is the authority. Each call reads it afresh, and a call that
/// writes holds `<path>.lock` from its read to its write, so a code issued or
/// an attempt made through another handle or process counts here.
#[derive(Debug)]
pub struct OneTimeCode {
    path: PathBuf,
}

#[derive(Debug)]
enum State {
    Pending {
        hash: TokenHash,
        wrong: u32,
        limit: u32,
    },
    Spent(SpentBy),
}

/// Why a code is spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpentBy {
    /// Its right use.
    Acceptance,
    /// Wrong attempts reaching the limit.
    Lockout,
}

/// What [`OneTimeCode::redeem`] made of a code.
#[must_use]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redemption {
    /// Right, and now spent.
    Accepted,
    /// Wrong, with one attempt or more left.
    Refused { remaining: u32 },
    /// Spent, by this attempt or before it.
    Spent(SpentBy),
}

/// A code's state as [`OneTimeCode::status`] reads it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pending { remaining: u32, limit: u32 },
    Spent(SpentBy),
}

impl OneTimeCode {
    /// Writes a fresh code over whatever is at `path`, allowing `attempts` wrong ones.
    pub fn issue(
        path: impl Into<PathBuf>,
        attempts: NonZeroU32,
    ) -> Result<(Self, PairingCode), CodeError> {
        let random =
            Secret::random::<16>(Encoding::Base32).map_err(|e| CodeError::Random(e.into()))?;
        let (issued, code) = (Self { path: path.into() }, PairingCode(random));
        let _lock = issued.lock()?;
        issued.save(&State::Pending {
            hash: code.0.hash(),
            wrong: 0,
            limit: attempts.get(),
        })?;
        Ok((issued, code))
    }

    /// The code issued at `path`; `None` when nothing is there.
    pub fn open(path: impl Into<PathBuf>) -> Result<Option<Self>, CodeError> {
        let opened = Self { path: path.into() };
        match opened.read() {
            Err(CodeError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Ok(None)
            }
            read => read.map(|_| Some(opened)),
        }
    }

    /// The state on disk, spending no attempt.
    pub fn status(&self) -> Result<Status, CodeError> {
        Ok(match self.read()? {
            State::Pending { wrong, limit, .. } => Status::Pending {
                remaining: limit - wrong,
                limit,
            },
            State::Spent(by) => Status::Spent(by),
        })
    }

    /// Checks `offered` and spends the code as the attempt requires, saved before it returns.
    ///
    /// A failed save answers an error and changes nothing: the attempt is
    /// neither counted nor answered.
    pub fn redeem(&self, offered: &PairingCode) -> Result<Redemption, CodeError> {
        let _lock = self.lock()?;
        let (hash, wrong, limit) = match self.read()? {
            State::Pending { hash, wrong, limit } => (hash, wrong + 1, limit),
            State::Spent(by) => return Ok(Redemption::Spent(by)),
        };
        let (next, answer) = if hash == offered.0.hash() {
            (State::Spent(SpentBy::Acceptance), Redemption::Accepted)
        } else if wrong == limit {
            let by = SpentBy::Lockout;
            (State::Spent(by), Redemption::Spent(by))
        } else {
            let remaining = limit - wrong;
            let next = State::Pending { hash, wrong, limit };
            (next, Redemption::Refused { remaining })
        };
        self.save(&next)?;
        Ok(answer)
    }

    /// Beside the state file rather than on it, as each save renames a new file over it.
    fn lock(&self) -> Result<File, CodeError> {
        let path = wslib_file_atomic::beside(&self.path, "lock");
        match wslib_file_atomic::write_private(&path, b"") {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            created => created.map_err(io_at(&path))?,
        }
        let file = File::open(&path).map_err(io_at(&path))?;
        file.lock().map_err(io_at(&path))?;
        Ok(file)
    }

    fn read(&self) -> Result<State, CodeError> {
        let text = fs::read_to_string(&self.path).map_err(io_at(&self.path))?;
        State::parse(&text).ok_or_else(|| CodeError::Corrupt {
            path: self.path.clone(),
        })
    }

    fn save(&self, state: &State) -> Result<(), CodeError> {
        wslib_file_atomic::replace_private(&self.path, state.render().as_bytes())
            .map_err(io_at(&self.path))
    }
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> CodeError {
    let path = path.to_path_buf();
    move |source| CodeError::Io { path, source }
}

impl State {
    fn render(&self) -> String {
        match self {
            Self::Pending { hash, wrong, limit } => {
                format!("pending {wrong} {limit} {}\n", hash.as_str())
            }
            Self::Spent(SpentBy::Acceptance) => "spent accepted\n".into(),
            Self::Spent(SpentBy::Lockout) => "spent locked-out\n".into(),
        }
    }

    fn parse(text: &str) -> Option<Self> {
        let fields: Vec<&str> = text.strip_suffix('\n')?.split(' ').collect();
        match fields[..] {
            ["spent", "accepted"] => Some(Self::Spent(SpentBy::Acceptance)),
            ["spent", "locked-out"] => Some(Self::Spent(SpentBy::Lockout)),
            ["pending", wrong, limit, hash] => {
                let (wrong, limit) = (wrong.parse().ok()?, limit.parse().ok()?);
                (wrong < limit).then_some(Self::Pending {
                    hash: TokenHash::from_stored(hash),
                    wrong,
                    limit,
                })
            }
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodeError {
    #[error("no randomness for a pairing code: {0}")]
    Random(#[source] io::Error),
    #[error("the pairing code's state at {}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error("the pairing code's state at {} is not one this crate wrote", path.display())]
    Corrupt { path: PathBuf },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_reads_in_either_case_and_nothing_else() {
        let code = "abcdefghijklmnopqrstuvwxyz".parse::<PairingCode>().unwrap();
        assert_eq!(code.expose(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert!("ABCDEFGHIJKLMNOPQRSTUVWXY1".parse::<PairingCode>().is_err());
        assert!("ABCDEFGHIJKLMNOPQRSTUVWXY".parse::<PairingCode>().is_err());
    }

    #[test]
    fn a_state_file_this_crate_did_not_write_is_refused() {
        for text in [
            "",
            "spent",
            "spent\n",
            "spent maybe\n",
            "pending 0 5\n",
            "pending 5 5 ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0\n",
            "spent accepted\nspent accepted\n",
        ] {
            assert!(State::parse(text).is_none(), "{text:?}");
        }
    }
}
