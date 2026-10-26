use std::num::NonZeroU32;
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, io};

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

/// A one-time code's state file, owner-only, holding the code's hash and
/// never the code: spent by its first right use, or when wrong attempts
/// reach the limit.
///
/// Hold one per file and serialise [`redeem`](Self::redeem) through it.
#[derive(Debug)]
pub struct OneTimeCode {
    path: PathBuf,
    state: State,
}

#[derive(Debug)]
enum State {
    Pending {
        hash: TokenHash,
        wrong: u32,
        limit: u32,
    },
    Spent,
}

/// What [`OneTimeCode::redeem`] made of a code.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redemption {
    /// Right, and now spent.
    Accepted,
    /// Wrong; at none remaining the code is spent.
    Refused { remaining: u32 },
    /// Spent before this attempt, which was not checked.
    Spent,
}

impl OneTimeCode {
    /// Writes a fresh code over whatever is at `path`, allowing `attempts` wrong ones.
    pub fn issue(
        path: impl Into<PathBuf>,
        attempts: NonZeroU32,
    ) -> Result<(Self, PairingCode), CodeError> {
        let code = PairingCode(Secret::random::<16>(Encoding::Base32)?);
        let issued = Self {
            path: path.into(),
            state: State::Pending {
                hash: code.0.hash(),
                wrong: 0,
                limit: attempts.get(),
            },
        };
        issued.save()?;
        Ok((issued, code))
    }

    /// The code issued at `path`; `None` when nothing is there.
    pub fn open(path: impl Into<PathBuf>) -> Result<Option<Self>, CodeError> {
        let path = path.into();
        let text = match fs::read_to_string(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            read => read.map_err(|source| CodeError::Io {
                path: path.clone(),
                source,
            })?,
        };
        let state = State::parse(&text).ok_or_else(|| CodeError::Corrupt { path: path.clone() })?;
        Ok(Some(Self { path, state }))
    }

    /// Checks `offered` and spends the code as the attempt requires, saved before it returns.
    ///
    /// A failed save leaves the code refusing in memory as well, so an error never admits.
    pub fn redeem(&mut self, offered: &PairingCode) -> Result<Redemption, CodeError> {
        let State::Pending { hash, wrong, limit } = &mut self.state else {
            return Ok(Redemption::Spent);
        };
        let right = *hash == offered.0.hash();
        *wrong += u32::from(!right);
        let remaining = *limit - *wrong;
        if right || remaining == 0 {
            self.state = State::Spent;
        }
        self.save()?;
        Ok(if right {
            Redemption::Accepted
        } else {
            Redemption::Refused { remaining }
        })
    }

    pub fn is_spent(&self) -> bool {
        matches!(self.state, State::Spent)
    }

    fn save(&self) -> Result<(), CodeError> {
        wslib_file_atomic::replace_private(&self.path, self.state.render().as_bytes()).map_err(
            |source| CodeError::Io {
                path: self.path.clone(),
                source,
            },
        )
    }
}

impl State {
    fn render(&self) -> String {
        match self {
            Self::Pending { hash, wrong, limit } => {
                format!("pending {wrong} {limit} {}\n", hash.as_str())
            }
            Self::Spent => "spent\n".into(),
        }
    }

    fn parse(text: &str) -> Option<Self> {
        let fields: Vec<&str> = text.strip_suffix('\n')?.split(' ').collect();
        match fields[..] {
            ["spent"] => Some(Self::Spent),
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
    Random(#[from] getrandom::Error),
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
            "pending 0 5\n",
            "pending 5 5 ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0\n",
            "spent\nspent\n",
        ] {
            assert!(State::parse(text).is_none(), "{text:?}");
        }
    }
}
