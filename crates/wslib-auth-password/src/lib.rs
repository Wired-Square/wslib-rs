//! Argon2id password hashes, stored as PHC strings.
//!
//! Every hash is made at m=19456 KiB, t=2, p=1, pinned here so a dependency
//! bump cannot move them. [`needs_rehash`] says when a stored hash was made
//! otherwise, for the caller to re-hash on the next sign-in that verifies.
//!
//! **Hashing and verifying block** for tens of milliseconds; on an async
//! runtime use the [`tokio`] wrappers (feature `tokio`).

use std::fmt;
use std::sync::OnceLock;

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

#[cfg(feature = "tokio")]
pub mod tokio;

/// The longest password accepted, in bytes; anything longer is refused before argon2 runs.
pub const MAX_BYTES: usize = 1024;

const M_COST: u32 = 19 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;
const OUTPUT_LEN: usize = 32;

fn params() -> Params {
    Params::new(M_COST, T_COST, P_COST, Some(OUTPUT_LEN)).expect("the pinned parameters are valid")
}

fn hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params())
}

/// The length rule a new password must meet; [`Policy::hash`] applies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    min_chars: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self { min_chars: 12 }
    }
}

impl Policy {
    /// A policy whose minimum is `min_chars` characters, not bytes.
    pub const fn with_min_chars(min_chars: usize) -> Self {
        Self { min_chars }
    }

    pub const fn min_chars(&self) -> usize {
        self.min_chars
    }

    /// Whether `password` is long enough and no longer than [`MAX_BYTES`].
    pub fn check(&self, password: &str) -> Result<(), PasswordError> {
        if password.len() > MAX_BYTES {
            return Err(PasswordError::TooLong {
                max_bytes: MAX_BYTES,
            });
        }
        if password.chars().count() < self.min_chars {
            return Err(PasswordError::TooShort {
                min_chars: self.min_chars,
            });
        }
        Ok(())
    }

    /// A PHC string for `password`, once it passes [`Policy::check`]. **Blocks.**
    pub fn hash(&self, password: &str) -> Result<String, PasswordError> {
        self.check(password)?;
        hash_unchecked(password)
    }
}

fn hash_unchecked(password: &str) -> Result<String, PasswordError> {
    hasher()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

/// Whether `password` matches the `stored` PHC string. **Blocks.**
///
/// An unreadable `stored` is false, as a wrong password is, so a corrupt row
/// signs nobody in and looks no different to whoever is trying.
pub fn verify(stored: &str, password: &str) -> bool {
    password.len() <= MAX_BYTES
        && hasher()
            .verify_password(password.as_bytes(), stored)
            .is_ok()
}

/// Costs what [`verify`] costs and is always false: call it when no account
/// has the name tried, so an unknown name answers no faster. **Blocks.**
pub fn verify_absent(password: &str) -> bool {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY
        .get_or_init(|| hash_unchecked("a password nobody has").expect("argon2 hashes a constant"));
    let _ = verify(dummy, password);
    false
}

/// Whether `stored` was made other than as [`Policy::hash`] makes one now:
/// another algorithm, version or parameters, or unreadable.
pub fn needs_rehash(stored: &str) -> bool {
    let Ok(hash) = PasswordHash::new(stored) else {
        return true;
    };
    hash.algorithm != argon2::ARGON2ID_IDENT
        || hash.version != Some(Version::V0x13.into())
        || Params::try_from(&hash).ok() != Some(params())
}

/// Why a password was not hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    TooShort {
        min_chars: usize,
    },
    TooLong {
        max_bytes: usize,
    },
    /// argon2 or the OS random source failed.
    Hash(String),
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { min_chars } => {
                write!(f, "the password must be at least {min_chars} characters")
            }
            Self::TooLong { max_bytes } => {
                write!(f, "the password must be at most {max_bytes} bytes")
            }
            Self::Hash(e) => write!(f, "the password could not be hashed: {e}"),
        }
    }
}

impl std::error::Error for PasswordError {}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";
    /// Made by argon2 0.5.3's `Argon2::default()`.
    const FROM_ARGON2_0_5: &str = "$argon2id$v=19$m=19456,t=2,p=1$7NwfKUJiyl5Q9n5qDUNBpA$RoDGU/g7McH81MkS6LuwU23Wue3fKpTDIW4Ydv9PNXg";

    #[test]
    fn a_password_verifies_against_its_own_hash_and_nothing_else() {
        let hash = Policy::default().hash(PASSWORD).unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{hash}"
        );
        assert!(verify(&hash, PASSWORD));
        assert!(!verify(&hash, "correct horse battery stapler"));
        assert!(!verify(&hash, ""));
        assert_ne!(hash, Policy::default().hash(PASSWORD).unwrap(), "salted");
    }

    #[test]
    fn an_unreadable_hash_signs_nobody_in() {
        for stored in ["", "not a phc string", "$argon2id$v=19$m=19456,t=2,p=1$x$y"] {
            assert!(!verify(stored, PASSWORD), "{stored:?}");
            assert!(needs_rehash(stored), "{stored:?}");
        }
    }

    #[test]
    fn a_hash_from_argon2_0_5_still_verifies_and_is_current() {
        assert!(verify(FROM_ARGON2_0_5, PASSWORD));
        assert!(!verify(FROM_ARGON2_0_5, "wrong"));
        assert!(!needs_rehash(FROM_ARGON2_0_5));
    }

    #[test]
    fn a_hash_under_other_parameters_needs_rehashing() {
        let cheaper = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8 * 1024, 1, 1, None).unwrap(),
        )
        .hash_password(PASSWORD.as_bytes())
        .unwrap()
        .to_string();
        assert!(
            verify(&cheaper, PASSWORD),
            "still verifies, at its own cost"
        );
        assert!(needs_rehash(&cheaper));

        let argon2i = Argon2::new(Algorithm::Argon2i, Version::V0x13, params())
            .hash_password(PASSWORD.as_bytes())
            .unwrap()
            .to_string();
        assert!(needs_rehash(&argon2i));

        assert!(!needs_rehash(&Policy::default().hash(PASSWORD).unwrap()));
    }

    #[test]
    fn the_minimum_counts_characters_and_the_maximum_bytes() {
        let policy = Policy::default();
        assert_eq!(
            policy.check(&"x".repeat(11)),
            Err(PasswordError::TooShort { min_chars: 12 })
        );
        assert_eq!(policy.check(&"x".repeat(12)), Ok(()));
        assert_eq!(policy.check(&"é".repeat(12)), Ok(()), "24 bytes, 12 chars");
        assert!(policy.check(&"é".repeat(11)).is_err(), "22 bytes, 11 chars");
        assert_eq!(Policy::with_min_chars(8).check("12345678"), Ok(()));

        assert_eq!(policy.check(&"x".repeat(MAX_BYTES)), Ok(()));
        let too_long = PasswordError::TooLong {
            max_bytes: MAX_BYTES,
        };
        assert_eq!(
            policy.check(&"x".repeat(MAX_BYTES + 1)),
            Err(too_long.clone())
        );
        assert_eq!(
            policy.check(&"é".repeat(MAX_BYTES / 2 + 1)),
            Err(too_long.clone())
        );
        let refused = Policy::with_min_chars(0).hash(&"x".repeat(MAX_BYTES + 1));
        assert_eq!(refused, Err(too_long));
    }

    #[test]
    fn an_overlong_password_never_verifies() {
        let long = "x".repeat(MAX_BYTES + 1);
        let hash = hash_unchecked(&long).unwrap();
        assert!(!verify(&hash, &long));
    }

    #[test]
    fn verifying_an_absent_account_is_always_false() {
        assert!(!verify_absent("a password nobody has"));
        assert!(!verify_absent(PASSWORD));
    }
}
