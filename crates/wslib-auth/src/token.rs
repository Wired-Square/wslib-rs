use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The session's bearer secret, as the cookie carries it; its `Debug` prints nothing of it.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken(String);

impl SessionToken {
    /// 32 bytes from the OS, in unpadded base64url.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// A token as a client presented it, unchecked.
    pub fn from_presented(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// What is stored in place of the token.
    pub fn hash(&self) -> TokenHash {
        TokenHash(URL_SAFE_NO_PAD.encode(Sha256::digest(&self.0)))
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(..)")
    }
}

/// The SHA-256 of a [`SessionToken`] in unpadded base64url, compared in constant time.
#[derive(Debug, Clone, Eq)]
pub struct TokenHash(String);

impl TokenHash {
    /// A hash read back from storage.
    pub fn from_stored(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq for TokenHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_32_random_bytes_and_hashes_as_sha256_base64url() {
        let a = SessionToken::generate().unwrap();
        assert_eq!(a.expose().len(), 43);
        assert_ne!(a, SessionToken::generate().unwrap());
        assert_eq!(format!("{a:?}"), "SessionToken(..)");

        let hash = SessionToken::from_presented("abc").hash();
        assert_eq!(hash.as_str(), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
        assert_eq!(hash, TokenHash::from_stored(hash.as_str()));
        assert_ne!(hash, SessionToken::from_presented("abd").hash());
    }
}
