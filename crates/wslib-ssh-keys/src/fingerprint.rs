use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use sha2::{Digest, Sha256};

use crate::Error;

/// OpenSSH's fingerprint: SHA-256 of the key's wire blob, shown as `SHA256:` and unpadded base64.
///
/// It is the string `ssh-keygen -l` prints, and not the colon-hex digest of a
/// DER public key that `wslib_crypto::Fingerprint` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The fingerprint of a wire blob, the base64-decoded second field of a key line.
    pub fn of_blob(blob: &[u8]) -> Self {
        Self(Sha256::digest(blob).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHA256:{}", STANDARD_NO_PAD.encode(self.0))
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        s.strip_prefix("SHA256:")
            .and_then(|digest| STANDARD_NO_PAD.decode(digest).ok())
            .and_then(|digest| digest.try_into().ok())
            .map(Self)
            .ok_or(Error::NotAFingerprint)
    }
}
