use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};

use crate::Error;

/// The SHA-256 of some DER; it displays as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `AB:CD:…`, as browsers and `openssl x509 -fingerprint` show it.
    pub fn colons(&self) -> String {
        self.0
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// Hex in either case, with or without colons.
impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let digits: String = s.trim().chars().filter(|&c| c != ':').collect();
        if digits.len() != 64 || !digits.is_ascii() {
            return Err(Error::NotAFingerprint);
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(digits.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| Error::NotAFingerprint)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| Error::NotAFingerprint)?;
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_spellings_read_back_as_the_same_fingerprint() {
        let fingerprint = Fingerprint::of(b"certificate");
        let hex = fingerprint.to_string();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(fingerprint.colons().len(), 95);
        assert_eq!(fingerprint.colons().to_lowercase().replace(':', ""), hex);
        assert_eq!(hex.parse::<Fingerprint>().unwrap(), fingerprint);
        assert_eq!(
            fingerprint.colons().parse::<Fingerprint>().unwrap(),
            fingerprint
        );
        assert!(hex[..62].parse::<Fingerprint>().is_err());
        assert!(format!("{}zz", &hex[..62]).parse::<Fingerprint>().is_err());
    }
}
