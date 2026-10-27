use std::fmt;
use std::str::FromStr;

/// The SHA-256 of the server's DER SubjectPublicKeyInfo, as a pairing URI pins it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpkiSha256([u8; 32]);

impl SpkiSha256 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SpkiSha256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Lower-case hex.
impl fmt::Display for SpkiSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for SpkiSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpkiSha256({self})")
    }
}

/// Hex in either case, with or without colons.
impl FromStr for SpkiSha256 {
    type Err = NotAPin;

    fn from_str(s: &str) -> Result<Self, NotAPin> {
        let digits: Vec<u8> = s.trim().bytes().filter(|&b| b != b':').collect();
        if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(NotAPin);
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| NotAPin)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| NotAPin)?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("not a pin: 64 hex digits, with or without colons")]
pub struct NotAPin;
