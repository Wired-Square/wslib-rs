use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::Secret;

/// How [`Secret::random`] writes its bytes as text, both unpadded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// RFC 4648 base64url, for machines.
    Base64Url,
    /// RFC 4648 base32 in upper case, for people to read and type.
    Base32,
}

impl Encoding {
    fn encode(self, bytes: &[u8]) -> String {
        match self {
            Self::Base64Url => encode(
                bytes,
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            ),
            Self::Base32 => encode(bytes, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
        }
    }
}

fn encode(bytes: &[u8], alphabet: &[u8]) -> String {
    let width = alphabet.len().trailing_zeros();
    let mask = (1 << width) - 1;
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(width as usize));
    let (mut buffer, mut bits) = (0u32, 0);
    for &byte in bytes {
        buffer = buffer << 8 | u32::from(byte);
        bits += 8;
        while bits >= width {
            bits -= width;
            out.push(alphabet[(buffer >> bits & mask) as usize].into());
        }
    }
    if bits > 0 {
        out.push(alphabet[(buffer << (width - bits) & mask) as usize].into());
    }
    out
}

impl Secret {
    /// `N` bytes from the OS, as text in `encoding`.
    pub fn random<const N: usize>(encoding: Encoding) -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new([0; N]);
        getrandom::fill(&mut *bytes)?;
        Ok(Self(encoding.encode(&*bytes)))
    }

    /// What to store in place of the secret: [`TokenHash::of`] its text.
    pub fn hash(&self) -> TokenHash {
        TokenHash::of(self.expose())
    }
}

/// The SHA-256 of a token's text in unpadded base64url, compared in constant time.
#[derive(Clone, Debug, Eq)]
pub struct TokenHash(String);

impl TokenHash {
    /// The hash of `text`, which a caller may first normalise as typing demands.
    pub fn of(text: &str) -> Self {
        Self(Encoding::Base64Url.encode(&Sha256::digest(text)))
    }

    /// A hash read back from storage, unchecked: one that is not a hash matches nothing.
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
    fn base32_is_rfc_4648_without_padding() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(Encoding::Base32.encode(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn base64url_is_rfc_4648_without_padding() {
        for (plain, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (b"\xfb\xff\xbf", "-_-_"),
        ] {
            assert_eq!(Encoding::Base64Url.encode(plain), encoded);
        }
    }

    #[test]
    fn random_secrets_have_the_encodings_length_and_differ() {
        let a = Secret::random::<32>(Encoding::Base64Url).unwrap();
        assert_eq!(a.expose().len(), 43);
        assert!(!a.matches(&Secret::random::<32>(Encoding::Base64Url).unwrap()));
        let b = Secret::random::<16>(Encoding::Base32).unwrap();
        assert_eq!(b.expose().len(), 26);
        assert!(
            b.expose()
                .bytes()
                .all(|c| matches!(c, b'A'..=b'Z' | b'2'..=b'7'))
        );
    }

    #[test]
    fn the_hash_is_the_one_wslib_auth_already_stores() {
        let hash = Secret::new("abc").hash();
        assert_eq!(hash.as_str(), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
        assert_eq!(hash, TokenHash::of("abc"));
    }

    #[test]
    fn a_hash_matches_its_stored_text_and_nothing_else() {
        let hash = TokenHash::of("abc");
        assert_eq!(hash, TokenHash::from_stored(hash.as_str()));
        assert_ne!(hash, TokenHash::of("abd"));
        assert_ne!(hash, TokenHash::from_stored(&hash.as_str()[1..]));
    }
}
