const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let (mut buffer, mut bits) = (0u32, 0);
    for &byte in bytes {
        buffer = buffer << 8 | u32::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ALPHABET[(buffer >> bits & 0x3f) as usize].into());
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(buffer << (6 - bits) & 0x3f) as usize].into());
    }
    out
}

/// Unpadded, with unused trailing bits zero, so each byte string has one encoding.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0);
    for &c in text.as_bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = buffer << 6 | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    (buffer & ((1 << bits) - 1) == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_rfc_4648_without_padding() {
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
            assert_eq!(encode(plain), encoded);
            assert_eq!(decode(encoded).as_deref(), Some(plain));
        }
    }

    #[test]
    fn refuses_padding_the_standard_alphabet_and_stray_bits() {
        for text in ["Zg==", "Zm8=", "+/+/", "Z", "Zh", "Zm9", "Zm 9v"] {
            assert_eq!(decode(text), None, "{text}");
        }
    }
}
