/// Standard base64, padding optional, ignoring the whitespace a TXT record
/// may fold in (RFC 6376 §3.6.1).
pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut padding = 0;
    for byte in text.bytes().filter(|b| !b.is_ascii_whitespace()) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            _ => return None,
        };
        if padding > 0 {
            return None;
        }
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    let leftover_is_zero = bits & ((1 << count) - 1) == 0;
    (count < 6 && padding <= 2 && leftover_is_zero).then_some(out)
}

const RSA_ENCRYPTION: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// The modulus length of an RSA public key, from a SubjectPublicKeyInfo as
/// RFC 6376 requires, or a bare PKCS #1 RSAPublicKey, which some publish.
pub(crate) fn rsa_modulus_bits(der: &[u8]) -> Option<u32> {
    spki_rsa_key(der).or(Some(der)).and_then(pkcs1_modulus_bits)
}

fn spki_rsa_key(der: &[u8]) -> Option<&[u8]> {
    let (spki, _) = tlv(der, 0x30)?;
    let (algorithm, rest) = tlv(spki, 0x30)?;
    let (oid, _) = tlv(algorithm, 0x06)?;
    if oid != RSA_ENCRYPTION {
        return None;
    }
    let (bit_string, _) = tlv(rest, 0x03)?;
    bit_string.strip_prefix(&[0])
}

fn pkcs1_modulus_bits(der: &[u8]) -> Option<u32> {
    let (sequence, _) = tlv(der, 0x30)?;
    let (modulus, rest) = tlv(sequence, 0x02)?;
    tlv(rest, 0x02)?;
    let significant: &[u8] = &modulus[modulus.iter().position(|&b| b != 0)?..];
    let bytes = u32::try_from(significant.len()).ok()?;
    Some(bytes * 8 - significant[0].leading_zeros())
}

/// One DER tag-length-value with the expected tag: its content and what
/// follows it.
fn tlv(der: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&first, rest) = der.split_first()?;
    if first != tag {
        return None;
    }
    let (&length, rest) = rest.split_first()?;
    let (length, rest) = if length < 0x80 {
        (usize::from(length), rest)
    } else {
        let octets = usize::from(length & 0x7f);
        if octets == 0 || octets > 4 || rest.len() < octets {
            return None;
        }
        let (bytes, rest) = rest.split_at(octets);
        (
            bytes.iter().fold(0usize, |n, &b| (n << 8) | usize::from(b)),
            rest,
        )
    };
    (rest.len() >= length).then(|| rest.split_at(length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_rfc_4648_vectors() {
        for (encoded, decoded) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
            ("Zm9v YmFy", "foobar"),
            ("Zm9vYg", "foob"),
        ] {
            assert_eq!(
                decode_base64(encoded).as_deref(),
                Some(decoded.as_bytes()),
                "{encoded}"
            );
        }
        for bad in ["Zm9v!", "Zg=x", "Z", "Zh=="] {
            assert_eq!(decode_base64(bad), None, "{bad}");
        }
    }

    #[test]
    fn rsa_key_sizes_come_from_the_modulus() {
        for (fixture, bits) in [
            (include_str!("../../testdata/dkim/rsa512.b64"), 512),
            (include_str!("../../testdata/dkim/rsa1024.b64"), 1024),
            (include_str!("../../testdata/dkim/rsa2048.b64"), 2048),
            (include_str!("../../testdata/dkim/rsa1024-pkcs1.b64"), 1024),
        ] {
            assert_eq!(
                rsa_modulus_bits(&decode_base64(fixture).unwrap()),
                Some(bits)
            );
        }
        assert_eq!(rsa_modulus_bits(b"not der"), None);
        assert_eq!(rsa_modulus_bits(&[0x30, 0x82, 0xff]), None);
    }
}
