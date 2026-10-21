use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use wslib_secret::Secret;

use crate::STEP_SECONDS;

const DIGITS: u32 = 6;
const KEY_BYTES: usize = 20;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A 160-bit TOTP key.
///
/// ```
/// # use std::time::SystemTime;
/// let key = wslib_auth_totp::Key::generate().expect("random");
/// let uri = key.otpauth_uri("Pump House", "ops");
/// let code = key.code_at(SystemTime::now());
/// let step = key.accepted_step(&code, SystemTime::now()).expect("accepted");
/// ```
#[derive(Clone)]
pub struct Key([u8; KEY_BYTES]);

impl Key {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut key = [0; KEY_BYTES];
        getrandom::fill(&mut key)?;
        Ok(Self(key))
    }

    /// The key as [`Self::to_base32`] wrote it: unpadded upper-case base32 of
    /// exactly 160 bits, so a stored key that isn't one signs nobody in.
    pub fn from_base32(text: &str) -> Option<Self> {
        base32_decode(text)?.try_into().ok().map(Self)
    }

    /// The form an authenticator app is given to type in.
    pub fn to_base32(&self) -> Secret {
        Secret::new(base32(&self.0))
    }

    /// The `otpauth://` URI for a QR code; `issuer` names the service in the app.
    pub fn otpauth_uri(&self, issuer: &str, account: &str) -> Secret {
        let issuer = percent_encode(issuer);
        Secret::new(format!(
            "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}\
             &algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
            account = percent_encode(account),
            secret = base32(&self.0),
        ))
    }

    /// The code an authenticator app shows at `at`.
    pub fn code_at(&self, at: SystemTime) -> String {
        self.code(step_at(at))
    }

    /// The latest step within one of `now`'s whose code is `code`, spaces
    /// ignored, with every candidate compared in full.
    pub fn accepted_step(&self, code: &str, now: SystemTime) -> Option<u64> {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let now = step_at(now);
        let mut accepted = None;
        for step in now.saturating_sub(1)..=now.saturating_add(1) {
            if bool::from(self.code(step).as_bytes().ct_eq(code.as_bytes())) {
                accepted = Some(step);
            }
        }
        accepted
    }

    fn code(&self, step: u64) -> String {
        format!(
            "{:0width$}",
            hotp(&self.0, step, DIGITS),
            width = DIGITS as usize
        )
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

fn step_at(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / STEP_SECONDS)
}

/// RFC 4226 §5.3.
fn hotp(key: &[u8], counter: u64, digits: u32) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(&counter.to_be_bytes());
    let mac = mac.finalize().into_bytes();
    let at = usize::from(mac[mac.len() - 1] & 0x0f);
    let truncated = u32::from_be_bytes([mac[at], mac[at + 1], mac[at + 2], mac[at + 3]]);
    (truncated & 0x7fff_ffff) % 10u32.pow(digits)
}

fn percent_encode(text: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[(buffer >> bits) as usize & 31]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(BASE32[(buffer << (5 - bits)) as usize & 31]));
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = BASE32.iter().position(|&b| b == c)?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const RFC_KEY: &[u8; 20] = b"12345678901234567890";

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// Mid-step, so a code taken one step either side is unambiguous.
    const NOW: u64 = 1_700_000_015;

    #[test]
    fn base32_matches_rfc_4648_unpadded() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(plain.as_bytes()), encoded);
            assert_eq!(base32_decode(encoded).as_deref(), Some(plain.as_bytes()));
        }
        assert_eq!(base32_decode("MZXW6="), None);
        assert_eq!(base32_decode("mzxw6"), None);
    }

    #[test]
    fn hotp_matches_rfc_4226_appendix_d() {
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, code) in expected.into_iter().enumerate() {
            assert_eq!(hotp(RFC_KEY, counter as u64, 6), code, "counter {counter}");
        }
    }

    #[test]
    fn totp_matches_rfc_6238_appendix_b_sha1() {
        for (time, code) in [
            (59, 94287082),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ] {
            let step = step_at(at(time));
            assert_eq!(hotp(RFC_KEY, step, 8), code, "T = {time}");
            assert_eq!(
                Key(*RFC_KEY).code_at(at(time)),
                format!("{:06}", code % 1_000_000),
                "T = {time}"
            );
        }
    }

    #[test]
    fn a_code_is_accepted_one_step_either_side_and_no_further() {
        let key = Key(*RFC_KEY);
        let now = step_at(at(NOW));
        for step in [now - 1, now, now + 1] {
            assert_eq!(key.accepted_step(&key.code(step), at(NOW)), Some(step));
        }
        assert_eq!(key.accepted_step(&key.code(now - 2), at(NOW)), None);
        assert_eq!(key.accepted_step(&key.code(now + 2), at(NOW)), None);
        let code = key.code(now);
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(key.accepted_step(&spaced, at(NOW)), Some(now));
        assert_eq!(key.accepted_step("", at(NOW)), None);
    }

    #[test]
    fn the_uri_names_the_issuer_and_account_percent_encoded() {
        let key = Key::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").expect("160 bits");
        assert_eq!(
            key.otpauth_uri("Pump House: 2", "ops@site").expose(),
            "otpauth://totp/Pump%20House%3A%202:ops%40site?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
             &issuer=Pump%20House%3A%202&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn a_key_is_160_bits_in_base32_and_nothing_else_reads_as_one() {
        let key = Key::generate().expect("random");
        let text = key.to_base32();
        assert_eq!(text.expose().len(), 32);
        assert_eq!(
            Key::from_base32(text.expose()).map(|k| k.0),
            Some(key.0),
            "round trips"
        );
        assert_ne!(Key::generate().expect("random").0, key.0);
        for stored in ["", "A", "MZXW6YTBOI", &"A".repeat(40), &"a".repeat(32)] {
            assert!(Key::from_base32(stored).is_none(), "{stored:?}");
        }
    }

    #[test]
    fn a_key_prints_nothing_of_itself() {
        let key = Key::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").expect("160 bits");
        assert_eq!(format!("{key:?}"), "Key(..)");
    }
}
