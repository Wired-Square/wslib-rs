//! Recovery codes: each signs in once in place of a TOTP code. Ten of 80 bits
//! each, shown once as four groups of four base32 characters. Keep only
//! [`recovery_code_hash`] of each, and spend one by the hash of what is typed.

use sha2::{Digest, Sha256};
use wslib_secret::Secret;

use crate::key::base32;

const COUNT: usize = 10;
const CODE_BYTES: usize = 10;

/// Ten new codes to show this once, and the hash to keep of each, in the same
/// order.
pub fn generate_recovery_codes() -> Result<(Vec<Secret>, Vec<String>), getrandom::Error> {
    let codes = (0..COUNT)
        .map(|_| {
            let mut bytes = [0; CODE_BYTES];
            getrandom::fill(&mut bytes)?;
            Ok(grouped(&base32(&bytes)))
        })
        .collect::<Result<Vec<_>, getrandom::Error>>()?;
    let hashes = codes.iter().map(|code| recovery_code_hash(code)).collect();
    Ok((codes.into_iter().map(Secret::new).collect(), hashes))
}

/// The lower-case hex SHA-256 of a code with case, separators and whitespace
/// normalised away, and the digits base32 lacks read as the letters they
/// resemble, so a code hashes the same however it is typed.
pub fn recovery_code_hash(code: &str) -> String {
    use std::fmt::Write;
    let normalised: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| match c.to_ascii_uppercase() {
            '0' => 'O',
            '1' => 'I',
            '8' => 'B',
            c => c,
        })
        .collect();
    Sha256::digest(normalised.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn grouped(code: &str) -> String {
    code.as_bytes()
        .chunks(4)
        .map(|group| std::str::from_utf8(group).expect("base32 is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_distinct_codes_of_sixteen_base32_characters_in_four_groups() {
        let (codes, hashes) = generate_recovery_codes().expect("random");
        assert_eq!(codes.len(), COUNT);
        let mut seen = std::collections::BTreeSet::new();
        for (code, hash) in codes.iter().zip(&hashes) {
            let groups: Vec<&str> = code.expose().split('-').collect();
            assert_eq!(groups.len(), 4, "{}", code.expose());
            assert!(groups.iter().all(|g| {
                g.len() == 4
                    && g.bytes()
                        .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
            }));
            assert!(seen.insert(code.expose().to_owned()), "a repeated code");
            assert_eq!(*hash, recovery_code_hash(code.expose()));
        }
    }

    #[test]
    fn the_hash_is_the_hex_sha256_of_the_normalised_code() {
        assert_eq!(
            recovery_code_hash("ABCD-EFGH-IJKL-MNOP"),
            "e7e8b89c2721d290cc5f55425491ecd6831355e91063f20b39c22f9ec6a71f91",
            "what a store already holds must still match"
        );
    }

    #[test]
    fn a_code_hashes_the_same_however_it_is_typed() {
        let issued = recovery_code_hash("ABCD-EFGH-IJKL-MNOP");
        for typed in [
            "abcd efgh ijkl mnop",
            "ABCDEFGHIJKLMNOP",
            " abcd-EFGH_ijkl.mnop\n",
        ] {
            assert_eq!(recovery_code_hash(typed), issued, "{typed:?}");
        }
        assert_ne!(recovery_code_hash("ABCD-EFGH-IJKL-MNOQ"), issued);
    }

    #[test]
    fn a_digit_base32_lacks_reads_as_the_letter_it_resembles() {
        assert_eq!(
            recovery_code_hash("OIBA-ABCD-EFGH-IJKL"),
            recovery_code_hash("018a abcd efgh ijkl")
        );
        assert_ne!(
            recovery_code_hash("9AAA-AAAA-AAAA-AAAA"),
            recovery_code_hash("AAAA-AAAA-AAAA-AAAA")
        );
    }
}
