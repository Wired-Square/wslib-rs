//! PEM text as people paste it: tidied, filtered to certificates, and refused
//! when a private key sits where a certificate goes.

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zeroize::Zeroizing;

use crate::Error;

/// The longest PEM text read; anything longer is refused before parsing.
pub const MAX_LEN: usize = 256 * 1024;

pub const CERTIFICATE: &str = "CERTIFICATE";
pub const PRIVATE_KEY: &str = "PRIVATE KEY";
pub const PUBLIC_KEY: &str = "PUBLIC KEY";

/// Every section of `pem`, each line trimmed and ending in LF, with nothing between them.
///
/// The base64 is kept verbatim, so the result holds the same certificates and
/// keys; what goes is commentary such as "Bag Attributes" and CRLF endings.
pub fn normalise(pem: &str) -> Result<String, Error> {
    within_length(pem)?;
    let out = sections(pem, |_| true)?;
    if out.is_empty() {
        return Err(Error::NotPem);
    }
    Ok(out)
}

/// The `CERTIFICATE` sections of `pem`, as [`normalise`] writes them, and nothing else.
pub fn certificate_sections(pem: &str) -> Result<String, Error> {
    within_length(pem)?;
    sections(pem, |label| label == CERTIFICATE)
}

/// The certificates in `pem`, at least one and leaf first; any other section is refused, a private key above all.
pub fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    within_length(pem)?;
    // Labels before the decoder, which would skip a foreign section silently.
    if !labels(pem).any(|label| label == CERTIFICATE) {
        return Err(missing(pem, CERTIFICATE));
    }
    if let Some(label) = labels(pem).find(|label| *label != CERTIFICATE) {
        return Err(Error::Beside {
            label: label.to_string(),
        });
    }
    let certificates = CertificateDer::pem_slice_iter(sections(pem, |_| true)?.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::Malformed(e.to_string()))?;
    if certificates.is_empty() {
        return Err(none_decodes());
    }
    Ok(certificates)
}

/// The one private key in `pem`; an encrypted key and a second key are refused.
pub fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>, Error> {
    within_length(pem)?;
    if encrypted(pem) {
        return Err(Error::Encrypted);
    }
    let tidy = sections(pem, |_| true)?;
    let mut keys = PrivateKeyDer::pem_slice_iter(tidy.as_bytes());
    let key = match keys.next() {
        Some(key) => key.map_err(|e| Error::Malformed(e.to_string()))?,
        None => return Err(missing(pem, PRIVATE_KEY)),
    };
    if keys.next().is_some() {
        return Err(Error::MoreThanOneKey);
    }
    Ok(key)
}

/// PEM text for `der` under `label`, with LF line endings on every platform.
pub fn encode(label: &str, der: &[u8]) -> String {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BYTES_PER_LINE: usize = 48;
    let base64_len = der.len().div_ceil(3) * 4;
    let lines = der.len().div_ceil(BYTES_PER_LINE);
    let capacity =
        "-----BEGIN -----\n-----END -----\n".len() + 2 * label.len() + base64_len + lines;
    // Sized exactly, so a private key is never left behind in a reallocated buffer.
    let mut out = String::with_capacity(capacity);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in der.chunks(BYTES_PER_LINE) {
        for group in line.chunks(3) {
            let bits = group.iter().enumerate().fold(0u32, |bits, (i, byte)| {
                bits | u32::from(*byte) << (16 - 8 * i)
            });
            for i in 0..4 {
                out.push(if i <= group.len() {
                    char::from(BASE64[((bits >> (18 - 6 * i)) & 0x3f) as usize])
                } else {
                    '='
                });
            }
        }
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    debug_assert_eq!(out.capacity(), capacity);
    out
}

/// A PKCS#8 key as `PRIVATE KEY` PEM, wiped on drop.
pub fn encode_private_key(key: &PrivatePkcs8KeyDer<'_>) -> Zeroizing<String> {
    Zeroizing::new(encode(PRIVATE_KEY, key.secret_pkcs8_der()))
}

fn within_length(pem: &str) -> Result<(), Error> {
    if pem.len() > MAX_LEN {
        return Err(Error::TooLong {
            limit: MAX_LEN,
            actual: pem.len(),
        });
    }
    Ok(())
}

pub(crate) fn none_decodes() -> Error {
    Error::Malformed("no certificate decodes".into())
}

fn missing(pem: &str, wanted: &'static str) -> Error {
    match labels(pem).next() {
        Some(found) => Error::Missing {
            wanted,
            found: found.to_string(),
        },
        None => Error::NotPem,
    }
}

/// PKCS#8's own label, or the older `Proc-Type` header that the decoder reports as bad base64.
fn encrypted(pem: &str) -> bool {
    labels(pem).any(|label| label.contains("ENCRYPTED"))
        || pem
            .lines()
            .any(|line| line.trim().starts_with("Proc-Type: 4,ENCRYPTED"))
}

fn sections(pem: &str, keep: impl Fn(&str) -> bool) -> Result<String, Error> {
    let mut out = String::new();
    let mut open: Option<(&str, bool)> = None;
    for line in pem.lines().map(str::trim) {
        let kept = match open {
            None => match begins(line) {
                Some(label) => {
                    let kept = keep(label);
                    open = Some((label, kept));
                    kept
                }
                None => false,
            },
            Some((label, kept)) => {
                if ends(line) == Some(label) {
                    open = None;
                }
                kept
            }
        };
        if kept {
            out.push_str(line);
            out.push('\n');
        }
    }
    match open {
        Some((label, _)) => Err(Error::Unterminated {
            label: label.to_string(),
        }),
        None => Ok(out),
    }
}

fn labels(pem: &str) -> impl Iterator<Item = &str> {
    pem.lines().filter_map(|line| begins(line.trim()))
}

fn begins(line: &str) -> Option<&str> {
    line.strip_prefix("-----BEGIN ")?.strip_suffix("-----")
}

fn ends(line: &str) -> Option<&str> {
    line.strip_prefix("-----END ")?.strip_suffix("-----")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{certificate, key_pem};
    use std::sync::Arc;

    #[test]
    fn a_key_pasted_where_a_certificate_goes_is_named_for_what_it_is() {
        let e = certificates(&key_pem()).expect_err("a key is not a certificate");
        assert!(
            matches!(&e, Error::Missing { wanted: CERTIFICATE, found } if found == PRIVATE_KEY),
            "{e:?}"
        );
        let encrypted =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(
            matches!(certificates(encrypted), Err(Error::Missing { found, .. }) if found.contains(PRIVATE_KEY))
        );
    }

    #[test]
    fn a_private_key_beside_the_certificate_is_refused_so_it_is_never_served() {
        let pem = certificate(|_| {});
        for combined in [format!("{}{pem}", key_pem()), format!("{pem}{}", key_pem())] {
            assert_eq!(
                certificates(&combined),
                Err(Error::Beside {
                    label: PRIVATE_KEY.to_string()
                })
            );
        }
        let crl = format!("{pem}-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n");
        assert_eq!(
            certificates(&crl),
            Err(Error::Beside {
                label: "X509 CRL".to_string()
            })
        );
    }

    #[test]
    fn a_foreign_section_ahead_of_the_certificate_is_named_before_the_decoder_runs() {
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nMIIB\n\
                      -----END RSA PRIVATE KEY-----\n";
        let e = certificates(&format!("{legacy}{}", certificate(|_| {}))).unwrap_err();
        assert!(matches!(e, Error::Beside { .. }), "{e:?}");
    }

    #[test]
    fn only_the_certificate_sections_of_a_file_are_kept() {
        let pem = certificate(|_| {});
        let key = key_pem();
        for combined in [
            format!("{key}{pem}"),
            format!("{pem}{key}"),
            format!("{pem}{key}{pem}"),
        ] {
            let kept = certificate_sections(&combined).expect("well formed");
            assert!(!kept.contains(PRIVATE_KEY), "{kept}");
            assert!(kept.starts_with(&pem), "{kept}");
            assert_eq!(
                kept.matches("BEGIN CERTIFICATE").count(),
                combined.matches("BEGIN CERTIFICATE").count()
            );
        }
    }

    #[test]
    fn an_encrypted_key_is_refused_in_either_spelling() {
        let pkcs8 =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
                      DEK-Info: AES-128-CBC,00\n\nMIIB\n-----END RSA PRIVATE KEY-----\n";
        for encrypted in [pkcs8, legacy] {
            assert_eq!(private_key(encrypted), Err(Error::Encrypted));
        }
    }

    #[test]
    fn one_key_reads_and_two_are_refused_rather_than_guessed_between() {
        assert!(matches!(
            private_key(&key_pem()),
            Ok(PrivateKeyDer::Pkcs8(_))
        ));
        let two = format!("{}{}", key_pem(), key_pem());
        assert_eq!(private_key(&two), Err(Error::MoreThanOneKey));
        assert_eq!(
            private_key(&certificate(|_| {})),
            Err(Error::Missing {
                wanted: PRIVATE_KEY,
                found: CERTIFICATE.to_string()
            })
        );
    }

    #[test]
    fn text_that_is_not_pem_at_all_says_so() {
        assert_eq!(certificates("\u{0}\u{1}not text"), Err(Error::NotPem));
        assert_eq!(private_key("\u{0}\u{1}not text"), Err(Error::NotPem));
        assert_eq!(normalise("\u{0}\u{1}not text"), Err(Error::NotPem));
    }

    #[test]
    fn text_longer_than_any_real_pair_is_refused_before_it_is_parsed() {
        let huge = "-".repeat(MAX_LEN + 1);
        for refused in [
            certificates(&huge).map(drop),
            private_key(&huge).map(drop),
            normalise(&huge).map(drop),
            certificate_sections(&huge).map(drop),
        ] {
            assert!(matches!(refused, Err(Error::TooLong { .. })), "{refused:?}");
        }
    }

    #[test]
    fn a_half_copied_file_is_refused_with_the_reason() {
        let half: String = certificate(|_| {})
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            normalise(&half),
            Err(Error::Unterminated {
                label: CERTIFICATE.to_string()
            })
        );
    }

    #[test]
    fn tidying_drops_what_is_outside_the_markers_and_keeps_the_bytes() {
        let pem = certificate(|_| {});
        let messy = format!(
            "Bag Attributes\r\n    friendlyName: widget\r\n{}\r\ntrailing junk\r\n",
            pem.trim().replace('\n', "\r\n")
        );
        assert_eq!(normalise(&messy).expect("tidies"), pem);
    }

    #[test]
    fn indented_markers_decode_as_if_they_were_not() {
        let indent = |pem: &str| {
            pem.lines()
                .map(|line| format!("  {line}\n"))
                .collect::<String>()
        };
        let pem = certificate(|_| {});
        assert_eq!(certificates(&indent(&pem)), certificates(&pem));
        assert_eq!(private_key(&indent(&key_pem())), private_key(&key_pem()));
    }

    #[test]
    fn a_chain_keeps_its_leaf_first_and_the_issuers_after_it() {
        let leaf = certificate(|_| {});
        let issuer = certificate(|params| {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        });
        let chain = format!("{leaf}{issuer}");
        let read = certificates(&chain).expect("reads");
        assert_eq!(read.len(), 2);
        assert_eq!(read[0], certificates(&leaf).unwrap()[0]);
        assert_eq!(normalise(&chain).expect("tidies"), chain);
    }

    #[test]
    fn encoding_matches_the_pem_crate_it_replaced_at_every_remainder() {
        let fixture = include_str!("../testdata/lengths.pem");
        let encoded: String = [0usize, 1, 2, 3, 4, 47, 48, 49, 50, 96, 97, 144, 145]
            .into_iter()
            .map(|n| {
                let der: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
                encode("TEST", &der)
            })
            .collect();
        assert_eq!(encoded, fixture);
    }

    #[test]
    fn a_public_key_encodes_as_openssl_ec_pubout_writes_it() {
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("../testdata/p256.sec1.pem")).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let signer = wslib_crypto::Signer::new(provider, &key).unwrap();
        assert_eq!(
            encode(PUBLIC_KEY, signer.spki()),
            include_str!("../testdata/p256.spki.pem")
        );
    }

    #[test]
    fn an_encoded_private_key_reads_back_as_the_same_key() {
        let key = wslib_crypto::KeyAlgorithm::EcP384.generate().unwrap();
        let pem = encode_private_key(&key);
        assert_eq!(private_key(&pem), Ok(PrivateKeyDer::Pkcs8(key.clone_key())));
    }
}
