//! PEM text as people paste it: tidied, filtered to certificates, and refused
//! when a private key sits where a certificate goes.

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::Error;

/// The longest PEM text read; anything longer is refused before parsing.
pub const MAX_LEN: usize = 256 * 1024;

pub const CERTIFICATE: &str = "CERTIFICATE";
pub const PRIVATE_KEY: &str = "PRIVATE KEY";

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

/// The certificates in `pem`, leaf first; any other section is refused, a private key above all.
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
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::Malformed(e.to_string()))
}

/// The one private key in `pem`; an encrypted key and a second key are refused.
pub fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>, Error> {
    within_length(pem)?;
    if encrypted(pem) {
        return Err(Error::Encrypted);
    }
    let mut keys = PrivateKeyDer::pem_slice_iter(pem.as_bytes());
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
    let config = ::pem::EncodeConfig::new().set_line_ending(::pem::LineEnding::LF);
    ::pem::encode_config(&::pem::Pem::new(label, der), config)
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
}
