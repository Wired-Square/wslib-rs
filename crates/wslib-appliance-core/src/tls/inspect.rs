//! Reading a certificate, and saying what is odd about it, for an operator; the
//! reading and the checks are `wslib-crypto-x509`'s. Nothing here is a trust
//! decision: no chain, no revocation.
//!
//! Refuse only what cannot be what the operator meant, such as a key in the
//! certificate box, an encrypted key, two keys or a mismatched one.
//! Everything else, including validity dates, is a warning: a box with a dead
//! clock reads every certificate as not yet valid, and refusing there bricks it.

use chrono::{DateTime, Utc};
use rustls::pki_types::CertificateDer;
use wslib_appliance_types::tls::{CertificateReport, CertificateView, MAX_PEM_LEN};
use wslib_crypto_x509::pem::{self, CERTIFICATE, PRIVATE_KEY};
use wslib_crypto_x509::{Error, Warning};

use super::TlsError;

/// Read a certificate's DER.
pub(super) fn read(der: &[u8]) -> Result<wslib_crypto_x509::CertificateView, TlsError> {
    wslib_crypto_x509::inspect(der).map_err(|e| {
        TlsError::Pem(format!(
            "this is not a certificate this build can read: {}",
            decoding(e)
        ))
    })
}

/// What a caller sees. Only the names a browser matches are listed.
pub(super) fn view(certificate: &wslib_crypto_x509::CertificateView) -> CertificateView {
    CertificateView {
        subject: certificate.subject.clone(),
        issuer: certificate.issuer.clone(),
        sans: certificate
            .sans
            .iter()
            .filter(|san| san.is_host())
            .map(ToString::to_string)
            .collect(),
        not_before: certificate.not_before.into(),
        not_after: certificate.not_after.into(),
        sha256: certificate.fingerprint.to_string(),
        key: certificate.key.to_string(),
        self_signed: certificate.self_signed,
    }
}

/// Read the first certificate in some PEM text.
#[doc(hidden)]
#[cfg(any(test, feature = "testing"))]
pub fn inspect_pem(pem: &str) -> Result<CertificateView, TlsError> {
    Ok(parse(pem)?.view())
}

/// A leaf certificate, read, beside the DER it was read from.
pub(super) struct Leaf {
    read: wslib_crypto_x509::CertificateView,
    der: CertificateDer<'static>,
}

impl Leaf {
    pub(super) fn view(&self) -> CertificateView {
        view(&self.read)
    }

    pub(super) fn sha256(&self) -> String {
        self.read.fingerprint.to_string()
    }

    pub(super) fn is_authority(&self) -> bool {
        self.read.ca
    }

    pub(super) fn into_der(self) -> CertificateDer<'static> {
        self.der
    }
}

/// The leaf (leading section) of some PEM text, read. Nothing but certificates:
/// the text this accepts becomes the file every viewer may download.
pub(super) fn parse(pem: &str) -> Result<Leaf, TlsError> {
    within_length(pem)?;
    let der = pem::certificates(pem)
        .map_err(|e| refused(e, Wanted::Certificate))?
        .swap_remove(0);
    Ok(Leaf {
        read: read(&der)?,
        der,
    })
}

/// Tidy PEM text for storage: each section's own bytes, in order, LF-ended,
/// and nothing between them.
pub(crate) fn normalise_pem(pem: &str) -> Result<String, TlsError> {
    within_length(pem)?;
    pem::normalise(pem).map_err(|e| match e {
        Error::NotPem => TlsError::Pem(
            "that text holds no PEM section — nothing beginning `-----BEGIN`. A `.pfx`, \
             `.p12` or `.der` file has to be converted first."
                .to_string(),
        ),
        e => refused(e, Wanted::Certificate),
    })
}

/// The `CERTIFICATE` sections of `pem`, verbatim, and nothing else.
fn certificate_sections(pem: &str) -> Result<String, TlsError> {
    pem::certificate_sections(pem).map_err(|e| refused(e, Wanted::Certificate))
}

/// Say what an operator should know about a certificate. `host` is the name the
/// asking browser is using, if any; `now` is an argument so a test can move it.
pub(super) fn examine(leaf: &Leaf, host: Option<&str>, now: DateTime<Utc>) -> CertificateReport {
    let certificate = leaf.view();
    let warnings = wslib_crypto_x509::examine(leaf.read.clone(), host, now.into())
        .warnings
        .iter()
        .map(|warning| sentence(warning, &certificate, now, BROWSERS_REFUSE))
        .collect();
    CertificateReport {
        certificate,
        warnings,
    }
}

const BROWSERS_REFUSE: &str = "Browsers will refuse it until it is replaced.";

/// `expired` is the sentence that follows the expiry date.
fn sentence(
    warning: &Warning,
    certificate: &CertificateView,
    now: DateTime<Utc>,
    expired: &str,
) -> String {
    let day = |at: DateTime<Utc>| at.format("%-d %B %Y");
    match warning {
        Warning::Expired => format!(
            "This certificate expired on {}. {expired}",
            day(certificate.not_after)
        ),
        Warning::NotYetValid => format!(
            "This certificate is not valid until {}, and this appliance thinks it is {}. \
             Either the certificate is post-dated, or this box has no clock and has not \
             reached a time server yet.",
            day(certificate.not_before),
            day(now),
        ),
        Warning::NoHostName => "This certificate names no host or address among its subject \
                                alternative names, so no browser will match it to any address. \
                                A common name alone has not been accepted since 2017."
            .to_string(),
        Warning::HostNotCovered { host } => format!(
            "This certificate does not cover {host}, which is the address this page is open \
             on. A browser reaching the appliance that way will report a name mismatch."
        ),
        Warning::NoServerAuth => "This certificate's extended key usage does not include server \
                                  authentication, so browsers will refuse it however it is \
                                  installed."
            .to_string(),
        Warning::CertificateAuthority => "This is a certificate authority's certificate, not a \
                                          server's. Serving it works in some clients and not \
                                          others; the certificate to install here is the one \
                                          issued *to* this appliance."
            .to_string(),
        other => {
            let said = other.to_string();
            let mut chars = said.chars();
            chars.next().map_or_else(String::new, |first| {
                format!("{}{}.", first.to_uppercase(), chars.as_str())
            })
        }
    }
}

/// An authority's certificate, read for installing: one `CERTIFICATE` section
/// that says `CA:TRUE`, refused otherwise because a leaf cannot sign. The text
/// handed back is the section alone, tidied, which is what the row keeps.
pub(crate) fn read_authority(
    pem: &str,
    now: DateTime<Utc>,
) -> Result<(String, CertificateReport), TlsError> {
    let leaf = parse(pem)?;
    if pem::certificates(pem).map_or(0, |all| all.len()) > 1 {
        return Err(TlsError::Pem(
            "that text holds more than one certificate. An authority is installed one at a \
             time: paste your site's root — the last in a chain — or the intermediate that \
             signed the hosts; either vouches."
                .to_string(),
        ));
    }
    if !leaf.is_authority() {
        return Err(TlsError::Pem(
            "this is a host's own certificate, not an authority's — it does not say CA:TRUE. \
             The certificate to install here is the authority that *signed* the hosts this \
             appliance connects to; a host nobody's authority signed is pinned instead."
                .to_string(),
        ));
    }
    let certificate = leaf.view();
    let warnings = wslib_crypto_x509::examine(leaf.read.clone(), None, now.into())
        .warnings
        .iter()
        .filter(|warning| matches!(warning, Warning::Expired | Warning::NotYetValid))
        .map(|warning| {
            sentence(
                warning,
                &certificate,
                now,
                "This appliance does not check an authority's own dates, so what it signed is \
                 still trusted — but its owner has probably reissued it, and hosts it signs \
                 from now on may carry the new one.",
            )
        })
        .collect();
    Ok((
        certificate_sections(pem)?,
        CertificateReport {
            certificate,
            warnings,
        },
    ))
}

/// Refuse a key that is not one, is more than one, or is not this certificate's,
/// as the process's crypto provider reads it.
pub(super) fn check_pair(leaf: &Leaf, key_pem: &str) -> Result<(), TlsError> {
    within_length(key_pem)?;
    let key = pem::private_key(key_pem).map_err(|e| refused(e, Wanted::PrivateKey))?;
    let provider = super::provider().map_err(|e| TlsError::Internal(e.to_string()))?;
    let matches = wslib_crypto::key_matches(&provider, &key, &leaf.read.spki)
        .map_err(|e| TlsError::Pem(format!("this private key is not usable: {e}")))?;
    if matches {
        Ok(())
    } else {
        Err(TlsError::Mismatched)
    }
}

/// Refuse text longer than anything a real pair occupies, before parsing it.
fn within_length(pem: &str) -> Result<(), TlsError> {
    if pem.len() > MAX_PEM_LEN {
        return Err(TlsError::TooLong {
            limit: MAX_PEM_LEN,
            actual: pem.len(),
        });
    }
    Ok(())
}

/// Which of the two boxes some text was pasted into.
#[derive(Clone, Copy)]
enum Wanted {
    Certificate,
    PrivateKey,
}

impl Wanted {
    fn noun(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::PrivateKey => "private key",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Certificate => CERTIFICATE,
            Self::PrivateKey => PRIVATE_KEY,
        }
    }
}

/// The sentence for text the reader refused, for somebody who pasted it into
/// the box `wanted` names.
fn refused(e: Error, wanted: Wanted) -> TlsError {
    TlsError::Pem(match e {
        Error::TooLong { limit, actual } => return TlsError::TooLong { limit, actual },
        Error::NotPem => format!(
            "This appliance needs a {} in PEM form — text beginning `-----BEGIN {}-----`. \
             A `.pfx`, `.p12` or `.der` file has to be converted first.",
            wanted.noun(),
            wanted.label()
        ),
        Error::Missing { found, .. } => match wanted {
            Wanted::Certificate if found.contains(PRIVATE_KEY) => {
                "That is a private key, not a certificate — the two boxes are the other way \
                 around."
                    .to_string()
            }
            Wanted::PrivateKey if found == CERTIFICATE => {
                "That is a certificate, not a private key — the two boxes are the other way \
                 around."
                    .to_string()
            }
            _ => format!(
                "This appliance needs a {} in PEM form, and that text holds a {found} \
                 section instead.",
                wanted.noun()
            ),
        },
        Error::Beside { label } if label.contains(PRIVATE_KEY) => {
            "That text holds a private key beside the certificate. Paste only the certificate \
             here — the key goes in its own box, and the certificate is a file every signed-in \
             viewer may download."
                .to_string()
        }
        Error::Beside { label } => format!(
            "That text holds a {label} section beside the certificate. Paste the \
             certificate, its chain if there is one, and nothing else."
        ),
        Error::Unterminated { label } => format!(
            "that text opens a {label} section and never ends it — it looks like only \
             part of the file was copied"
        ),
        Error::Encrypted => "That private key is encrypted with a passphrase, and this appliance \
                             has nowhere to keep one. Decrypt it first: `openssl pkey -in key.pem \
                             -out decrypted.pem`."
            .to_string(),
        Error::MoreThanOneKey => "that is more than one private key. Paste the one that belongs \
                                  to the certificate, and nothing else."
            .to_string(),
        e => format!(
            "the {} could not be decoded: {}",
            wanted.noun(),
            decoding(e)
        ),
    })
}

/// What the decoder said, without the reader's own prefix.
fn decoding(e: Error) -> String {
    match e {
        Error::Malformed(why) => why,
        e => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use wslib_crypto::{KeyAlgorithm, Signer};

    fn signer() -> Signer {
        let key = KeyAlgorithm::EcP256.generate().expect("key");
        Signer::new(super::super::provider().unwrap(), &key.into()).expect("loads")
    }

    fn key_pem() -> String {
        pem::encode(
            PRIVATE_KEY,
            KeyAlgorithm::EcP256
                .generate()
                .expect("key")
                .secret_pkcs8_der(),
        )
    }

    /// A certificate built to order rather than a fixture, which would expire.
    fn certificate(build: impl FnOnce(&mut rcgen::CertificateParams)) -> String {
        let mut params = rcgen::CertificateParams::new(vec!["widget-01.local".to_string()])
            .expect("a usable name");
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        build(&mut params);
        signed(params)
    }

    fn signed(mut params: rcgen::CertificateParams) -> String {
        params.serial_number = Some(1u64.into());
        pem::encode(
            CERTIFICATE,
            params.self_signed(&signer()).expect("sign").der(),
        )
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 17, 12, 0, 0).unwrap()
    }

    fn examined(pem: &str, host: Option<&str>) -> CertificateReport {
        examined_at(pem, host, now())
    }

    fn examined_at(pem: &str, host: Option<&str>, now: DateTime<Utc>) -> CertificateReport {
        examine(&parse(pem).expect("parses"), host, now)
    }

    #[test]
    fn a_freshly_minted_pair_reports_its_names_its_key_and_no_warnings() {
        let pem = certificate(|_| {});
        let report = examined(&pem, Some("widget-01.local"));

        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.certificate.sans, ["widget-01.local"]);
        assert_eq!(report.certificate.key, "ECDSA P-256");
        assert!(report.certificate.self_signed);
        assert_eq!(report.certificate.subject, report.certificate.issuer);
        assert_eq!(report.certificate.sha256.len(), 64);
        assert!(
            report
                .certificate
                .sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex: {}",
            report.certificate.sha256
        );
    }

    #[test]
    fn an_expired_certificate_warns_and_is_still_installable() {
        let pem = certificate(|params| {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        });
        let report = examined(&pem, None);

        assert_eq!(
            report.warnings,
            [
                "This certificate expired on 1 January 2021. Browsers will refuse it until it is \
              replaced."
            ]
        );
        assert_eq!(report.certificate.sans, ["widget-01.local"]);
    }

    #[test]
    fn a_certificate_from_a_box_with_no_clock_warns_about_the_clock_not_the_file() {
        let pem = certificate(|_| {});
        let at_epoch = examined_at(&pem, None, Utc.timestamp_opt(0, 0).unwrap());

        assert_eq!(at_epoch.warnings.len(), 1, "{:?}", at_epoch.warnings);
        assert!(
            at_epoch.warnings[0].contains("time server"),
            "the warning has to point at the clock: {:?}",
            at_epoch.warnings
        );
    }

    #[test]
    fn a_certificate_with_no_san_warns_that_nothing_will_ever_match_it() {
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "widget-01.local");
        let pem = signed(params);

        let report = examined(&pem, Some("widget-01.local"));
        assert!(report.certificate.sans.is_empty());
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(
            report.warnings[0].contains("names no host or address"),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn a_name_this_page_is_open_on_that_the_certificate_does_not_cover_is_named() {
        let pem = certificate(|_| {});
        let report = examined(&pem, Some("widget-02.local"));

        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(
            report.warnings[0].contains("widget-02.local"),
            "{:?}",
            report.warnings
        );
        assert!(examined(&pem, Some("widget-01.local")).warnings.is_empty());
    }

    #[test]
    fn an_address_in_a_certificate_reads_as_an_address_and_an_email_is_not_listed() {
        let pem = certificate(|params| {
            params.subject_alt_names = vec![
                rcgen::SanType::IpAddress("192.168.1.10".parse().expect("v4")),
                rcgen::SanType::IpAddress("::1".parse().expect("v6")),
                rcgen::SanType::Rfc822Name("ops@example.com".try_into().expect("ascii")),
            ];
        });
        assert_eq!(
            inspect_pem(&pem).expect("reads").sans,
            ["192.168.1.10", "::1"]
        );
    }

    #[test]
    fn a_certificate_that_signs_for_something_else_says_so() {
        let pem = certificate(|params| {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        });
        let report = examined(&pem, Some("widget-01.local"));
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("server authentication")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn a_certificate_authoritys_certificate_says_so() {
        let pem = certificate(|params| {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        });
        let report = examined(&pem, Some("widget-01.local"));
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("certificate authority")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn a_key_pasted_into_the_certificate_box_is_refused_by_name() {
        let e = inspect_pem(&key_pem()).expect_err("a key is not a certificate");
        assert!(
            e.to_string().contains("the other way around"),
            "the refusal has to say which box: {e}"
        );
    }

    /// The file `openssl pkcs12 -nodes` writes: rustls's reader would skip the
    /// key and serve the rest to every viewer, so the key is refused by label.
    #[test]
    fn a_private_key_beside_the_certificate_is_refused_so_it_is_never_served() {
        let pem = certificate(|_| {});
        let key = key_pem();
        for combined in [format!("{key}{pem}"), format!("{pem}{key}")] {
            let e = parse(&combined).err().expect("a key beside a certificate");
            assert!(e.to_string().contains("beside the certificate"), "{e}");
        }
        let odd = format!("{pem}-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n");
        let e = parse(&odd).err().expect("a CRL is not a certificate");
        assert!(e.to_string().contains("X509 CRL section beside"), "{e}");
    }

    #[test]
    fn only_the_certificate_sections_of_a_file_are_what_is_served() {
        let pem = certificate(|_| {});
        let key = key_pem();
        // Either side of the certificate, and between two of them: a filter that
        // found the first certificate and kept the rest would pass one of these.
        for combined in [
            format!("{key}{pem}"),
            format!("{pem}{key}"),
            format!("{pem}{key}{pem}"),
        ] {
            let served = certificate_sections(&combined).expect("well formed");
            assert!(!served.contains("PRIVATE KEY"), "{served}");
            assert!(served.starts_with(&pem), "{served}");
            assert_eq!(
                served.matches("BEGIN CERTIFICATE").count(),
                combined.matches("BEGIN CERTIFICATE").count()
            );
        }
    }

    /// A known-but-undecodable section ahead of the certificate is named for
    /// what it is, not reported as the certificate failing to decode.
    #[test]
    fn a_foreign_section_ahead_of_the_certificate_is_named_before_the_decoder_runs() {
        let pem = certificate(|_| {});
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nMIIB\n\
                      -----END RSA PRIVATE KEY-----\n";
        let e = parse(&format!("{legacy}{pem}"))
            .err()
            .expect("a key ahead of it");
        assert!(e.to_string().contains("beside the certificate"), "{e}");
    }

    #[test]
    fn an_encrypted_key_says_how_to_decrypt_it() {
        let leaf = parse(&certificate(|_| {})).expect("a certificate to check against");
        let pkcs8 =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
                      DEK-Info: AES-128-CBC,00\n\nMIIB\n-----END RSA PRIVATE KEY-----\n";
        for encrypted in [pkcs8, legacy] {
            let e = check_pair(&leaf, encrypted).expect_err("no passphrase to decrypt it with");
            assert!(e.to_string().contains("openssl pkey"), "{e}");
        }
    }

    /// Each box names its own marker, and an empty key box does not tell the
    /// operator to paste a certificate.
    #[test]
    fn a_file_that_is_not_pem_at_all_says_what_to_convert_for_the_box_it_went_in() {
        let e = inspect_pem("\u{0}\u{1}not text").expect_err("binary");
        assert!(e.to_string().contains("BEGIN CERTIFICATE"), "{e}");
        assert!(e.to_string().contains(".pfx"), "{e}");

        let leaf = parse(&certificate(|_| {})).expect("a certificate");
        let e = check_pair(&leaf, "\u{0}\u{1}not text").expect_err("binary");
        assert!(e.to_string().contains("BEGIN PRIVATE KEY"), "{e}");

        // After tidying, which is what the install does first, the sentence is
        // about PEM rather than about either box.
        let e = normalise_pem("\u{0}\u{1}not text").expect_err("binary");
        assert!(e.to_string().contains("no PEM section"), "{e}");
    }

    #[test]
    fn an_encrypted_key_in_the_certificate_box_is_told_the_boxes_are_swapped() {
        let e = inspect_pem(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n",
        )
        .expect_err("a key, whatever else it is");
        assert!(e.to_string().contains("the other way around"), "{e}");
    }

    #[test]
    fn two_keys_are_refused_rather_than_guessed_between() {
        let pem = certificate(|_| {});
        let two = format!("{}{}", key_pem(), key_pem());
        let e = check_pair(&parse(&pem).expect("a certificate"), &two).expect_err("which one?");
        assert!(e.to_string().contains("more than one"), "{e}");
    }

    #[test]
    fn a_key_that_is_not_the_certificates_is_mismatched() {
        let leaf = parse(&certificate(|_| {})).expect("a certificate");
        assert!(matches!(
            check_pair(&leaf, &key_pem()),
            Err(TlsError::Mismatched)
        ));
    }

    #[test]
    fn text_longer_than_any_real_pair_is_refused_before_it_is_parsed() {
        let huge = "-".repeat(MAX_PEM_LEN + 1);
        assert!(matches!(inspect_pem(&huge), Err(TlsError::TooLong { .. })));
    }

    #[test]
    fn a_half_copied_file_is_refused_with_the_reason() {
        let pem = certificate(|_| {});
        let half: String = pem.lines().take(3).collect::<Vec<_>>().join("\n");
        let e = normalise_pem(&half).expect_err("no END line");
        assert!(e.to_string().contains("only part of the file"), "{e}");
    }

    #[test]
    fn tidying_drops_what_is_outside_the_markers_and_keeps_the_bytes() {
        let pem = certificate(|_| {});
        let messy = format!(
            "Bag Attributes\r\n    friendlyName: widget\r\n{}\r\ntrailing junk\r\n",
            pem.trim().replace('\n', "\r\n")
        );

        let tidy = normalise_pem(&messy).expect("tidies");
        assert_eq!(tidy, pem, "the same bytes, without the commentary");
        assert!(!tidy.contains('\r'));
        assert_eq!(
            inspect_pem(&tidy).expect("reads").sha256,
            inspect_pem(&pem).expect("reads").sha256
        );
    }

    #[test]
    fn a_chain_keeps_its_leaf_first_and_the_issuers_after_it() {
        let leaf = certificate(|_| {});
        let issuer = certificate(|params| {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        });
        let chain = format!("{leaf}{issuer}");

        assert_eq!(
            inspect_pem(&chain).expect("reads").sha256,
            inspect_pem(&leaf).expect("reads").sha256,
            "the leaf is what this appliance serves"
        );
        assert_eq!(normalise_pem(&chain).expect("tidies"), chain);
    }

    #[test]
    fn a_peers_der_inspects_the_same_as_our_own() {
        let pem = certificate(|_| {});
        let der = parse(&pem).expect("decodes").into_der();
        assert_eq!(
            view(&read(&der).expect("reads")),
            inspect_pem(&pem).expect("reads")
        );
    }

    #[test]
    fn an_authority_warns_only_about_its_dates_and_a_leaf_or_two_are_refused() {
        let authority = certificate(|params| {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.extended_key_usages = Vec::new();
            params.subject_alt_names = Vec::new();
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        });
        let (kept, report) = read_authority(&authority, now()).expect("an authority");
        assert_eq!(kept, authority);
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(report.warnings[0].contains("does not check an authority's own dates"));

        let leaf = certificate(|_| {});
        assert!(read_authority(&leaf, now()).is_err());
        assert!(read_authority(&format!("{authority}{authority}"), now()).is_err());
    }
}
