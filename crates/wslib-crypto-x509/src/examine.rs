use std::fmt;
use std::time::SystemTime;

use crate::{CertificateView, ExtendedKeyUsage};

/// A server's certificate, and what is odd about it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    pub certificate: CertificateView,
    /// In the order found; none is a reason to refuse the certificate.
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    Expired,
    /// Post-dated, or the clock is wrong.
    NotYetValid,
    /// No client will match it to any name.
    NoSubjectAltName,
    HostNotCovered {
        host: String,
    },
    /// An extended key usage without server authentication.
    NoServerAuth,
    /// `CA:TRUE` on a certificate served as a leaf.
    CertificateAuthority,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => f.write_str("the certificate has expired"),
            Self::NotYetValid => f.write_str("the certificate is not valid yet"),
            Self::NoSubjectAltName => {
                f.write_str("the certificate has no subject alternative names")
            }
            Self::HostNotCovered { host } => write!(f, "the certificate does not cover {host}"),
            Self::NoServerAuth => {
                f.write_str("the certificate's extended key usage leaves out server authentication")
            }
            Self::CertificateAuthority => {
                f.write_str("the certificate is a certificate authority's")
            }
        }
    }
}

/// What is odd about `certificate` served at `now` to a client that reached it as `host`.
///
/// `now` is an argument so that a host with no clock yet is testable.
pub fn examine(certificate: CertificateView, host: Option<&str>, now: SystemTime) -> Report {
    let mut warnings = Vec::new();
    if certificate.not_after < now {
        warnings.push(Warning::Expired);
    } else if certificate.not_before > now {
        warnings.push(Warning::NotYetValid);
    }

    if certificate.sans.is_empty() {
        warnings.push(Warning::NoSubjectAltName);
    } else if let Some(host) = host
        && !certificate.sans.iter().any(|san| san.covers(host))
    {
        warnings.push(Warning::HostNotCovered {
            host: host.to_string(),
        });
    }

    if certificate
        .extended_key_usages
        .as_ref()
        .is_some_and(|usages| {
            !usages
                .iter()
                .any(|usage| matches!(usage, ExtendedKeyUsage::ServerAuth | ExtendedKeyUsage::Any))
        })
    {
        warnings.push(Warning::NoServerAuth);
    }

    if certificate.ca {
        warnings.push(Warning::CertificateAuthority);
    }

    Report {
        certificate,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::inspect_pem;
    use crate::testing::certificate;

    /// 2026-09-17 12:00 UTC.
    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_789_646_400)
    }

    fn examined(pem: &str, host: Option<&str>) -> Report {
        examine(inspect_pem(pem).expect("reads"), host, now())
    }

    #[test]
    fn a_freshly_made_certificate_has_no_warnings() {
        let report = examined(&certificate(|_| {}), Some("widget-01.local"));
        assert_eq!(report.warnings, []);
    }

    #[test]
    fn an_expired_certificate_warns_and_is_still_read() {
        let pem = certificate(|params| {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        });
        let report = examined(&pem, None);
        assert_eq!(report.warnings, [Warning::Expired]);
        assert_eq!(report.certificate.sans.len(), 1);
    }

    #[test]
    fn a_host_with_no_clock_reads_a_current_certificate_as_not_yet_valid() {
        let at_epoch = examine(
            inspect_pem(&certificate(|_| {})).unwrap(),
            None,
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(at_epoch.warnings, [Warning::NotYetValid]);
    }

    #[test]
    fn no_san_is_one_warning_and_not_also_a_mismatch() {
        let pem = certificate(|params| params.subject_alt_names.clear());
        let report = examined(&pem, Some("widget-01.local"));
        assert_eq!(report.warnings, [Warning::NoSubjectAltName]);
    }

    #[test]
    fn a_host_the_certificate_does_not_cover_is_named() {
        let pem = certificate(|_| {});
        assert_eq!(
            examined(&pem, Some("widget-02.local")).warnings,
            [Warning::HostNotCovered {
                host: "widget-02.local".into()
            }]
        );
        assert_eq!(examined(&pem, Some("widget-01.local")).warnings, []);
    }

    #[test]
    fn a_certificate_for_another_purpose_says_so() {
        let pem = certificate(|params| {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        });
        assert_eq!(examined(&pem, None).warnings, [Warning::NoServerAuth]);
        let any = certificate(|params| {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Any];
        });
        assert_eq!(examined(&any, None).warnings, []);
    }

    #[test]
    fn a_certificate_authoritys_certificate_says_so() {
        let pem = certificate(|params| {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        });
        assert_eq!(
            examined(&pem, None).warnings,
            [Warning::CertificateAuthority]
        );
    }
}
