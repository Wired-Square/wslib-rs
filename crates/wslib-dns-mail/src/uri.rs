use std::ops::Range;

use crate::text::offset_in;
use crate::{FaultCode, SyntaxFault};

/// A reporting destination from a `rua=` or `ruf=` list.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportUri {
    /// The URI without any `!size` suffix.
    pub uri: String,
    /// The `!size` limit, in bytes.
    pub max_size: Option<u64>,
    pub span: Range<usize>,
}

impl ReportUri {
    pub fn scheme(&self) -> &str {
        self.uri.split_once(':').map_or("", |(scheme, _)| scheme)
    }

    /// The address of a `mailto:` URI, without any `?` header fields.
    pub fn mailbox(&self) -> Option<&str> {
        let rest = self
            .uri
            .get(..7)?
            .eq_ignore_ascii_case("mailto:")
            .then(|| &self.uri[7..])?;
        Some(rest.split('?').next().unwrap_or(rest))
    }

    /// The domain reports go to: a mailbox's domain or an `https:` host.
    pub fn domain(&self) -> Option<String> {
        if let Some(mailbox) = self.mailbox() {
            return mailbox
                .rsplit_once('@')
                .map(|(_, domain)| wslib_dns::normalise(domain));
        }
        let rest = self.uri.split_once("://")?.1;
        let authority = rest.split(['/', '?', '#']).next()?;
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let host = host.split(':').next()?;
        (!host.is_empty()).then(|| wslib_dns::normalise(host))
    }
}

pub(crate) enum Schemes {
    /// DMARC: any URI, with `mailto:` checked closely and `!size` allowed.
    Dmarc,
    /// TLS-RPT: `mailto:` or `https:` only.
    TlsRpt,
}

/// Parses a comma-separated URI list, keeping the valid entries and reporting
/// the rest as [`FaultCode::InvalidUri`].
pub(crate) fn parse_list(
    input: &str,
    value: &str,
    tag: &str,
    schemes: Schemes,
    faults: &mut Vec<SyntaxFault>,
) -> Vec<ReportUri> {
    let mut uris = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        let start = offset_in(input, entry);
        let span = start..start + entry.len();
        match parse_one(entry, &schemes) {
            Some((uri, max_size)) => uris.push(ReportUri {
                uri: uri.to_owned(),
                max_size,
                span,
            }),
            None => faults.push(SyntaxFault::named(FaultCode::InvalidUri, span, tag)),
        }
    }
    uris
}

fn parse_one<'a>(entry: &'a str, schemes: &Schemes) -> Option<(&'a str, Option<u64>)> {
    let (uri, max_size) = match (schemes, entry.rsplit_once('!')) {
        (Schemes::Dmarc, Some((uri, size))) => (uri, Some(parse_size(size)?)),
        (_, Some(_)) => return None,
        (_, None) => (entry, None),
    };
    let (scheme, rest) = uri.split_once(':')?;
    let scheme_ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_ok || rest.is_empty() || uri.contains(char::is_whitespace) {
        return None;
    }
    let valid = match scheme.to_ascii_lowercase().as_str() {
        "mailto" => valid_mailbox(rest.split('?').next().unwrap_or(rest)),
        "https" => rest
            .strip_prefix("//")
            .is_some_and(|r| !r.is_empty() && !r.starts_with('/')),
        _ => matches!(schemes, Schemes::Dmarc),
    };
    valid.then_some((uri, max_size))
}

fn valid_mailbox(address: &str) -> bool {
    address.rsplit_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && wslib_dns::validate_hostname(domain).is_ok() && domain.contains('.')
    })
}

/// `digits [k|m|g|t]`, in bytes with units of 1024 (RFC 7489 §6.4).
fn parse_size(size: &str) -> Option<u64> {
    let (digits, unit) = match size.char_indices().last()? {
        (at, c) if c.is_ascii_alphabetic() => (&size[..at], Some(c.to_ascii_lowercase())),
        _ => (size, None),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let shift = match unit {
        None => 0,
        Some('k') => 10,
        Some('m') => 20,
        Some('g') => 30,
        Some('t') => 40,
        Some(_) => return None,
    };
    digits.parse::<u64>().ok()?.checked_mul(1 << shift)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dmarc(value: &str) -> (Vec<ReportUri>, Vec<SyntaxFault>) {
        let mut faults = Vec::new();
        let uris = parse_list(value, value, "rua", Schemes::Dmarc, &mut faults);
        (uris, faults)
    }

    #[test]
    fn mailto_with_a_size_limit() {
        let (uris, faults) = dmarc("mailto:dmarc@example.com!10m, mailto:b@example.net");
        assert!(faults.is_empty());
        assert_eq!(uris[0].uri, "mailto:dmarc@example.com");
        assert_eq!(uris[0].max_size, Some(10 << 20));
        assert_eq!(uris[0].mailbox(), Some("dmarc@example.com"));
        assert_eq!(uris[0].domain().as_deref(), Some("example.com"));
        assert_eq!(uris[1].span, 30..50);
    }

    #[test]
    fn bad_entries_are_faults_and_good_ones_survive() {
        let (uris, faults) = dmarc(
            "dmarc@example.com,mailto:,mailto:x@localhost,mailto:a@example.com!5x,mailto:ok@example.com",
        );
        assert_eq!(uris.len(), 1);
        assert_eq!(faults.len(), 4);
        assert!(faults.iter().all(|f| f.code == FaultCode::InvalidUri));
    }

    #[test]
    fn tls_rpt_takes_mailto_and_https_only() {
        let mut faults = Vec::new();
        let value = "https://reports.example.com/tlsrpt,mailto:tls@example.com,ftp://example.com,mailto:a@example.com!1k";
        let uris = parse_list(value, value, "rua", Schemes::TlsRpt, &mut faults);
        assert_eq!(uris.len(), 2);
        assert_eq!(uris[0].domain().as_deref(), Some("reports.example.com"));
        assert_eq!(faults.len(), 2);
    }
}
