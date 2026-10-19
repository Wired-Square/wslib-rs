//! SMTP TLS reporting records (RFC 8460).

use crate::text::{check_version, first_of_each, starts_with_version, tag_list, unwrap};
use crate::uri::{self, ReportUri, Schemes};
use crate::{FaultCode, Parsed, Tag};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsRptRecord {
    pub tags: Vec<Tag>,
    /// The valid `mailto:` and `https:` destinations of `rua=`.
    pub aggregate: Vec<ReportUri>,
}

impl Parsed<TlsRptRecord> {
    /// Version first and at least one valid report destination.
    pub fn is_usable(&self) -> bool {
        let version_ok = !self.faults.iter().any(|fault| {
            matches!(
                fault.code,
                FaultCode::MissingVersion | FaultCode::InvalidVersion | FaultCode::VersionNotFirst
            )
        });
        version_ok && !self.record.aggregate.is_empty()
    }
}

pub fn is_tls_rpt(txt: &str) -> bool {
    starts_with_version(txt, "TLSRPTv1")
}

/// Extension tags are allowed (§3), so unknown tags are not faults.
pub fn parse(input: &str) -> Parsed<TlsRptRecord> {
    let (_, text) = unwrap(input);
    let mut faults = Vec::new();
    let all = tag_list(input, text, &mut faults);
    check_version(input, &all, "TLSRPTv1", &mut faults);
    let mut record = TlsRptRecord {
        tags: all.iter().map(|tag| tag.written(true)).collect(),
        ..TlsRptRecord::default()
    };
    let tags = first_of_each(all, |a, b| a.eq_ignore_ascii_case(b), &mut faults);
    match tags.iter().find(|tag| tag.name.eq_ignore_ascii_case("rua")) {
        Some(rua) => {
            record.aggregate =
                uri::parse_list(input, rua.value, "rua", Schemes::TlsRpt, &mut faults)
        }
        None => faults.push(crate::text::missing(input, "rua")),
    }
    faults.sort_by_key(|fault| fault.span.start);
    Parsed { record, faults }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(input: &str) -> Vec<FaultCode> {
        parse(input).faults.iter().map(|fault| fault.code).collect()
    }

    #[test]
    fn mailto_and_https_destinations() {
        let parsed = parse("v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.com/v1");
        assert!(parsed.is_usable());
        assert_eq!(parsed.record.aggregate.len(), 2);
    }

    #[test]
    fn every_fault_code() {
        for (input, code) in [
            ("v=TLSRPTv1", FaultCode::MissingTag),
            ("v=TLSRPTv1; rua=tls@example.com", FaultCode::InvalidUri),
            (
                "rua=mailto:tls@example.com; v=TLSRPTv1",
                FaultCode::VersionNotFirst,
            ),
            (
                "v=TLSRPTv2; rua=mailto:tls@example.com",
                FaultCode::InvalidVersion,
            ),
        ] {
            assert_eq!(codes(input), [code], "{input}");
            assert!(!parse(input).is_usable(), "{input}");
        }
        assert!(
            parse("v=TLSRPTv1; rua=mailto:tls@example.com; ext=1")
                .faults
                .is_empty()
        );
    }
}
