//! BIMI assertion records (draft-brand-indicators-for-message-identification).

use crate::text::{RawTag, check_version, first_of_each, starts_with_version, tag_list, unwrap};
use crate::{FaultCode, Parsed, SyntaxFault, Tag};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BimiRecord {
    pub tags: Vec<Tag>,
    /// `l=`: the logo's `https:` URL; empty when the domain declines to show
    /// one.
    pub location: Option<String>,
    /// `a=`: the mark certificate's `https:` URL.
    pub authority: Option<String>,
}

impl BimiRecord {
    /// An empty `l=`: the domain publishes no indicator.
    pub fn is_declined(&self) -> bool {
        self.location.as_deref() == Some("")
    }
}

impl Parsed<BimiRecord> {
    /// Unknown tags are ignored; any other fault discards the record.
    pub fn is_usable(&self) -> bool {
        self.faults
            .iter()
            .all(|fault| fault.code == FaultCode::UnknownTag)
    }
}

pub fn is_bimi(txt: &str) -> bool {
    starts_with_version(txt, "BIMI1")
}

pub fn parse(input: &str) -> Parsed<BimiRecord> {
    let (_, text) = unwrap(input);
    let mut faults = Vec::new();
    let all = tag_list(input, text, &mut faults);
    check_version(input, &all, "BIMI1", &mut faults);
    let mut record = BimiRecord {
        tags: all.iter().map(|tag| tag.written(true)).collect(),
        ..BimiRecord::default()
    };
    for tag in first_of_each(all, |a, b| a.eq_ignore_ascii_case(b), &mut faults) {
        match tag.name.to_ascii_lowercase().as_str() {
            "v" => {}
            "l" => record.location = Some(https_or_empty(&tag, "l", &mut faults)),
            "a" => record.authority = Some(https_or_empty(&tag, "a", &mut faults)),
            name => faults.push(SyntaxFault::named(
                FaultCode::UnknownTag,
                tag.span.clone(),
                name,
            )),
        }
    }
    if record.location.is_none() {
        faults.push(crate::text::missing(input, "l"));
    }
    faults.sort_by_key(|fault| fault.span.start);
    Parsed { record, faults }
}

fn https_or_empty(tag: &RawTag<'_>, name: &str, faults: &mut Vec<SyntaxFault>) -> String {
    let value = tag.value;
    if !value.is_empty() {
        match value.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => {
                if rest.is_empty() || rest.starts_with('/') || value.contains(char::is_whitespace) {
                    faults.push(SyntaxFault::named(
                        FaultCode::InvalidUri,
                        tag.value_span.clone(),
                        name,
                    ));
                }
            }
            Some(_) => faults.push(SyntaxFault::named(
                FaultCode::InsecureUri,
                tag.value_span.clone(),
                name,
            )),
            None => faults.push(SyntaxFault::named(
                FaultCode::InvalidUri,
                tag.value_span.clone(),
                name,
            )),
        }
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(input: &str) -> Vec<FaultCode> {
        parse(input).faults.iter().map(|fault| fault.code).collect()
    }

    #[test]
    fn a_record_with_logo_and_certificate() {
        let parsed =
            parse("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem");
        assert!(parsed.is_usable());
        assert_eq!(
            parsed.record.location.as_deref(),
            Some("https://example.com/logo.svg")
        );
        assert_eq!(
            parsed.record.authority.as_deref(),
            Some("https://example.com/vmc.pem")
        );
        assert!(!parsed.record.is_declined());
    }

    #[test]
    fn an_empty_location_declines() {
        let parsed = parse("v=BIMI1; l=; a=;");
        assert!(parsed.is_usable());
        assert!(parsed.record.is_declined());
    }

    #[test]
    fn every_fault_code() {
        for (input, code) in [
            (
                "v=BIMI1; l=http://example.com/logo.svg",
                FaultCode::InsecureUri,
            ),
            (
                "v=BIMI1; l=https://example.com/l.svg; a=ftp://example.com/vmc",
                FaultCode::InsecureUri,
            ),
            ("v=BIMI1; l=example.com/logo.svg", FaultCode::InvalidUri),
            ("v=BIMI1; l=https://", FaultCode::InvalidUri),
            (
                "v=BIMI1; a=https://example.com/vmc.pem",
                FaultCode::MissingTag,
            ),
            (
                "l=https://example.com/l.svg; v=BIMI1",
                FaultCode::VersionNotFirst,
            ),
            ("v=BIMI2; l=", FaultCode::InvalidVersion),
            ("v=BIMI1; l=; l=", FaultCode::DuplicateTag),
        ] {
            assert_eq!(codes(input), [code], "{input}");
            assert!(!parse(input).is_usable(), "{input}");
        }
        assert_eq!(codes("v=BIMI1; l=; avp=brand"), [FaultCode::UnknownTag]);
        assert!(parse("v=BIMI1; l=; avp=brand").is_usable());
    }

    #[test]
    fn recognises_bimi_records() {
        assert!(is_bimi("v=BIMI1; l="));
        assert!(!is_bimi("v=DMARC1; p=none"));
    }
}
