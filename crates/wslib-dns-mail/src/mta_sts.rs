//! MTA-STS (RFC 8461): the `_mta-sts` TXT record and the policy file.

use std::ops::Range;

use crate::text::{check_version, first_of_each, offset_in, starts_with_version, tag_list, unwrap};
use crate::{FaultCode, Parsed, SyntaxFault, Tag};

/// The longest `max_age` a policy may give, in seconds (§3.2).
pub const MAX_AGE_LIMIT: u32 = 31_557_600;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MtaStsRecord {
    pub tags: Vec<Tag>,
    /// `id=`, when it is 1 to 32 letters and digits.
    pub id: Option<String>,
}

impl Parsed<MtaStsRecord> {
    /// Extension tags are allowed (§3.1); any other fault discards the record.
    pub fn is_usable(&self) -> bool {
        self.faults.iter().all(|fault| fault.code.is_advisory())
    }
}

pub fn is_mta_sts(txt: &str) -> bool {
    starts_with_version(txt, "STSv1")
}

pub fn parse_record(input: &str) -> Parsed<MtaStsRecord> {
    let (_, text) = unwrap(input);
    let mut faults = Vec::new();
    let all = tag_list(input, text, &mut faults);
    check_version(input, &all, "STSv1", &mut faults);
    let mut record = MtaStsRecord {
        tags: all.iter().map(|tag| tag.written(true)).collect(),
        ..MtaStsRecord::default()
    };
    let tags = first_of_each(all, |a, b| a.eq_ignore_ascii_case(b), &mut faults);
    match tags.iter().find(|tag| tag.name.eq_ignore_ascii_case("id")) {
        Some(id)
            if (1..=32).contains(&id.value.len())
                && id.value.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            record.id = Some(id.value.to_owned());
        }
        Some(id) => faults.push(SyntaxFault::named(
            FaultCode::InvalidTagValue,
            id.value_span.clone(),
            "id",
        )),
        None => faults.push(crate::text::missing(input, "id")),
    }
    faults.sort_by_key(|fault| fault.span.start);
    Parsed { record, faults }
}

/// A policy file (§3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MtaStsPolicy {
    /// Every `key: value` line, as written.
    pub fields: Vec<Tag>,
    pub mode: Option<Mode>,
    pub mx: Vec<MxPattern>,
    /// In seconds, when valid and within [`MAX_AGE_LIMIT`].
    pub max_age: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Mode {
    Enforce,
    Testing,
    None,
}

/// An `mx:` host, or `*.` and a domain to match any one label under it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MxPattern {
    pub pattern: String,
    pub span: Range<usize>,
}

impl MxPattern {
    /// Whether `host` matches, per §4.1: a wildcard stands for exactly one
    /// leftmost label.
    pub fn matches(&self, host: &str) -> bool {
        let host = wslib_dns::normalise(host);
        let pattern = wslib_dns::normalise(&self.pattern);
        match pattern.strip_prefix("*.") {
            Some(parent) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == parent),
            None => host == pattern,
        }
    }
}

impl MtaStsPolicy {
    /// Whether any `mx:` pattern matches `host`.
    pub fn covers(&self, host: &str) -> bool {
        self.mx.iter().any(|pattern| pattern.matches(host))
    }
}

impl Parsed<MtaStsPolicy> {
    /// A sender can apply the policy: version, mode and `max_age` are valid,
    /// and there are `mx:` patterns unless the mode is `none`.
    pub fn is_usable(&self) -> bool {
        let fatal = self.faults.iter().any(|fault| {
            matches!(
                fault.code,
                FaultCode::MissingVersion
                    | FaultCode::InvalidVersion
                    | FaultCode::MissingTag
                    | FaultCode::DuplicateTag
            ) || (fault.code == FaultCode::InvalidTagValue && fault.name.as_deref() != Some("mx"))
        });
        !fatal && self.record.mode.is_some() && self.record.max_age.is_some()
    }
}

/// Parses a policy file. Lines end in CRLF or LF; unknown keys are ignored.
pub fn parse_policy(input: &str) -> Parsed<MtaStsPolicy> {
    let mut faults = Vec::new();
    let mut policy = MtaStsPolicy::default();
    for line in input.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        let start = offset_in(input, line);
        let line_span = start..start + line.len();
        let Some((key, value)) = line.split_once(':') else {
            faults.push(SyntaxFault::new(FaultCode::MalformedLine, line_span));
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let value_start = offset_in(input, value);
        let value_span = value_start..value_start + value.len();
        let name = key.to_ascii_lowercase();
        let seen = policy.fields.iter().any(|field| field.name == name);
        policy.fields.push(Tag {
            name: name.clone(),
            value: value.to_owned(),
            span: line_span.clone(),
        });
        if seen && matches!(name.as_str(), "version" | "mode" | "max_age") {
            faults.push(SyntaxFault::named(
                FaultCode::DuplicateTag,
                line_span,
                &name,
            ));
            continue;
        }
        let mut invalid = || {
            faults.push(SyntaxFault::named(
                FaultCode::InvalidTagValue,
                value_span.clone(),
                &name,
            ))
        };
        match name.as_str() {
            "version" if value == "STSv1" => {}
            "version" => faults.push(SyntaxFault::named(
                FaultCode::InvalidVersion,
                value_span.clone(),
                "version",
            )),
            "mode" => match value {
                "enforce" => policy.mode = Some(Mode::Enforce),
                "testing" => policy.mode = Some(Mode::Testing),
                "none" => policy.mode = Some(Mode::None),
                _ => invalid(),
            },
            "max_age" => {
                let age = (value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| value.parse::<u64>().ok())
                    .flatten();
                match age
                    .and_then(|age| u32::try_from(age).ok())
                    .filter(|&age| age <= MAX_AGE_LIMIT)
                {
                    Some(age) => policy.max_age = Some(age),
                    None => invalid(),
                }
            }
            "mx" => {
                let host = value.strip_prefix("*.").unwrap_or(value);
                if wslib_dns::validate_hostname(host).is_ok() && host.contains('.') {
                    policy.mx.push(MxPattern {
                        pattern: value.to_owned(),
                        span: value_span.clone(),
                    });
                } else {
                    invalid();
                }
            }
            _ => {}
        }
    }
    let end = input.len()..input.len();
    let written = |name: &str| policy.fields.iter().any(|field| field.name == name);
    if !written("version") {
        faults.push(SyntaxFault::new(FaultCode::MissingVersion, end.clone()));
    }
    for name in ["mode", "max_age"] {
        if !written(name) {
            faults.push(SyntaxFault::named(FaultCode::MissingTag, end.clone(), name));
        }
    }
    if policy.mode.is_some_and(|mode| mode != Mode::None) && !written("mx") {
        faults.push(SyntaxFault::named(FaultCode::MissingTag, end, "mx"));
    }
    Parsed {
        record: policy,
        faults,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(input: &str) -> Vec<FaultCode> {
        parse_policy(input)
            .faults
            .iter()
            .map(|fault| fault.code)
            .collect()
    }

    #[test]
    fn the_txt_record_needs_a_short_alphanumeric_id() {
        assert!(parse_record("v=STSv1; id=20160831085700Z;").is_usable());
        assert_eq!(
            parse_record("v=STSv1; id=20160831085700Z")
                .record
                .id
                .as_deref(),
            Some("20160831085700Z")
        );
        for (input, code) in [
            ("v=STSv1", FaultCode::MissingTag),
            ("v=STSv1; id=2016-08-31", FaultCode::InvalidTagValue),
            ("v=STSv1; id=", FaultCode::InvalidTagValue),
            (
                "v=STSv1; id=123456789012345678901234567890123",
                FaultCode::InvalidTagValue,
            ),
            ("id=1; v=STSv1", FaultCode::VersionNotFirst),
        ] {
            let parsed = parse_record(input);
            assert_eq!(
                parsed.faults.iter().map(|f| f.code).collect::<Vec<_>>(),
                [code],
                "{input}"
            );
            assert!(!parsed.is_usable(), "{input}");
        }
        assert!(is_mta_sts("v=STSv1; id=1"));
        let parsed = parse_record("v=stsv1; id=1");
        assert_eq!(
            parsed.faults.iter().map(|f| f.code).collect::<Vec<_>>(),
            [FaultCode::NoncanonicalVersion]
        );
        assert!(parsed.is_usable());
    }

    #[test]
    fn the_rfc_example_policy() {
        let policy = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmx: backupmx.example.com\r\nmax_age: 604800\r\n";
        let parsed = parse_policy(policy);
        assert_eq!(parsed.faults, []);
        assert!(parsed.is_usable());
        assert_eq!(parsed.record.mode, Some(Mode::Enforce));
        assert_eq!(parsed.record.max_age, Some(604_800));
        assert_eq!(parsed.record.mx.len(), 3);
        assert_eq!(&policy[parsed.record.mx[1].span.clone()], "*.example.net");
    }

    #[test]
    fn wildcards_match_exactly_one_label() {
        let parsed = parse_policy(
            "version: STSv1\nmode: testing\nmx: *.example.net\nmx: mail.example.com\nmax_age: 86400",
        );
        let policy = &parsed.record;
        assert!(policy.covers("mx1.example.net"));
        assert!(policy.covers("MX1.Example.NET."));
        assert!(policy.covers("mail.example.com"));
        assert!(!policy.covers("example.net"));
        assert!(!policy.covers("a.b.example.net"));
        assert!(!policy.covers("mx.example.com"));
    }

    #[test]
    fn mode_none_needs_no_mx() {
        assert!(parse_policy("version: STSv1\nmode: none\nmax_age: 86400\n").is_usable());
    }

    #[test]
    fn every_fault_code() {
        for (input, code) in [
            (
                "mode: enforce\nmx: mail.example.com\nmax_age: 1",
                FaultCode::MissingVersion,
            ),
            (
                "version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 1",
                FaultCode::InvalidVersion,
            ),
            (
                "version: STSv1\nmx: mail.example.com\nmax_age: 1",
                FaultCode::MissingTag,
            ),
            (
                "version: STSv1\nmode: enforce\nmax_age: 1",
                FaultCode::MissingTag,
            ),
            (
                "version: STSv1\nmode: enforce\nmx: mail.example.com",
                FaultCode::MissingTag,
            ),
            (
                "version: STSv1\nmode: strict\nmx: mail.example.com\nmax_age: 1",
                FaultCode::InvalidTagValue,
            ),
            (
                "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 31557601",
                FaultCode::InvalidTagValue,
            ),
            (
                "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: -1",
                FaultCode::InvalidTagValue,
            ),
            (
                "version: STSv1\nmode: enforce\nmode: testing\nmx: mail.example.com\nmax_age: 1",
                FaultCode::DuplicateTag,
            ),
        ] {
            assert_eq!(codes(input), [code], "{input}");
            assert!(!parse_policy(input).is_usable(), "{input}");
        }
        let input = "version: STSv1\nmode: enforce\nmx: *.*.example.com\nmx: mail.example.com\nmax_age: 1\njunk";
        assert_eq!(
            codes(input),
            [FaultCode::InvalidTagValue, FaultCode::MalformedLine]
        );
        assert!(parse_policy(input).is_usable());
    }
}
