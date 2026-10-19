use std::fmt;
use std::ops::Range;

/// A record as far as it could be read, and every fault found on the way.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Parsed<T> {
    pub record: T,
    pub faults: Vec<SyntaxFault>,
}

impl<T> Parsed<T> {
    pub fn has(&self, code: FaultCode) -> bool {
        self.faults.iter().any(|fault| fault.code == code)
    }
}

/// One fault, at a byte range of the text that was parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyntaxFault {
    pub code: FaultCode,
    /// Empty, at the end of the input, for something missing.
    pub span: Range<usize>,
    /// The tag, mechanism or key the fault is about, lowercased.
    pub name: Option<String>,
}

impl SyntaxFault {
    pub(crate) fn new(code: FaultCode, span: Range<usize>) -> Self {
        Self {
            code,
            span,
            name: None,
        }
    }

    pub(crate) fn named(code: FaultCode, span: Range<usize>, name: &str) -> Self {
        Self {
            code,
            span,
            name: Some(name.to_ascii_lowercase()),
        }
    }
}

/// What is wrong. The serialised names are stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum FaultCode {
    /// No version tag, or the record doesn't start with one.
    MissingVersion,
    InvalidVersion,
    VersionNotFirst,
    /// A tag-list segment with no `=`.
    MalformedTag,
    DuplicateTag,
    /// Receivers ignore it, but it may be a typo.
    UnknownTag,
    MissingTag,
    InvalidTagValue,
    InvalidUri,
    /// A URI that has to be `https:` but isn't.
    InsecureUri,
    UnknownMechanism,
    /// A term that can't be read as a mechanism or modifier.
    InvalidTerm,
    MissingDomainSpec,
    InvalidDomainSpec,
    InvalidMacro,
    InvalidCidr,
    InvalidAddress,
    DuplicateModifier,
    InvalidBase64,
    /// Key data that isn't a public key of the declared type.
    InvalidKey,
    UnknownKeyType,
    /// A policy-file line with no `:`.
    MalformedLine,
}

impl fmt::Display for FaultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingVersion => "missing version",
            Self::InvalidVersion => "invalid version",
            Self::VersionNotFirst => "version is not first",
            Self::MalformedTag => "malformed tag",
            Self::DuplicateTag => "duplicate tag",
            Self::UnknownTag => "unknown tag",
            Self::MissingTag => "missing required tag",
            Self::InvalidTagValue => "invalid tag value",
            Self::InvalidUri => "invalid URI",
            Self::InsecureUri => "URI is not https",
            Self::UnknownMechanism => "unknown mechanism",
            Self::InvalidTerm => "invalid term",
            Self::MissingDomainSpec => "missing domain-spec",
            Self::InvalidDomainSpec => "invalid domain-spec",
            Self::InvalidMacro => "invalid macro",
            Self::InvalidCidr => "invalid CIDR length",
            Self::InvalidAddress => "invalid address",
            Self::DuplicateModifier => "duplicate modifier",
            Self::InvalidBase64 => "invalid base64",
            Self::InvalidKey => "invalid public key",
            Self::UnknownKeyType => "unknown key type",
            Self::MalformedLine => "malformed line",
        })
    }
}

impl fmt::Display for SyntaxFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(
                f,
                "{} ({name}) at {}..{}",
                self.code, self.span.start, self.span.end
            ),
            None => write!(f, "{} at {}..{}", self.code, self.span.start, self.span.end),
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn fault_codes_serialise_as_snake_case() {
        let fault = SyntaxFault::named(FaultCode::InvalidTagValue, 3..6, "pct");
        assert_eq!(
            serde_json::to_string(&fault).unwrap(),
            r#"{"code":"invalid_tag_value","span":{"start":3,"end":6},"name":"pct"}"#
        );
        assert_eq!(
            serde_json::to_string(&FaultCode::MissingDomainSpec).unwrap(),
            r#""missing_domain_spec""#
        );
    }
}
