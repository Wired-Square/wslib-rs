use std::ops::Range;

use crate::{FaultCode, SyntaxFault};

/// The record inside a BOM, outer whitespace and stray wrapping quotes, as a
/// slice of the input so spans stay relative to what the caller passed.
pub(crate) fn unwrap(input: &str) -> (usize, &str) {
    let mut text = input.trim_start_matches('\u{feff}').trim();
    while let Some(inner) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        text = inner.trim();
    }
    if let Some(inner) = text.strip_prefix('"').or_else(|| text.strip_suffix('"')) {
        text = inner.trim();
    }
    (offset_in(input, text), text)
}

pub(crate) fn offset_in(outer: &str, inner: &str) -> usize {
    inner.as_ptr() as usize - outer.as_ptr() as usize
}

/// One `name=value` segment of a tag-list (RFC 6376 §3.2), trimmed, with
/// spans into the original input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawTag<'a> {
    pub name: &'a str,
    pub value: &'a str,
    pub span: Range<usize>,
    pub name_span: Range<usize>,
    pub value_span: Range<usize>,
}

impl RawTag<'_> {
    pub fn written(&self, lowercase_name: bool) -> Tag {
        Tag {
            name: if lowercase_name {
                self.name.to_ascii_lowercase()
            } else {
                self.name.to_owned()
            },
            value: self.value.to_owned(),
            span: self.span.clone(),
        }
    }
}

/// A tag of a tag-list record, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tag {
    pub name: String,
    pub value: String,
    pub span: Range<usize>,
}

/// Renders a tag-list record's tags as written, single-spaced:
/// `v=DMARC1; p=reject; rua=…`.
macro_rules! display_tags {
    ($($record:ty),+) => {$(
        impl std::fmt::Display for $record {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for (index, tag) in self.tags.iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    write!(f, "{}={}", tag.name, tag.value)?;
                }
                Ok(())
            }
        }
    )+};
}

display_tags!(
    crate::dmarc::DmarcRecord,
    crate::dkim::DkimKeyRecord,
    crate::bimi::BimiRecord,
    crate::mta_sts::MtaStsRecord,
    crate::tls_rpt::TlsRptRecord
);

/// Splits a tag-list on `;`. Empty segments, as a trailing `;` leaves, are
/// skipped; a segment without `=` is a [`FaultCode::MalformedTag`].
pub(crate) fn tag_list<'a>(
    input: &'a str,
    text: &'a str,
    faults: &mut Vec<SyntaxFault>,
) -> Vec<RawTag<'a>> {
    let mut tags = Vec::new();
    for segment in text.split(';') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let start = offset_in(input, trimmed);
        let span = start..start + trimmed.len();
        let Some((name, value)) = trimmed.split_once('=') else {
            faults.push(SyntaxFault::new(FaultCode::MalformedTag, span));
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        let name_start = offset_in(input, name);
        let value_start = offset_in(input, value);
        tags.push(RawTag {
            name,
            value,
            span,
            name_span: name_start..name_start + name.len(),
            value_span: value_start..value_start + value.len(),
        });
    }
    tags
}

/// Reports every repeat of a tag name after its first, comparing names with
/// `same`, and returns the tags with repeats dropped.
pub(crate) fn first_of_each<'a>(
    tags: Vec<RawTag<'a>>,
    same: impl Fn(&str, &str) -> bool,
    faults: &mut Vec<SyntaxFault>,
) -> Vec<RawTag<'a>> {
    let mut kept: Vec<RawTag<'a>> = Vec::with_capacity(tags.len());
    for tag in tags {
        if kept.iter().any(|seen| same(seen.name, tag.name)) {
            faults.push(SyntaxFault::named(
                FaultCode::DuplicateTag,
                tag.span.clone(),
                tag.name,
            ));
        } else {
            kept.push(tag);
        }
    }
    kept
}

/// Checks the first tag is the version tag `v=<expected>` and reports what's
/// wrong otherwise.
pub(crate) fn check_version(
    input: &str,
    tags: &[RawTag<'_>],
    expected: &str,
    faults: &mut Vec<SyntaxFault>,
) {
    let Some(index) = tags
        .iter()
        .position(|tag| tag.name.eq_ignore_ascii_case("v"))
    else {
        faults.push(SyntaxFault::new(
            FaultCode::MissingVersion,
            input.len()..input.len(),
        ));
        return;
    };
    if index != 0 {
        faults.push(SyntaxFault::named(
            FaultCode::VersionNotFirst,
            tags[index].span.clone(),
            "v",
        ));
    }
    if let Some(fault) = version_value_fault(&tags[index], expected) {
        faults.push(fault);
    }
}

/// Version values are case-sensitive in every record type here; the wrong
/// case alone is [`FaultCode::NoncanonicalVersion`], which receivers forgive.
pub(crate) fn version_value_fault(tag: &RawTag<'_>, expected: &str) -> Option<SyntaxFault> {
    let code = if tag.value == expected {
        return None;
    } else if tag.value.eq_ignore_ascii_case(expected) {
        FaultCode::NoncanonicalVersion
    } else {
        FaultCode::InvalidVersion
    };
    Some(SyntaxFault::named(code, tag.value_span.clone(), "v"))
}

/// Whether a tag-list's first tag is `v=<version>`, compared without case.
pub(crate) fn starts_with_version(txt: &str, version: &str) -> bool {
    let (_, text) = unwrap(txt);
    text.split(';')
        .next()
        .and_then(|first| first.split_once('='))
        .is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("v") && value.trim().eq_ignore_ascii_case(version)
        })
}

pub(crate) fn missing(input: &str, name: &str) -> SyntaxFault {
    SyntaxFault::named(FaultCode::MissingTag, input.len()..input.len(), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_strips_bom_whitespace_and_stray_quotes() {
        for input in [
            "v=x",
            "  v=x  ",
            "\u{feff}v=x",
            "\"v=x\"",
            " \"v=x",
            "v=x\" ",
            "\"\"v=x\"\"",
        ] {
            let (offset, text) = unwrap(input);
            assert_eq!(text, "v=x", "{input:?}");
            assert_eq!(&input[offset..offset + 3], "v=x");
        }
    }

    #[test]
    fn tag_list_spans_point_into_the_input() {
        let input = "\"v=DMARC1 ;  p = reject;;junk; \"";
        let (_, text) = unwrap(input);
        let mut faults = Vec::new();
        let tags = tag_list(input, text, &mut faults);
        assert_eq!(tags.len(), 2);
        assert_eq!(&input[tags[1].name_span.clone()], "p");
        assert_eq!(&input[tags[1].value_span.clone()], "reject");
        assert_eq!(faults.len(), 1);
        assert_eq!(&input[faults[0].span.clone()], "junk");
    }
}
