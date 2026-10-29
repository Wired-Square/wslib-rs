use std::collections::BTreeMap;

use serde::Serialize;

/// A note as a code and its interpolation values, for the caller to translate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct ChecksumNote {
    pub code: String,
    #[cfg_attr(feature = "ts", ts(type = "{ [key in string]: unknown }"))]
    pub values: BTreeMap<String, NoteValue>,
}

impl ChecksumNote {
    pub fn new(code: &str, values: &[(&str, NoteValue)]) -> Self {
        Self {
            code: code.to_string(),
            values: values
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        }
    }
}

/// One interpolation value: a number or a string, serialised bare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(untagged)]
pub enum NoteValue {
    Int(i64),
    Text(String),
}

impl From<i32> for NoteValue {
    fn from(n: i32) -> Self {
        Self::Int(n.into())
    }
}

impl From<usize> for NoteValue {
    fn from(n: usize) -> Self {
        Self::Int(i64::try_from(n).unwrap_or(i64::MAX))
    }
}

impl From<String> for NoteValue {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

/// One note the engine can emit: its code and the variables it interpolates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteSpec {
    pub code: &'static str,
    pub values: &'static [&'static str],
}

/// Every note the engine can emit, for a locale file to be checked against in
/// both directions. Kept honest by `manifest_covers_every_emitted_note`.
pub const ALL_NOTES: &[NoteSpec] = &[
    NoteSpec {
        code: "analysed",
        values: &["frames", "minLength", "maxLength"],
    },
    NoteSpec {
        code: "columnNearlyConstant",
        values: &["distinct"],
    },
    NoteSpec {
        code: "columnVaries",
        values: &["distinct", "samples"],
    },
    NoteSpec {
        code: "configurationsTested",
        values: &["specs", "algorithms"],
    },
    NoteSpec {
        code: "constantExcluded",
        values: &["value"],
    },
    NoteSpec {
        code: "constantPadding",
        values: &["position", "value"],
    },
    NoteSpec {
        code: "constantPaddingRun",
        values: &["from", "to", "value"],
    },
    NoteSpec {
        code: "fewSamples",
        values: &["count"],
    },
    NoteSpec {
        code: "highByteConstant",
        values: &[],
    },
    NoteSpec {
        code: "matchesAll",
        values: &["count"],
    },
    NoteSpec {
        code: "matchesSome",
        values: &["matched", "total"],
    },
    NoteSpec {
        code: "noFrames",
        values: &[],
    },
    NoteSpec {
        code: "noneButLastByteVaries",
        values: &["distinct", "frames"],
    },
    NoteSpec {
        code: "noneLastByteConstant",
        values: &["value", "frames"],
    },
    NoteSpec {
        code: "shortRange",
        values: &[],
    },
    NoteSpec {
        code: "startsAfterHeader",
        values: &["byte"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// The call's arguments, found by balancing parentheses rather than by
    /// searching for a closing delimiter. A note with no values ends `&[])`, so
    /// scanning for `"],"` runs past the call and swallows whatever follows.
    fn call_arguments(after_open_paren: &str) -> Option<&str> {
        let mut depth = 1usize;
        let mut in_string = false;
        let mut escaped = false;

        for (i, c) in after_open_paren.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' if in_string => escaped = true,
                '"' => in_string = !in_string,
                _ if in_string => {}
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&after_open_paren[..i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Every `ChecksumNote::new("code", &[("var", …)])` in the engine, parsed out
    /// of the source.
    fn emitted() -> BTreeMap<String, BTreeSet<String>> {
        const CALL: &str = "ChecksumNote::new(";
        let source = include_str!("detect.rs");
        let mut found = BTreeMap::new();
        let mut rest = source;

        while let Some(start) = rest.find(CALL) {
            rest = &rest[start + CALL.len()..];
            let Some(call) = call_arguments(rest) else {
                break;
            };

            // A tuple key is a bare identifier; `format!("0x{value:02X}")` and
            // friends are string *values* and must not read as variable names.
            let quoted = call
                .split('"')
                .skip(1)
                .step_by(2)
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric()));

            let mut quoted = quoted.map(str::to_string);
            let Some(code) = quoted.next() else { continue };
            found.insert(code, quoted.collect());
        }

        found
    }

    #[test]
    fn manifest_covers_every_emitted_note() {
        let emitted = emitted();

        // Guards the parser: a refactor of how notes are built must not make
        // this test silently vacuous.
        assert!(emitted.len() > 10, "parsed only {} notes", emitted.len());
        assert_eq!(
            emitted.get("matchesAll"),
            Some(&BTreeSet::from(["count".to_string()]))
        );

        let declared: BTreeMap<String, BTreeSet<String>> = ALL_NOTES
            .iter()
            .map(|n| {
                (
                    n.code.to_string(),
                    n.values.iter().map(|v| (*v).to_string()).collect(),
                )
            })
            .collect();

        assert_eq!(declared, emitted);
    }
}
