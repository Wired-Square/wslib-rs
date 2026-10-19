//! DMARC policy records (RFC 7489, with the DMARCbis `np`, `psd` and `t` tags).

use std::fmt;

use crate::Tag;
use crate::text::{check_version, first_of_each, starts_with_version, tag_list, unwrap};
use crate::uri::{self, ReportUri, Schemes};
use crate::{FaultCode, Parsed, SyntaxFault};

/// The tags of a DMARC record, as written in [`tags`](Self::tags) and as the
/// valid values of the tags this crate knows. A repeated tag's first value
/// counts. The `effective_*` methods apply the RFC defaults.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DmarcRecord {
    pub tags: Vec<Tag>,
    pub policy: Option<Policy>,
    pub subdomain_policy: Option<Policy>,
    pub non_existent_policy: Option<Policy>,
    pub public_suffix_domain: Option<Psd>,
    pub testing: Option<bool>,
    pub dkim_alignment: Option<Alignment>,
    pub spf_alignment: Option<Alignment>,
    pub percent: Option<u8>,
    pub failure_options: Option<Vec<FailureOption>>,
    pub report_formats: Option<Vec<String>>,
    pub report_interval: Option<u32>,
    pub aggregate: Vec<ReportUri>,
    pub failure: Vec<ReportUri>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Alignment {
    #[default]
    Relaxed,
    Strict,
}

/// `psd=`: whether the domain is a public suffix domain (DMARCbis).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Psd {
    Yes,
    No,
    #[default]
    Unknown,
}

/// One `fo=` option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FailureOption {
    /// `0`: report when every mechanism fails to align.
    AllFail,
    /// `1`: report when any mechanism fails to align.
    AnyFail,
    /// `d`: report DKIM failures.
    Dkim,
    /// `s`: report SPF failures.
    Spf,
}

impl Policy {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "quarantine" => Some(Self::Quarantine),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Alignment {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "r" => Some(Self::Relaxed),
            "s" => Some(Self::Strict),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relaxed => "r",
            Self::Strict => "s",
        }
    }
}

impl Psd {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "y",
            Self::No => "n",
            Self::Unknown => "u",
        }
    }
}

impl FailureOption {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllFail => "0",
            Self::AnyFail => "1",
            Self::Dkim => "d",
            Self::Spf => "s",
        }
    }
}

impl DmarcRecord {
    fn written(&self, name: &str) -> bool {
        self.tags
            .iter()
            .any(|tag| tag.name.eq_ignore_ascii_case(name))
    }

    /// RFC 7489 §6.6.3: with no valid `p`, or an invalid `sp`, a receiver
    /// still acts as if `p=none` was published when `rua` has a valid URI.
    pub fn policy_treated_as_none(&self) -> bool {
        self.policy_broken() && !self.aggregate.is_empty()
    }

    fn policy_broken(&self) -> bool {
        self.policy.is_none() || (self.written("sp") && self.subdomain_policy.is_none())
    }

    /// With a broken policy every effective policy is the §6.6.3 outcome:
    /// `none` if `rua` saves it, else no DMARC processing.
    fn fallback(&self) -> Option<Option<Policy>> {
        self.policy_broken()
            .then(|| self.policy_treated_as_none().then_some(Policy::None))
    }

    /// The policy for the domain itself, or `None` when a receiver applies no
    /// DMARC processing at all.
    pub fn effective_policy(&self) -> Option<Policy> {
        self.fallback().unwrap_or(self.policy)
    }

    /// `sp`, defaulting to the domain's policy.
    pub fn effective_subdomain_policy(&self) -> Option<Policy> {
        self.fallback()
            .unwrap_or(self.subdomain_policy.or(self.policy))
    }

    /// `np` (DMARCbis), defaulting to the subdomain policy.
    pub fn effective_non_existent_policy(&self) -> Option<Policy> {
        self.fallback().unwrap_or(
            self.non_existent_policy
                .or(self.subdomain_policy)
                .or(self.policy),
        )
    }

    pub fn effective_dkim_alignment(&self) -> Alignment {
        self.dkim_alignment.unwrap_or_default()
    }

    pub fn effective_spf_alignment(&self) -> Alignment {
        self.spf_alignment.unwrap_or_default()
    }

    pub fn effective_percent(&self) -> u8 {
        self.percent.unwrap_or(100)
    }

    pub fn effective_testing(&self) -> bool {
        self.testing.unwrap_or(false)
    }

    pub fn effective_public_suffix_domain(&self) -> Psd {
        self.public_suffix_domain.unwrap_or_default()
    }

    pub fn effective_failure_options(&self) -> Vec<FailureOption> {
        self.failure_options
            .clone()
            .unwrap_or_else(|| vec![FailureOption::AllFail])
    }

    pub fn effective_report_interval(&self) -> u32 {
        self.report_interval.unwrap_or(86_400)
    }

    /// Whether aggregate reports go to `address`, given with or without
    /// `mailto:`.
    pub fn reports_to(&self, address: &str) -> bool {
        let address = address.trim();
        let address = strip_mailto(address);
        self.aggregate.iter().any(|uri| {
            uri.mailbox()
                .is_some_and(|mailbox| mailbox.eq_ignore_ascii_case(address))
        })
    }
}

fn strip_mailto(address: &str) -> &str {
    match address.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("mailto:") => &address[7..],
        _ => address,
    }
}

impl Parsed<DmarcRecord> {
    /// Whether a receiver would apply this record: it starts `v=DMARC1` and
    /// yields a policy, if only the §6.6.3 fallback to `none`.
    pub fn is_usable(&self) -> bool {
        let version_ok = !self.faults.iter().any(|fault| {
            matches!(
                fault.code,
                FaultCode::MissingVersion | FaultCode::InvalidVersion | FaultCode::VersionNotFirst
            )
        });
        version_ok && self.record.effective_policy().is_some()
    }
}

/// Whether a TXT string is a DMARC record at all: it starts `v=DMARC1`.
pub fn is_dmarc(txt: &str) -> bool {
    starts_with_version(txt, "DMARC1")
}

pub fn parse(input: &str) -> Parsed<DmarcRecord> {
    let (_, text) = unwrap(input);
    let mut faults = Vec::new();
    let all = tag_list(input, text, &mut faults);
    check_version(input, &all, "DMARC1", &mut faults);
    // §6.3: "the "v" and "p" tags MUST be present and MUST appear in that
    // order", and the §6.4 grammar puts `p` directly after `v`.
    let version_first = all
        .first()
        .is_some_and(|tag| tag.name.eq_ignore_ascii_case("v"));
    let p = all
        .iter()
        .position(|tag| tag.name.eq_ignore_ascii_case("p"));
    if let Some(p) = p.filter(|&at| version_first && at != 1) {
        faults.push(SyntaxFault::named(
            FaultCode::TagOutOfOrder,
            all[p].span.clone(),
            "p",
        ));
    }
    let mut record = DmarcRecord {
        tags: all.iter().map(|tag| tag.written(true)).collect(),
        ..DmarcRecord::default()
    };
    for tag in first_of_each(all, |a, b| a.eq_ignore_ascii_case(b), &mut faults) {
        let name = tag.name.to_ascii_lowercase();
        let value = tag.value;
        let mut invalid = || {
            faults.push(SyntaxFault::named(
                FaultCode::InvalidTagValue,
                tag.value_span.clone(),
                &name,
            ))
        };
        match name.as_str() {
            "v" => {}
            "p" | "sp" | "np" => match Policy::parse(value) {
                Some(policy) => match name.as_str() {
                    "p" => record.policy = Some(policy),
                    "sp" => record.subdomain_policy = Some(policy),
                    _ => record.non_existent_policy = Some(policy),
                },
                None => invalid(),
            },
            "adkim" | "aspf" => match Alignment::parse(value) {
                Some(alignment) if name == "adkim" => record.dkim_alignment = Some(alignment),
                Some(alignment) => record.spf_alignment = Some(alignment),
                None => invalid(),
            },
            "pct" => match digits::<u8>(value).filter(|&n| n <= 100) {
                Some(percent) => record.percent = Some(percent),
                None => invalid(),
            },
            "t" => match value.to_ascii_lowercase().as_str() {
                "y" => record.testing = Some(true),
                "n" => record.testing = Some(false),
                _ => invalid(),
            },
            "psd" => match value.to_ascii_lowercase().as_str() {
                "y" => record.public_suffix_domain = Some(Psd::Yes),
                "n" => record.public_suffix_domain = Some(Psd::No),
                "u" => record.public_suffix_domain = Some(Psd::Unknown),
                _ => invalid(),
            },
            "fo" => match colon_list(value, |option| match option.to_ascii_lowercase().as_str() {
                "0" => Some(FailureOption::AllFail),
                "1" => Some(FailureOption::AnyFail),
                "d" => Some(FailureOption::Dkim),
                "s" => Some(FailureOption::Spf),
                _ => None,
            }) {
                Some(options) => record.failure_options = Some(options),
                None => invalid(),
            },
            "rf" => match colon_list(value, |format| {
                let keyword = format.starts_with(|c: char| c.is_ascii_alphabetic())
                    && format.chars().all(|c| c.is_ascii_alphanumeric());
                keyword.then(|| format.to_ascii_lowercase())
            }) {
                Some(formats) => record.report_formats = Some(formats),
                None => invalid(),
            },
            "ri" => match digits::<u32>(value) {
                Some(interval) => record.report_interval = Some(interval),
                None => invalid(),
            },
            "rua" => {
                record.aggregate = uri::parse_list(input, value, "rua", Schemes::Dmarc, &mut faults)
            }
            "ruf" => {
                record.failure = uri::parse_list(input, value, "ruf", Schemes::Dmarc, &mut faults)
            }
            _ => faults.push(SyntaxFault::named(
                FaultCode::UnknownTag,
                tag.span.clone(),
                &name,
            )),
        }
    }
    if record.policy.is_none() && !record.written("p") {
        faults.push(crate::text::missing(input, "p"));
    }
    faults.sort_by_key(|fault| fault.span.start);
    Parsed { record, faults }
}

/// Plain digits only: `parse` alone would accept a leading `+`.
fn digits<T: std::str::FromStr>(value: &str) -> Option<T> {
    value
        .bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| value.parse().ok())
        .flatten()
}

fn colon_list<T>(value: &str, parse: impl Fn(&str) -> Option<T>) -> Option<Vec<T>> {
    value.split(':').map(|item| parse(item.trim())).collect()
}

/// Composes a DMARC record with its tags in a fixed order.
#[derive(Clone, Debug)]
pub struct DmarcBuilder {
    policy: Policy,
    subdomain_policy: Option<Policy>,
    non_existent_policy: Option<Policy>,
    public_suffix_domain: Option<Psd>,
    testing: Option<bool>,
    dkim_alignment: Option<Alignment>,
    spf_alignment: Option<Alignment>,
    percent: Option<u8>,
    failure_options: Vec<FailureOption>,
    report_interval: Option<u32>,
    aggregate: Vec<String>,
    failure: Vec<String>,
}

impl DmarcBuilder {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            subdomain_policy: None,
            non_existent_policy: None,
            public_suffix_domain: None,
            testing: None,
            dkim_alignment: None,
            spf_alignment: None,
            percent: None,
            failure_options: Vec::new(),
            report_interval: None,
            aggregate: Vec::new(),
            failure: Vec::new(),
        }
    }

    pub fn subdomain_policy(mut self, policy: Policy) -> Self {
        self.subdomain_policy = Some(policy);
        self
    }

    pub fn non_existent_policy(mut self, policy: Policy) -> Self {
        self.non_existent_policy = Some(policy);
        self
    }

    pub fn public_suffix_domain(mut self, psd: Psd) -> Self {
        self.public_suffix_domain = Some(psd);
        self
    }

    pub fn testing(mut self, testing: bool) -> Self {
        self.testing = Some(testing);
        self
    }

    pub fn dkim_alignment(mut self, alignment: Alignment) -> Self {
        self.dkim_alignment = Some(alignment);
        self
    }

    pub fn spf_alignment(mut self, alignment: Alignment) -> Self {
        self.spf_alignment = Some(alignment);
        self
    }

    /// Clamped to 100.
    pub fn percent(mut self, percent: u8) -> Self {
        self.percent = Some(percent.min(100));
        self
    }

    pub fn failure_option(mut self, option: FailureOption) -> Self {
        if !self.failure_options.contains(&option) {
            self.failure_options.push(option);
        }
        self
    }

    pub fn report_interval(mut self, seconds: u32) -> Self {
        self.report_interval = Some(seconds);
        self
    }

    /// Adds an aggregate report destination; a bare address gets `mailto:`.
    pub fn aggregate(mut self, uri: &str) -> Self {
        self.aggregate.push(with_scheme(uri));
        self
    }

    /// Adds a failure report destination; a bare address gets `mailto:`.
    pub fn failure(mut self, uri: &str) -> Self {
        self.failure.push(with_scheme(uri));
        self
    }

    pub fn build(&self) -> String {
        let mut tags = vec![("v", "DMARC1".to_owned()), ("p", self.policy.to_string())];
        let mut push = |name, value: Option<String>| {
            if let Some(value) = value {
                tags.push((name, value));
            }
        };
        push("sp", self.subdomain_policy.map(|p| p.to_string()));
        push("np", self.non_existent_policy.map(|p| p.to_string()));
        push(
            "psd",
            self.public_suffix_domain.map(|p| p.as_str().to_owned()),
        );
        push(
            "t",
            self.testing.map(|t| if t { "y" } else { "n" }.to_owned()),
        );
        push("adkim", self.dkim_alignment.map(|a| a.as_str().to_owned()));
        push("aspf", self.spf_alignment.map(|a| a.as_str().to_owned()));
        push("pct", self.percent.map(|p| p.to_string()));
        push(
            "fo",
            (!self.failure_options.is_empty()).then(|| {
                self.failure_options
                    .iter()
                    .map(|o| o.as_str())
                    .collect::<Vec<_>>()
                    .join(":")
            }),
        );
        push("ri", self.report_interval.map(|ri| ri.to_string()));
        push(
            "rua",
            (!self.aggregate.is_empty()).then(|| self.aggregate.join(",")),
        );
        push(
            "ruf",
            (!self.failure.is_empty()).then(|| self.failure.join(",")),
        );
        tags.iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn with_scheme(uri: &str) -> String {
    let uri = uri.trim();
    if uri.contains(':') {
        uri.to_owned()
    } else {
        format!("mailto:{uri}")
    }
}

/// Adds an aggregate report destination to a published record, appending to
/// its `rua=` list or adding the tag, and leaving every other tag as written.
/// Already-present destinations are not added twice.
pub fn with_aggregate(record: &str, uri: &str) -> String {
    let uri = with_scheme(uri);
    let (_, text) = unwrap(record);
    let mut tags: Vec<String> = text
        .split(';')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect();
    if !parse(text).record.reports_to(&uri) {
        let rua = tags.iter_mut().find(|tag| {
            tag.split_once('=')
                .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("rua"))
        });
        match rua {
            Some(tag) => *tag = format!("{tag},{uri}"),
            None => tags.push(format!("rua={uri}")),
        }
    }
    tags.join("; ")
}

#[cfg(test)]
mod tests;
