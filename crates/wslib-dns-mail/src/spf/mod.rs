//! SPF records (RFC 7208).

mod macros;

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

pub use macros::{Macro, MacroLetter, MacroString, MacroToken};

use crate::text::{offset_in, unwrap};
use crate::{FaultCode, Parsed, SyntaxFault};

/// The terms of an SPF record, in published order, after `v=spf1`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpfRecord {
    pub terms: Vec<SpfTerm>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpfTerm {
    pub term: Term,
    pub span: Range<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Term {
    Directive {
        qualifier: Qualifier,
        mechanism: Mechanism,
    },
    Redirect(MacroString),
    Explanation(MacroString),
    /// Receivers ignore modifiers they don't know (§6).
    UnknownModifier {
        name: String,
        value: String,
    },
    /// A term the record's faults explain, kept as written.
    Invalid(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Qualifier {
    #[default]
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

impl Qualifier {
    fn from_char(c: char) -> Option<Self> {
        Some(match c {
            '+' => Self::Pass,
            '-' => Self::Fail,
            '~' => Self::SoftFail,
            '?' => Self::Neutral,
            _ => return None,
        })
    }

    pub fn symbol(self) -> char {
        match self {
            Self::Pass => '+',
            Self::Fail => '-',
            Self::SoftFail => '~',
            Self::Neutral => '?',
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Mechanism {
    All,
    Include(MacroString),
    A {
        domain: Option<MacroString>,
        cidr: DualCidr,
    },
    Mx {
        domain: Option<MacroString>,
        cidr: DualCidr,
    },
    Ptr(Option<MacroString>),
    Ip4 {
        address: Ipv4Addr,
        prefix: Option<u8>,
    },
    Ip6 {
        address: Ipv6Addr,
        prefix: Option<u8>,
    },
    Exists(MacroString),
}

impl Mechanism {
    pub fn name(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Include(_) => "include",
            Self::A { .. } => "a",
            Self::Mx { .. } => "mx",
            Self::Ptr(_) => "ptr",
            Self::Ip4 { .. } => "ip4",
            Self::Ip6 { .. } => "ip6",
            Self::Exists(_) => "exists",
        }
    }

    /// Counts towards the ten DNS-querying terms of §4.6.4.
    pub fn queries_dns(&self) -> bool {
        matches!(
            self,
            Self::Include(_) | Self::A { .. } | Self::Mx { .. } | Self::Ptr(_) | Self::Exists(_)
        )
    }
}

/// The `/n` and `//n` prefix lengths on `a` and `mx`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualCidr {
    pub ip4: Option<u8>,
    pub ip6: Option<u8>,
}

impl fmt::Display for DualCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip4) = self.ip4 {
            write!(f, "/{ip4}")?;
        }
        if let Some(ip6) = self.ip6 {
            write!(f, "//{ip6}")?;
        }
        Ok(())
    }
}

impl SpfRecord {
    pub fn directives(&self) -> impl Iterator<Item = (Qualifier, &Mechanism)> {
        self.terms.iter().filter_map(|term| match &term.term {
            Term::Directive {
                qualifier,
                mechanism,
            } => Some((*qualifier, mechanism)),
            _ => None,
        })
    }

    /// The first `all` and its position among the terms.
    pub fn all(&self) -> Option<(usize, Qualifier)> {
        self.terms
            .iter()
            .enumerate()
            .find_map(|(index, term)| match &term.term {
                Term::Directive {
                    qualifier,
                    mechanism: Mechanism::All,
                } => Some((index, *qualifier)),
                _ => None,
            })
    }

    /// The first `redirect=`.
    pub fn redirect(&self) -> Option<&MacroString> {
        self.terms.iter().find_map(|term| match &term.term {
            Term::Redirect(target) => Some(target),
            _ => None,
        })
    }

    /// The first `exp=`.
    pub fn explanation(&self) -> Option<&MacroString> {
        self.terms.iter().find_map(|term| match &term.term {
            Term::Explanation(target) => Some(target),
            _ => None,
        })
    }

    /// The domains of every literal `include:`, in order.
    pub fn includes(&self) -> impl Iterator<Item = &str> {
        self.directives()
            .filter_map(|(_, mechanism)| match mechanism {
                Mechanism::Include(domain) => domain.literal(),
                _ => None,
            })
    }
}

impl Parsed<SpfRecord> {
    /// Every syntax fault but a tab for a space is a permerror (§4.6).
    pub fn is_usable(&self) -> bool {
        self.faults.iter().all(|fault| fault.code.is_advisory())
    }
}

/// Whether a TXT string is an SPF record at all (§4.5): `v=spf1` followed by a
/// space or the end, without case.
pub fn is_spf(txt: &str) -> bool {
    let (_, text) = unwrap(txt);
    text.get(..6)
        .is_some_and(|v| v.eq_ignore_ascii_case("v=spf1"))
        && matches!(text.as_bytes().get(6), None | Some(b' '))
}

pub fn parse(input: &str) -> Parsed<SpfRecord> {
    let (offset, text) = unwrap(input);
    let mut faults: Vec<SyntaxFault> = text
        .match_indices(|c: char| c.is_ascii_whitespace() && c != ' ')
        .map(|(at, _)| SyntaxFault::new(FaultCode::InvalidSeparator, offset + at..offset + at + 1))
        .collect();
    let mut tokens = text.split_ascii_whitespace().peekable();
    match tokens.peek() {
        Some(first) if first.eq_ignore_ascii_case("v=spf1") => {
            tokens.next();
        }
        Some(first) if first.get(..2).is_some_and(|v| v.eq_ignore_ascii_case("v=")) => {
            faults.push(SyntaxFault::new(
                FaultCode::InvalidVersion,
                span_of(input, first),
            ));
            tokens.next();
        }
        _ => faults.push(SyntaxFault::new(FaultCode::MissingVersion, 0..0)),
    }
    let mut terms: Vec<SpfTerm> = Vec::new();
    for token in tokens {
        let span = span_of(input, token);
        let term = parse_term(token, &span, &mut faults);
        let repeated = |same: fn(&Term) -> bool| same(&term) && terms.iter().any(|t| same(&t.term));
        if repeated(|t| matches!(t, Term::Redirect(_))) {
            faults.push(SyntaxFault::named(
                FaultCode::DuplicateModifier,
                span.clone(),
                "redirect",
            ));
        }
        if repeated(|t| matches!(t, Term::Explanation(_))) {
            faults.push(SyntaxFault::named(
                FaultCode::DuplicateModifier,
                span.clone(),
                "exp",
            ));
        }
        terms.push(SpfTerm { term, span });
    }
    faults.sort_by_key(|fault| fault.span.start);
    Parsed {
        record: SpfRecord { terms },
        faults,
    }
}

fn span_of(input: &str, token: &str) -> Range<usize> {
    let start = offset_in(input, token);
    start..start + token.len()
}

fn parse_term(token: &str, span: &Range<usize>, faults: &mut Vec<SyntaxFault>) -> Term {
    let mut fault = |code, name: &str| {
        faults.push(SyntaxFault::named(code, span.clone(), name));
        Term::Invalid(token.to_owned())
    };
    let (qualifier, bare) = match token.chars().next().and_then(Qualifier::from_char) {
        Some(qualifier) => (Some(qualifier), &token[1..]),
        None => (None, token),
    };
    let name_end = bare.find([':', '/', '=']).unwrap_or(bare.len());
    let name = &bare[..name_end];
    let rest = &bare[name_end..];

    if let Some(value) = rest.strip_prefix('=') {
        if qualifier.is_some() || !is_modifier_name(name) {
            return fault(FaultCode::InvalidTerm, name);
        }
        let spec = |faults: &mut Vec<SyntaxFault>| domain_spec(value, span, name, faults);
        return match name.to_ascii_lowercase().as_str() {
            "redirect" => {
                spec(faults).map_or_else(|| Term::Invalid(token.to_owned()), Term::Redirect)
            }
            "exp" => {
                spec(faults).map_or_else(|| Term::Invalid(token.to_owned()), Term::Explanation)
            }
            _ => Term::UnknownModifier {
                name: name.to_owned(),
                value: value.to_owned(),
            },
        };
    }

    let lower = name.to_ascii_lowercase();
    let argument = rest.strip_prefix(':');
    let mechanism = match lower.as_str() {
        "all" if rest.is_empty() => Some(Mechanism::All),
        "all" => return fault(FaultCode::InvalidTerm, "all"),
        "include" | "exists" => {
            let Some(value) = argument.filter(|v| !v.is_empty()) else {
                return fault(FaultCode::MissingDomainSpec, &lower);
            };
            domain_spec(value, span, &lower, faults).map(|spec| {
                if lower == "include" {
                    Mechanism::Include(spec)
                } else {
                    Mechanism::Exists(spec)
                }
            })
        }
        "a" | "mx" => {
            let Ok((domain, cidr)) = split_dual_cidr(rest) else {
                return fault(FaultCode::InvalidCidr, &lower);
            };
            let domain = match domain.strip_prefix(':') {
                Some("") => return fault(FaultCode::MissingDomainSpec, &lower),
                Some(value) => match domain_spec(value, span, &lower, faults) {
                    Some(spec) => Some(spec),
                    None => return Term::Invalid(token.to_owned()),
                },
                None if domain.is_empty() => None,
                None => return fault(FaultCode::InvalidTerm, &lower),
            };
            Some(if lower == "a" {
                Mechanism::A { domain, cidr }
            } else {
                Mechanism::Mx { domain, cidr }
            })
        }
        "ptr" => match argument {
            None if rest.is_empty() => Some(Mechanism::Ptr(None)),
            Some("") => return fault(FaultCode::MissingDomainSpec, "ptr"),
            Some(value) => {
                domain_spec(value, span, "ptr", faults).map(|spec| Mechanism::Ptr(Some(spec)))
            }
            None => return fault(FaultCode::InvalidTerm, "ptr"),
        },
        "ip4" | "ip6" => {
            let Some(value) = argument.filter(|v| !v.is_empty()) else {
                return fault(FaultCode::InvalidAddress, &lower);
            };
            let (address, prefix) = match value.split_once('/') {
                Some((address, prefix)) => (address, Some(prefix)),
                None => (value, None),
            };
            let max = if lower == "ip4" { 32 } else { 128 };
            let prefix = match prefix.map(|p| cidr_length(p, max)) {
                Some(None) => return fault(FaultCode::InvalidCidr, &lower),
                Some(Some(prefix)) => Some(prefix),
                None => None,
            };
            if lower == "ip4" {
                address
                    .parse()
                    .ok()
                    .map(|address| Mechanism::Ip4 { address, prefix })
            } else {
                address
                    .parse()
                    .ok()
                    .map(|address| Mechanism::Ip6 { address, prefix })
            }
            .or_else(|| {
                faults.push(SyntaxFault::named(
                    FaultCode::InvalidAddress,
                    span.clone(),
                    &lower,
                ));
                None
            })
        }
        _ => return fault(FaultCode::UnknownMechanism, name),
    };
    match mechanism {
        Some(mechanism) => Term::Directive {
            qualifier: qualifier.unwrap_or_default(),
            mechanism,
        },
        None => Term::Invalid(token.to_owned()),
    }
}

fn is_modifier_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn domain_spec(
    value: &str,
    span: &Range<usize>,
    name: &str,
    faults: &mut Vec<SyntaxFault>,
) -> Option<MacroString> {
    if value.is_empty() {
        faults.push(SyntaxFault::named(
            FaultCode::MissingDomainSpec,
            span.clone(),
            name,
        ));
        return None;
    }
    let Ok(spec) = macros::parse(value, false) else {
        faults.push(SyntaxFault::named(
            FaultCode::InvalidMacro,
            span.clone(),
            name,
        ));
        return None;
    };
    if !macros::has_domain_end(&spec) {
        faults.push(SyntaxFault::named(
            FaultCode::InvalidDomainSpec,
            span.clone(),
            name,
        ));
        return None;
    }
    Some(spec)
}

/// Splits `[:domain][/ip4][//ip6]` into the part before the lengths and the
/// lengths, taken from the end so a `/` can't be mistaken for a domain.
fn split_dual_cidr(rest: &str) -> Result<(&str, DualCidr), ()> {
    let mut cidr = DualCidr::default();
    let mut rest = rest;
    if let Some(at) = rest.rfind("//") {
        cidr.ip6 = Some(cidr_length(&rest[at + 2..], 128).ok_or(())?);
        rest = &rest[..at];
    }
    if let Some(at) = rest.rfind('/') {
        cidr.ip4 = Some(cidr_length(&rest[at + 1..], 32).ok_or(())?);
        rest = &rest[..at];
    }
    if rest.contains('/') {
        return Err(());
    }
    Ok((rest, cidr))
}

/// A prefix length per the ABNF: digits without a leading zero, at most `max`.
fn cidr_length(digits: &str, max: u8) -> Option<u8> {
    let well_formed = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    well_formed
        .then(|| digits.parse::<u8>().ok())
        .flatten()
        .filter(|&n| n <= max)
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        match self {
            Self::All => Ok(()),
            Self::Include(domain) | Self::Exists(domain) => write!(f, ":{domain}"),
            Self::A { domain, cidr } | Self::Mx { domain, cidr } => {
                if let Some(domain) = domain {
                    write!(f, ":{domain}")?;
                }
                write!(f, "{cidr}")
            }
            Self::Ptr(domain) => domain
                .as_ref()
                .map_or(Ok(()), |domain| write!(f, ":{domain}")),
            Self::Ip4 { address, prefix } => {
                write!(f, ":{address}")?;
                prefix.map_or(Ok(()), |prefix| write!(f, "/{prefix}"))
            }
            Self::Ip6 { address, prefix } => {
                write!(f, ":{address}")?;
                prefix.map_or(Ok(()), |prefix| write!(f, "/{prefix}"))
            }
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directive {
                qualifier: Qualifier::Pass,
                mechanism,
            } => write!(f, "{mechanism}"),
            Self::Directive {
                qualifier,
                mechanism,
            } => write!(f, "{}{mechanism}", qualifier.symbol()),
            Self::Redirect(target) => write!(f, "redirect={target}"),
            Self::Explanation(target) => write!(f, "exp={target}"),
            Self::UnknownModifier { name, value } => write!(f, "{name}={value}"),
            Self::Invalid(text) => f.write_str(text),
        }
    }
}

/// `v=spf1` and the terms, single-spaced, with mechanism names lowercased and
/// `+` left implicit.
impl fmt::Display for SpfRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("v=spf1")?;
        for term in &self.terms {
            write!(f, " {}", term.term)?;
        }
        Ok(())
    }
}

/// Adds `include:` for each domain the record doesn't already include, before
/// its `all` or at the end, leaving every other term as written.
pub fn with_includes<'a>(record: &str, domains: impl IntoIterator<Item = &'a str>) -> String {
    let (_, text) = unwrap(record);
    let mut tokens: Vec<String> = text.split_ascii_whitespace().map(str::to_owned).collect();
    let parsed = parse(text);
    let mut present: Vec<String> = parsed
        .record
        .includes()
        .map(str::to_ascii_lowercase)
        .collect();
    let mut at = tokens
        .iter()
        .position(|token| {
            token
                .trim_start_matches(['+', '-', '~', '?'])
                .eq_ignore_ascii_case("all")
        })
        .unwrap_or(tokens.len());
    for domain in domains {
        let domain = domain.trim().to_ascii_lowercase();
        if present.contains(&domain) {
            continue;
        }
        tokens.insert(at, format!("include:{domain}"));
        at += 1;
        present.push(domain);
    }
    tokens.join(" ")
}

#[cfg(test)]
mod tests;
