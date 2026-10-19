//! Finding records over DNS, through any [`Resolver`].
//!
//! Each function reports what it found and how: every matching record (so
//! duplicates can be reported), and why a query came back empty.

mod bimi_logo;
mod dkim;
mod dmarc;
mod dnsbl;
mod fetch;
mod mta_sts_policy;
mod mx;

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

#[cfg(feature = "http")]
pub use bimi_logo::bimi_logo;
pub use bimi_logo::{LOGO_FETCH_LIMIT, LOGO_INFLATE_LIMIT, LogoFetch};
pub use dkim::{COMMON_SELECTORS, DkimDiscovery, dkim, probe_dkim};
pub use dmarc::{
    AppliedPolicy, DmarcDiscovery, DmarcDiscoveryMode, PolicyTag, ReportAuthorisation, dmarc,
    dmarc_report_authorisation,
};
pub use dnsbl::{DnsblResult, DnsblStatus, dnsbl};
pub use fetch::FetchFailure;
#[cfg(feature = "http")]
pub use fetch::HttpClients;
pub(crate) use fetch::media_type;
#[cfg(feature = "http")]
pub use mta_sts_policy::mta_sts_policy;
pub use mta_sts_policy::{POLICY_SIZE_LIMIT, PolicyFetch, policy_url};
pub use mx::{MxDiscovery, MxHost, ReverseDns, mx};
use wslib_dns::{LookupError, Resolver};

use crate::Parsed;
use crate::bimi::BimiRecord;
use crate::mta_sts::MtaStsRecord;
use crate::spf::SpfRecord;
use crate::tls_rpt::TlsRptRecord;

/// One TXT string and what it parsed to.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Published<T> {
    pub text: String,
    pub parsed: Parsed<T>,
}

/// The records of one kind at one name.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecordSet<T> {
    pub name: String,
    /// Why the query returned no records at all.
    pub error: Option<LookupError>,
    pub ttl: Option<u32>,
    /// Every TXT string at the name that is this kind of record.
    pub records: Vec<Published<T>>,
    /// The other TXT strings at the name, which receivers skip.
    pub others: Vec<String>,
}

impl<T> RecordSet<T> {
    /// The record, when there is exactly one.
    pub fn single(&self) -> Option<&Published<T>> {
        match self.records.as_slice() {
            [record] => Some(record),
            _ => None,
        }
    }

    pub fn is_multiple(&self) -> bool {
        self.records.len() > 1
    }

    /// Known to have no such record: the query answered, or the name or
    /// type doesn't exist.
    pub fn is_absent(&self) -> bool {
        self.records.is_empty() && self.error.as_ref().is_none_or(LookupError::is_absent)
    }

    /// The lookup failed, so whether a record exists is unknown.
    pub fn failure(&self) -> Option<&LookupError> {
        self.error.as_ref().filter(|error| !error.is_absent())
    }
}

/// Queries TXT at `name` and keeps the strings `is_kind` accepts.
pub(crate) async fn txt_set<T>(
    resolver: &impl Resolver,
    name: String,
    is_kind: fn(&str) -> bool,
    parse: fn(&str) -> Parsed<T>,
) -> RecordSet<T> {
    match resolver.txt(&name).await {
        Ok(answer) => {
            let (kind, others): (Vec<String>, Vec<String>) = answer
                .records
                .iter()
                .map(|txt| txt.joined())
                .partition(|text| is_kind(text));
            RecordSet {
                name,
                error: None,
                ttl: answer.ttl,
                records: kind
                    .into_iter()
                    .map(|text| Published {
                        parsed: parse(&text),
                        text,
                    })
                    .collect(),
                others,
            }
        }
        Err(error) => RecordSet {
            name,
            error: Some(error),
            ttl: None,
            records: Vec::new(),
            others: Vec::new(),
        },
    }
}

/// The name to build query names from: A-labels, lowercase, no trailing dot.
pub(crate) fn ascii(domain: &str) -> String {
    wslib_dns::to_ascii(domain).unwrap_or_else(|_| wslib_dns::normalise(domain))
}

/// The SPF records at `domain` (RFC 7208 §4.4). More than one is a permerror
/// (§4.5), so all are kept.
pub async fn spf(resolver: &impl Resolver, domain: &str) -> RecordSet<SpfRecord> {
    txt_set(
        resolver,
        ascii(domain),
        crate::spf::is_spf,
        crate::spf::parse,
    )
    .await
}

/// The MTA-STS TXT records at `_mta-sts.<domain>` (RFC 8461 §3.1).
pub async fn mta_sts(resolver: &impl Resolver, domain: &str) -> RecordSet<MtaStsRecord> {
    let name = format!("_mta-sts.{}", ascii(domain));
    txt_set(
        resolver,
        name,
        crate::mta_sts::is_mta_sts,
        crate::mta_sts::parse_record,
    )
    .await
}

/// The TLS-RPT records at `_smtp._tls.<domain>` (RFC 8460 §3).
pub async fn tls_rpt(resolver: &impl Resolver, domain: &str) -> RecordSet<TlsRptRecord> {
    let name = format!("_smtp._tls.{}", ascii(domain));
    txt_set(
        resolver,
        name,
        crate::tls_rpt::is_tls_rpt,
        crate::tls_rpt::parse,
    )
    .await
}

/// The BIMI records at `<selector>._bimi.<domain>`, falling back to the
/// organisational domain when there are none, as the BIMI draft does.
pub async fn bimi(resolver: &impl Resolver, domain: &str, selector: &str) -> Inherited<BimiRecord> {
    let domain = ascii(domain);
    let mut domains = vec![domain.clone()];
    domains.extend(wslib_dns::registrable_domain(&domain).filter(|org| *org != domain));
    walk(
        resolver,
        domain,
        domains,
        |d| format!("{selector}._bimi.{d}"),
        crate::bimi::is_bimi,
        crate::bimi::parse,
    )
    .await
}

/// A record looked for at a domain and then at its ancestors, as DMARC and
/// BIMI do.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Inherited<T> {
    pub domain: String,
    /// Each domain tried, in order, and what was at it.
    pub attempts: Vec<Attempt<T>>,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attempt<T> {
    pub domain: String,
    pub set: RecordSet<T>,
}

/// How a walk ended. `at` indexes [`Inherited::attempts`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
pub enum Outcome {
    Found {
        at: usize,
    },
    /// No record anywhere the walk looked.
    Missing,
    /// More than one record at one domain, which ends the walk with none.
    Multiple {
        at: usize,
    },
    /// A lookup failed, so whether a record exists is unknown.
    Failed {
        at: usize,
    },
}

impl<T> Inherited<T> {
    pub fn found(&self) -> Option<&Published<T>> {
        match self.outcome {
            Outcome::Found { at } => self.attempts[at].set.single(),
            _ => None,
        }
    }

    /// The ancestor the record came from, when it isn't the domain's own.
    pub fn inherited_from(&self) -> Option<&str> {
        match self.outcome {
            Outcome::Found { at } if at > 0 => Some(&self.attempts[at].domain),
            _ => None,
        }
    }
}

pub(crate) async fn walk<T>(
    resolver: &impl Resolver,
    domain: String,
    domains: Vec<String>,
    name: impl Fn(&str) -> String,
    is_kind: fn(&str) -> bool,
    parse: fn(&str) -> Parsed<T>,
) -> Inherited<T> {
    let mut attempts = Vec::new();
    let mut outcome = Outcome::Missing;
    for (at, candidate) in domains.into_iter().enumerate() {
        let set = txt_set(resolver, name(&candidate), is_kind, parse).await;
        let ended = if set.failure().is_some() {
            Some(Outcome::Failed { at })
        } else if set.is_multiple() {
            Some(Outcome::Multiple { at })
        } else if set.single().is_some() {
            Some(Outcome::Found { at })
        } else {
            None
        };
        attempts.push(Attempt {
            domain: candidate,
            set,
        });
        if let Some(ended) = ended {
            outcome = ended;
            break;
        }
    }
    Inherited {
        domain,
        attempts,
        outcome,
    }
}

/// Polls every future to completion without a runtime's help, so discovery
/// stays executor-agnostic. Outputs are in input order.
pub(crate) async fn join_all<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut futures: Vec<Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut outputs: Vec<Option<F::Output>> = futures.iter().map(|_| None).collect();
    poll_fn(|cx| {
        let mut pending = false;
        for (future, output) in futures.iter_mut().zip(outputs.iter_mut()) {
            if output.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => *output = Some(value),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    outputs
        .into_iter()
        .map(|output| output.expect("polled to completion"))
        .collect()
}

#[cfg(test)]
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

#[cfg(test)]
mod tests;
