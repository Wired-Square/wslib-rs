//! Checking a domain's records against their specifications and common
//! practice, as data: stable codes, a kind, a severity, a reference and a
//! typed detail. Wording is the consumer's.

mod bimi;
mod dkim;
mod dmarc;
mod finding;
mod mta_sts;
mod mx;
mod spf;

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

pub use bimi::bimi_findings;
pub use dkim::{DkimCheck, RSA_MINIMUM_BITS, RSA_RECOMMENDED_BITS, check_dkim, dkim_findings};
pub use dmarc::{DmarcCheck, check_dmarc, dmarc_findings};
pub use finding::{Detail, Finding, FindingCode, Kind, Severity};
pub use mta_sts::{PolicyFetch, mta_sts_findings};
pub use mx::{MxCheck, check_mx, mx_findings};
pub use spf::{SPF_LENGTH_LIMIT, SpfCheck, check_spf, spf_findings};
use wslib_dns::{BudgetResolver, LoggingResolver, LookupError, QueryRecord, Resolver};

use crate::ReportUri;
use crate::bimi::BimiRecord;
use crate::discover::{
    self, DkimDiscovery, DmarcDiscovery, DmarcDiscoveryMode, DnsblResult, Inherited, MxDiscovery,
    RecordSet, ReportAuthorisation, join_all,
};
use crate::mta_sts::MtaStsRecord;
use crate::spf::tree::{SpfTree, WalkLimits};
use crate::tls_rpt::TlsRptRecord;

/// A lookup that failed; one never sent marks `check` incomplete instead.
pub(crate) fn lookup_failure(check: &str, name: &str, error: &LookupError) -> Finding {
    if *error == LookupError::NotSent {
        return incomplete(check, name);
    }
    Finding::new(
        FindingCode::LookupFailed,
        name,
        Detail::Lookup {
            name: name.to_owned(),
            error: error.clone(),
        },
    )
}

pub(crate) fn incomplete(check: &str, subject: &str) -> Finding {
    Finding::new(
        FindingCode::Incomplete,
        subject,
        Detail::Incomplete {
            checks: vec![check.to_owned()],
        },
    )
}

/// What [`check_domain`] looks at, and its bounds.
#[derive(Clone, Debug)]
pub struct CheckOptions {
    /// DKIM selectors the domain is expected to publish.
    pub dkim_selectors: Vec<String>,
    /// Also try [`COMMON_SELECTORS`](crate::discover::COMMON_SELECTORS).
    pub probe_common_selectors: bool,
    pub bimi_selector: String,
    pub dmarc_mode: DmarcDiscoveryMode,
    /// DNS blocklists to ask about every MX address.
    pub dnsbl_zones: Vec<String>,
    pub spf_limits: WalkLimits,
    /// After this, no more queries are sent.
    pub deadline: Option<Duration>,
    /// At most this many queries.
    pub max_queries: Option<u32>,
    /// Keep every query and its outcome in the report.
    pub query_log: bool,
}

/// No selectors or blocklists, RFC 7489 discovery, a 10 s deadline and 200
/// queries.
impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            dkim_selectors: Vec::new(),
            probe_common_selectors: false,
            bimi_selector: "default".into(),
            dmarc_mode: DmarcDiscoveryMode::default(),
            dnsbl_zones: Vec::new(),
            spf_limits: WalkLimits::default(),
            deadline: Some(Duration::from_secs(10)),
            max_queries: Some(200),
            query_log: false,
        }
    }
}

/// Everything [`check_domain`] found and everything wrong with it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainReport {
    pub domain: String,
    pub spf: SpfTree,
    pub dmarc: DmarcDiscovery,
    pub report_authorisations: Vec<(ReportUri, ReportAuthorisation)>,
    pub dkim: Vec<DkimDiscovery>,
    pub mx: MxDiscovery,
    pub dnsbl: Vec<DnsblResult>,
    pub bimi: Inherited<BimiRecord>,
    pub mta_sts: RecordSet<MtaStsRecord>,
    pub tls_rpt: RecordSet<TlsRptRecord>,
    /// Ordered by family, as the checks run.
    pub findings: Vec<Finding>,
    pub queries_sent: u32,
    /// Set when [`CheckOptions::query_log`] is.
    pub queries: Option<Vec<QueryRecord>>,
}

enum Part {
    Spf(SpfCheck),
    Dmarc(DmarcCheck),
    Dkim(DkimCheck),
    Mx(MxCheck),
    Bimi(Inherited<BimiRecord>),
    MtaSts(RecordSet<MtaStsRecord>, RecordSet<TlsRptRecord>),
}

type BoxedPart<'a> = Pin<Box<dyn Future<Output = Part> + Send + 'a>>;

/// Runs every check on `domain` concurrently, within the deadline and query
/// budget. A check cut short adds an `incomplete` finding naming it.
pub async fn check_domain(
    resolver: &impl Resolver,
    domain: &str,
    options: &CheckOptions,
) -> DomainReport {
    let deadline = options.deadline.map(|deadline| Instant::now() + deadline);
    let dns = LoggingResolver::new(BudgetResolver::new(resolver, deadline, options.max_queries));
    let dns = &dns;
    let domain = discover::ascii(domain);
    let parts: Vec<BoxedPart<'_>> = vec![
        Box::pin(async { Part::Spf(check_spf(dns, &domain, options.spf_limits).await) }),
        Box::pin(async { Part::Dmarc(check_dmarc(dns, &domain, options.dmarc_mode).await) }),
        Box::pin(async {
            Part::Dkim(
                check_dkim(
                    dns,
                    &domain,
                    &options.dkim_selectors,
                    options.probe_common_selectors,
                )
                .await,
            )
        }),
        Box::pin(async { Part::Mx(check_mx(dns, &domain, &options.dnsbl_zones).await) }),
        Box::pin(async { Part::Bimi(discover::bimi(dns, &domain, &options.bimi_selector).await) }),
        Box::pin(async {
            Part::MtaSts(
                discover::mta_sts(dns, &domain).await,
                discover::tls_rpt(dns, &domain).await,
            )
        }),
    ];
    let (mut spf, mut dmarc, mut dkim, mut mx, mut bimi, mut mta_sts) =
        (None, None, None, None, None, None);
    for part in join_all(parts).await {
        match part {
            Part::Spf(check) => spf = Some(check),
            Part::Dmarc(check) => dmarc = Some(check),
            Part::Dkim(check) => dkim = Some(check),
            Part::Mx(check) => mx = Some(check),
            Part::Bimi(records) => bimi = Some(records),
            Part::MtaSts(record, tls_rpt) => mta_sts = Some((record, tls_rpt)),
        }
    }
    let (spf, dmarc, dkim, mx, bimi, (mta_sts, tls_rpt)) = (
        spf.expect("every part runs"),
        dmarc.expect("every part runs"),
        dkim.expect("every part runs"),
        mx.expect("every part runs"),
        bimi.expect("every part runs"),
        mta_sts.expect("every part runs"),
    );

    let organisational =
        organisational_dmarc(dns, &domain, &bimi, &dmarc.discovery, options.dmarc_mode).await;
    let governing: Vec<&DmarcDiscovery> = std::iter::once(&dmarc.discovery)
        .chain(organisational.as_ref())
        .collect();

    let mut findings = Vec::new();
    findings.extend(spf.findings);
    findings.extend(dmarc.findings);
    findings.extend(dkim.findings);
    findings.extend(mx.findings);
    findings.extend(bimi_findings(&bimi, &governing));
    findings.extend(mta_sts_findings(&mta_sts, None, &tls_rpt, Some(&mx.mx)));
    merge_incomplete(&domain, &mut findings);

    let queries_sent = dns.inner().queries_sent();
    let queries = options.query_log.then(|| dns.log());
    DomainReport {
        domain,
        spf: spf.tree,
        dmarc: dmarc.discovery,
        report_authorisations: dmarc.authorisations,
        dkim: dkim.selectors,
        mx: mx.mx,
        dnsbl: mx.dnsbl,
        bimi,
        mta_sts,
        tls_rpt,
        findings,
        queries_sent,
        queries,
    }
}

/// BIMI needs the organisational domain's DMARC policy to enforce as well as
/// the domain's own, so that one is looked up when it isn't already known.
async fn organisational_dmarc(
    resolver: &impl Resolver,
    domain: &str,
    bimi: &Inherited<BimiRecord>,
    dmarc: &DmarcDiscovery,
    mode: DmarcDiscoveryMode,
) -> Option<DmarcDiscovery> {
    let wants_enforcement = bimi
        .found()
        .is_some_and(|found| !found.parsed.record.is_declined());
    let organisation = wslib_dns::registrable_domain(domain)?;
    let known =
        organisation == domain || dmarc.records.inherited_from() == Some(organisation.as_str());
    if !wants_enforcement || known {
        return None;
    }
    Some(discover::dmarc(resolver, &organisation, mode).await)
}

/// One `incomplete` finding, listing every check that was cut short, in
/// place of one per lookup.
fn merge_incomplete(domain: &str, findings: &mut Vec<Finding>) {
    let mut checks: Vec<String> = Vec::new();
    findings.retain(|finding| match (&finding.code, &finding.detail) {
        (FindingCode::Incomplete, Detail::Incomplete { checks: cut }) => {
            checks.extend(cut.iter().cloned());
            false
        }
        _ => true,
    });
    if !checks.is_empty() {
        checks.sort();
        checks.dedup();
        findings.push(Finding::new(
            FindingCode::Incomplete,
            domain,
            Detail::Incomplete { checks },
        ));
    }
}

#[cfg(test)]
mod tests;
