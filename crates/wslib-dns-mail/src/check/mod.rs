//! Checking a domain's records against their specifications and common
//! practice, as data: stable codes, a kind, a severity, a reference and a
//! typed detail. Wording is the consumer's.

mod bimi;
mod dkim;
mod dmarc;
mod dnssec;
mod finding;
mod mta_sts;
mod mx;
mod spf;

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

pub use bimi::{bimi_findings, bimi_logo_findings, bimi_vmc_findings};
pub use dkim::{DkimCheck, RSA_MINIMUM_BITS, RSA_RECOMMENDED_BITS, check_dkim, dkim_findings};
pub use dmarc::{DmarcCheck, check_dmarc, dmarc_findings};
pub use finding::{Detail, Finding, FindingCode, Kind, Severity};
pub use mta_sts::mta_sts_findings;
pub use mx::{MxCheck, check_mx, mx_findings};
pub use spf::{SPF_LENGTH_LIMIT, SpfCheck, check_spf, spf_findings};
use wslib_dns::{
    BudgetResolver, DnssecStatus, LoggingResolver, Lookup, LookupError, QueryRecord, Resolver,
};

use crate::ReportUri;
use crate::bimi::{BimiRecord, VmcVerification};
use crate::discover::{
    self, CertificateFetch, DkimDiscovery, DmarcDiscovery, DmarcDiscoveryMode, DnsblResult,
    Inherited, LogoFetch, MxDiscovery, Outcome, PolicyFetch, RecordSet, ReportAuthorisation,
    join_all,
};
use crate::mta_sts::MtaStsRecord;
use crate::spf::tree::{SpfTree, WalkLimits};
use crate::tls_rpt::TlsRptRecord;

/// A lookup that failed; one never sent marks `check` incomplete instead.
pub(crate) fn lookup_failure(check: &str, name: &str, error: &LookupError) -> Finding {
    let code = match error {
        LookupError::NotSent => return incomplete(check, name),
        LookupError::Bogus => FindingCode::DnssecBogus,
        _ => FindingCode::LookupFailed,
    };
    Finding::new(
        code,
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
#[non_exhaustive]
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
    /// Fetches the MTA-STS policy file, with clients made by these, when the
    /// domain publishes an MTA-STS record.
    #[cfg(feature = "http")]
    pub mta_sts_http: Option<discover::HttpClients>,
    /// Fetches and checks the BIMI logo, with clients made by these, when the
    /// governing BIMI record names one.
    #[cfg(feature = "http")]
    pub bimi_http: Option<discover::HttpClients>,
    /// Fetches and verifies the BIMI record's mark certificate (`a=`) with
    /// these, over `bimi_http`.
    #[cfg(feature = "http")]
    pub bimi_vmc: Option<crate::bimi::VmcOptions>,
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
            #[cfg(feature = "http")]
            mta_sts_http: None,
            #[cfg(feature = "http")]
            bimi_http: None,
            #[cfg(feature = "http")]
            bimi_vmc: None,
        }
    }
}

/// Everything [`check_domain`] found and everything wrong with it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DomainReport {
    pub domain: String,
    pub spf: SpfTree,
    pub dmarc: DmarcDiscovery,
    pub report_authorisations: Vec<(ReportUri, ReportAuthorisation)>,
    pub dkim: Vec<DkimDiscovery>,
    pub mx: MxDiscovery,
    pub dnsbl: Vec<DnsblResult>,
    /// The worst status among the domain's own answers, or Indeterminate
    /// when the resolver can't validate; set only by a validating resolver.
    pub dnssec: Option<DnssecStatus>,
    pub bimi: Inherited<BimiRecord>,
    pub mta_sts: RecordSet<MtaStsRecord>,
    pub tls_rpt: RecordSet<TlsRptRecord>,
    /// Set when the policy file was fetched.
    pub mta_sts_policy: Option<PolicyFetch>,
    /// Set when the logo was fetched.
    pub bimi_logo: Option<LogoFetch>,
    /// Set when the mark certificate was fetched.
    pub bimi_certificate: Option<CertificateFetch>,
    /// Set when the fetched mark certificate was verified.
    pub bimi_vmc: Option<VmcVerification>,
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
    Bimi(Inherited<BimiRecord>, BimiFetches),
    MtaSts(
        RecordSet<MtaStsRecord>,
        RecordSet<TlsRptRecord>,
        Option<PolicyFetch>,
    ),
    DnssecProbe(Option<Lookup<String>>),
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
        Box::pin(async {
            let records = discover::bimi(dns, &domain, &options.bimi_selector).await;
            let fetches = bimi_fetches(dns, &records, options, deadline).await;
            Part::Bimi(records, fetches)
        }),
        Box::pin(async {
            let record = discover::mta_sts(dns, &domain).await;
            let policy = policy(dns, &record, &domain, options, deadline).await;
            Part::MtaSts(record, discover::tls_rpt(dns, &domain).await, policy)
        }),
        Box::pin(async { Part::DnssecProbe(dnssec::probe(dns).await) }),
    ];
    let (mut spf, mut dmarc, mut dkim, mut mx, mut bimi, mut mta_sts) =
        (None, None, None, None, None, None);
    let mut probe = None;
    for part in join_all(parts).await {
        match part {
            Part::Spf(check) => spf = Some(check),
            Part::Dmarc(check) => dmarc = Some(check),
            Part::Dkim(check) => dkim = Some(check),
            Part::Mx(check) => mx = Some(check),
            Part::Bimi(records, fetches) => bimi = Some((records, fetches)),
            Part::MtaSts(record, tls_rpt, policy) => mta_sts = Some((record, tls_rpt, policy)),
            Part::DnssecProbe(lookup) => probe = lookup,
        }
    }
    let (spf, dmarc, dkim, mx, (bimi, bimi_fetches), (mta_sts, tls_rpt, mta_sts_policy)) = (
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
    if let (Outcome::Found { at }, Some(logo)) = (bimi.outcome, &bimi_fetches.logo) {
        findings.extend(bimi_logo_findings(&bimi.attempts[at].set.name, logo));
    }
    if let (Outcome::Found { at }, Some(certificate)) = (bimi.outcome, &bimi_fetches.certificate) {
        let subject = &bimi.attempts[at].set.name;
        findings.extend(bimi_vmc_findings(
            subject,
            certificate,
            bimi_fetches.vmc.as_ref(),
        ));
    }
    findings.extend(mta_sts_findings(
        &mta_sts,
        mta_sts_policy.as_ref(),
        &tls_rpt,
        Some(&mx.mx),
    ));
    let apex = [mx.mx.dnssec, spf.tree.root.records.dnssec]
        .into_iter()
        .flatten()
        .min();
    let (dnssec, dnssec_findings) =
        dnssec::dnssec_findings(dns, &domain, probe, apex, &findings).await;
    findings.extend(dnssec_findings);
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
        dnssec,
        bimi,
        mta_sts,
        tls_rpt,
        mta_sts_policy,
        bimi_logo: bimi_fetches.logo,
        bimi_certificate: bimi_fetches.certificate,
        bimi_vmc: bimi_fetches.vmc,
        findings,
        queries_sent,
        queries,
    }
}

/// What a BIMI record points at, fetched when clients were given: the logo,
/// and the mark certificate verified against it.
#[derive(Default)]
struct BimiFetches {
    logo: Option<LogoFetch>,
    certificate: Option<CertificateFetch>,
    vmc: Option<VmcVerification>,
}

#[cfg(not(feature = "http"))]
async fn bimi_fetches(
    _: &impl Resolver,
    _: &Inherited<BimiRecord>,
    _: &CheckOptions,
    _: Option<Instant>,
) -> BimiFetches {
    BimiFetches::default()
}

#[cfg(feature = "http")]
async fn bimi_fetches(
    resolver: &impl Resolver,
    records: &Inherited<BimiRecord>,
    options: &CheckOptions,
    deadline: Option<Instant>,
) -> BimiFetches {
    let mut fetches = BimiFetches::default();
    let (Outcome::Found { at }, Some(found), Some(clients)) =
        (records.outcome, records.found(), &options.bimi_http)
    else {
        return fetches;
    };
    let remaining = || deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
    let record = &found.parsed.record;
    if let Some(url) = record.location.as_deref().filter(|url| !url.is_empty()) {
        fetches.logo = Some(discover::bimi_logo(resolver, clients, url, remaining()).await);
    }
    let authority = record.authority.as_deref().filter(|url| !url.is_empty());
    if let (Some(url), Some(vmc)) = (authority, &options.bimi_vmc) {
        let certificate = discover::bimi_certificate(resolver, clients, url, remaining()).await;
        if let CertificateFetch::Fetched { pem, .. } = &certificate {
            let logo = match &fetches.logo {
                Some(LogoFetch::Fetched { body, .. }) => Some(body.as_slice()),
                _ => None,
            };
            let domain = &records.attempts[at].domain;
            fetches.vmc = Some(crate::bimi::verify_vmc(
                pem,
                domain,
                &options.bimi_selector,
                logo,
                vmc,
            ));
        }
        fetches.certificate = Some(certificate);
    }
    fetches
}

/// The policy file, when the domain publishes an MTA-STS record and a
/// client was given, fetched within what's left of the deadline.
#[cfg_attr(not(feature = "http"), allow(unused_variables))]
async fn policy(
    resolver: &impl Resolver,
    record: &RecordSet<MtaStsRecord>,
    domain: &str,
    options: &CheckOptions,
    deadline: Option<Instant>,
) -> Option<PolicyFetch> {
    record.single()?;
    #[cfg(feature = "http")]
    if let Some(clients) = &options.mta_sts_http {
        let remaining = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        return Some(discover::mta_sts_policy(resolver, clients, domain, remaining).await);
    }
    None
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
