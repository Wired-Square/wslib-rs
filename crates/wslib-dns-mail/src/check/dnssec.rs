use wslib_dns::{DnssecStatus, Lookup, LookupError, Resolver};

use super::{Detail, Finding, FindingCode, incomplete, lookup_failure};

/// The root zone is always signed, so a validating resolver that can't call
/// its NS answer Secure isn't getting signatures from upstream.
pub(crate) const PROBE: &str = ".";

pub(crate) async fn probe(resolver: &impl Resolver) -> Option<Lookup<String>> {
    if resolver.validates() {
        Some(resolver.ns(PROBE).await)
    } else {
        None
    }
}

/// The domain's DNSSEC status and the findings about it, given the probe,
/// the worst status among the domain's own answers, and the other findings.
/// A SERVFAIL inside a zone with DS records is likely a validation failure
/// an upstream resolver hid, so it's flagged as a suspected bogus.
pub(crate) async fn dnssec_findings(
    resolver: &impl Resolver,
    domain: &str,
    probe: Option<Lookup<String>>,
    apex: Option<DnssecStatus>,
    findings: &[Finding],
) -> (Option<DnssecStatus>, Vec<Finding>) {
    let Some(probe) = probe else {
        return (None, Vec::new());
    };
    let mut out = Vec::new();
    let status = match probe {
        Ok(answer) if answer.dnssec == Some(DnssecStatus::Secure) => apex,
        Ok(answer) => {
            out.push(Finding::new(
                FindingCode::DnssecUnsupportedResolver,
                PROBE,
                Detail::Dnssec {
                    status: answer.dnssec.unwrap_or(DnssecStatus::Indeterminate),
                },
            ));
            Some(DnssecStatus::Indeterminate)
        }
        Err(LookupError::NotSent) => {
            out.push(incomplete("dnssec", domain));
            None
        }
        Err(error) => {
            out.push(lookup_failure("dnssec", PROBE, &error));
            Some(DnssecStatus::Indeterminate)
        }
    };
    if let Some(status) = status {
        out.push(Finding::new(
            FindingCode::DnssecStatus,
            domain,
            Detail::Dnssec { status },
        ));
    }
    if let Some(zone) = wslib_dns::registrable_domain(domain)
        && findings.iter().any(|finding| servfail_in(finding, &zone))
        && let Ok(answer) = resolver.ds(&zone).await
    {
        out.push(Finding::new(
            FindingCode::DnssecSuspectedBogus,
            &zone,
            Detail::SuspectedBogus {
                zone: zone.clone(),
                ds: answer.records,
            },
        ));
    }
    (status, out)
}

fn servfail_in(finding: &Finding, zone: &str) -> bool {
    matches!(
        &finding.detail,
        Detail::Lookup { name, error: LookupError::ServFail }
            if name == zone || name.strip_suffix(zone).is_some_and(|rest| rest.ends_with('.'))
    )
}
