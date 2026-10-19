use super::{Detail, Finding, FindingCode, Severity, lookup_failure};
use crate::FaultCode;
use crate::bimi::BimiRecord;
use crate::discover::{DmarcDiscovery, Inherited, Outcome};
use crate::dmarc::Policy;

/// The findings for a BIMI lookup. `dmarc` holds the DMARC discoveries that
/// govern the domain: its own, and its organisational domain's when they
/// differ. BIMI needs each to enforce.
pub fn bimi_findings(records: &Inherited<BimiRecord>, dmarc: &[&DmarcDiscovery]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let at = match records.outcome {
        Outcome::Found { at } => at,
        Outcome::Failed { at } => {
            let set = &records.attempts[at].set;
            findings.extend(
                set.failure()
                    .map(|error| lookup_failure("bimi", &set.name, error)),
            );
            return findings;
        }
        Outcome::Multiple { at } => {
            let set = &records.attempts[at].set;
            let texts = set.records.iter().map(|r| r.text.clone()).collect();
            findings.push(Finding::new(
                FindingCode::BimiSyntax,
                &set.name,
                Detail::Records { texts },
            ));
            return findings;
        }
        Outcome::Missing => return findings,
    };
    let set = &records.attempts[at].set;
    let published = set.single().expect("found means exactly one record");
    for fault in published
        .parsed
        .faults
        .iter()
        .filter(|fault| fault.code != FaultCode::UnknownTag)
    {
        let detail = Detail::Fault {
            fault: fault.clone(),
            text: published.text.clone(),
        };
        findings.push(match fault.code {
            FaultCode::InsecureUri => Finding::new(FindingCode::BimiInsecureUri, &set.name, detail),
            code if code.is_advisory() => {
                Finding::new(FindingCode::BimiSyntax, &set.name, detail).severity(Severity::Warning)
            }
            _ => Finding::new(FindingCode::BimiSyntax, &set.name, detail),
        });
    }
    if published.parsed.record.is_declined() {
        return findings;
    }
    for discovery in dmarc {
        if let Some(detail) = not_enforcing(discovery) {
            findings.push(Finding::new(
                FindingCode::BimiDmarcNotEnforcing,
                &set.name,
                detail,
            ));
        }
    }
    findings
}

/// BIMI requires `p=quarantine` or `reject` at `pct=100`, with no `sp=none`.
fn not_enforcing(discovery: &DmarcDiscovery) -> Option<Detail> {
    let domain = discovery.records.domain.clone();
    let Some(found) = discovery.records.found() else {
        return Some(Detail::Enforcement {
            domain,
            policy: None,
            percent: 0,
            subdomain_policy: None,
        });
    };
    let record = &found.parsed.record;
    let policy = discovery
        .applies
        .map_or(record.effective_policy(), |applies| applies.policy);
    let subdomain_policy = record.effective_subdomain_policy();
    let enforcing =
        |policy: Option<Policy>| matches!(policy, Some(Policy::Quarantine | Policy::Reject));
    let percent = record.effective_percent();
    (!(enforcing(policy) && enforcing(subdomain_policy) && percent == 100)).then_some(
        Detail::Enforcement {
            domain,
            policy,
            percent,
            subdomain_policy,
        },
    )
}
