use wslib_dns::{LookupError, Resolver};

use super::{Detail, Finding, FindingCode, incomplete, lookup_failure};
use crate::discover::{
    DmarcDiscovery, DmarcDiscoveryMode, Outcome, ReportAuthorisation, dmarc,
    dmarc_report_authorisation, join_all,
};
use crate::dmarc::Policy;
use crate::{FaultCode, ReportUri};

/// What a receiver that reads RFC 7489 §6.3 to the letter does with a version
/// in the wrong case.
const NONCANONICAL_VERSION_RISK: &str =
    "a receiver that applies RFC 7489 §6.3 strictly ignores the whole record";

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DmarcCheck {
    pub discovery: DmarcDiscovery,
    /// Each `rua` and `ruf` destination of the record found, and whether it
    /// takes reports for the domain (RFC 7489 §7.1).
    pub authorisations: Vec<(ReportUri, ReportAuthorisation)>,
    pub findings: Vec<Finding>,
}

pub async fn check_dmarc(
    resolver: &impl Resolver,
    domain: &str,
    mode: DmarcDiscoveryMode,
) -> DmarcCheck {
    let discovery = dmarc(resolver, domain, mode).await;
    let mut authorisations = Vec::new();
    if let Some(found) = discovery.records.found() {
        let policy_domain = discovery
            .records
            .inherited_from()
            .unwrap_or(&discovery.records.domain)
            .to_owned();
        let record = &found.parsed.record;
        let uris: Vec<ReportUri> = record
            .aggregate
            .iter()
            .chain(&record.failure)
            .cloned()
            .collect();
        let checked = join_all(
            uris.iter()
                .map(|uri| dmarc_report_authorisation(resolver, &policy_domain, uri)),
        )
        .await;
        authorisations = uris.into_iter().zip(checked).collect();
    }
    let findings = dmarc_findings(&discovery, &authorisations);
    DmarcCheck {
        discovery,
        authorisations,
        findings,
    }
}

/// A TXT string at a `_dmarc` name that would be a DMARC record if `v` came
/// first. Receivers skip it as not DMARC at all (§6.6.3), so it is reported
/// apart from the record that was used.
fn version_not_first(discovery: &DmarcDiscovery) -> impl Iterator<Item = Finding> + '_ {
    discovery.records.attempts.iter().flat_map(|attempt| {
        attempt.set.others.iter().filter_map(|text| {
            let parsed = crate::dmarc::parse(text);
            let fault = parsed
                .faults
                .into_iter()
                .find(|fault| fault.code == FaultCode::VersionNotFirst)?;
            Some(Finding::new(
                FindingCode::DmarcVersionNotFirst,
                &attempt.set.name,
                Detail::Fault {
                    fault,
                    text: text.clone(),
                },
            ))
        })
    })
}

pub fn dmarc_findings(
    discovery: &DmarcDiscovery,
    authorisations: &[(ReportUri, ReportAuthorisation)],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let records = &discovery.records;
    findings.extend(version_not_first(discovery));
    let at = match records.outcome {
        Outcome::Missing => {
            findings.push(Finding::new(
                FindingCode::DmarcMissing,
                &records.domain,
                Detail::None,
            ));
            return findings;
        }
        Outcome::Failed { at } => {
            let set = &records.attempts[at].set;
            if let Some(error) = set.failure() {
                findings.push(lookup_failure("dmarc", &set.name, error));
            }
            return findings;
        }
        Outcome::Multiple { at } => {
            let set = &records.attempts[at].set;
            let texts = set.records.iter().map(|r| r.text.clone()).collect();
            findings.push(Finding::new(
                FindingCode::DmarcMultipleRecords,
                &set.name,
                Detail::Records { texts },
            ));
            return findings;
        }
        Outcome::Found { at } => at,
    };
    let set = &records.attempts[at].set;
    let subject = set.name.as_str();
    let published = set.single().expect("found means exactly one record");
    let record = &published.parsed.record;

    if let Some(from) = records.inherited_from() {
        findings.push(Finding::new(
            FindingCode::DmarcPolicyInherited,
            &records.domain,
            Detail::Inherited {
                from: from.to_owned(),
            },
        ));
    }
    if let Some(error) = &discovery.existence_error {
        findings.push(lookup_failure("dmarc", &records.domain, error));
    }
    for fault in &published.parsed.faults {
        let fault_detail = || Detail::Fault {
            fault: fault.clone(),
            text: published.text.clone(),
        };
        let policy_detail = || Detail::Policy {
            tag: fault.name.clone().unwrap_or_default(),
            treated_as_none: record.policy_treated_as_none(),
        };
        let is_policy_tag = matches!(fault.name.as_deref(), Some("p" | "sp"));
        let finding = match fault.code {
            FaultCode::VersionNotFirst => {
                Finding::new(FindingCode::DmarcVersionNotFirst, subject, fault_detail())
            }
            FaultCode::NoncanonicalVersion => Finding::new(
                FindingCode::DmarcVersionNoncanonical,
                subject,
                Detail::Risk {
                    fault: fault.clone(),
                    text: published.text.clone(),
                    risk: NONCANONICAL_VERSION_RISK.to_owned(),
                },
            ),
            FaultCode::TagOutOfOrder => {
                Finding::new(FindingCode::DmarcPolicyOutOfOrder, subject, fault_detail())
            }
            FaultCode::DuplicateTag => {
                Finding::new(FindingCode::DmarcTagDuplicate, subject, fault_detail())
            }
            FaultCode::UnknownTag => {
                Finding::new(FindingCode::DmarcTagUnknown, subject, fault_detail())
            }
            FaultCode::MissingTag if is_policy_tag => {
                Finding::new(FindingCode::DmarcPolicyMissing, subject, policy_detail())
            }
            FaultCode::InvalidTagValue if is_policy_tag => {
                Finding::new(FindingCode::DmarcPolicyInvalid, subject, policy_detail())
            }
            FaultCode::InvalidTagValue => {
                Finding::new(FindingCode::DmarcTagValueInvalid, subject, fault_detail())
            }
            FaultCode::InvalidUri => {
                Finding::new(FindingCode::DmarcReportUriInvalid, subject, fault_detail())
            }
            _ => Finding::new(FindingCode::DmarcSyntax, subject, fault_detail()),
        };
        findings.push(finding);
    }

    if let Some(percent) = record.percent.filter(|&percent| percent < 100) {
        findings.push(Finding::new(
            FindingCode::DmarcPctPartial,
            subject,
            Detail::Percent { percent },
        ));
    }
    if let Some(domain_policy) = record.policy {
        for (tag, policy) in [
            ("sp", record.subdomain_policy),
            ("np", record.non_existent_policy),
        ] {
            if let Some(policy) = policy.filter(|&policy| policy < domain_policy) {
                findings.push(Finding::new(
                    FindingCode::DmarcSubdomainPolicyWeaker,
                    subject,
                    Detail::Weaker {
                        tag: tag.to_owned(),
                        policy,
                        domain_policy,
                    },
                ));
            }
        }
    }
    if record.aggregate.is_empty() {
        findings.push(Finding::new(
            FindingCode::DmarcNoAggregateReports,
            subject,
            Detail::None,
        ));
    }
    let applied = discovery
        .applies
        .map(|applies| applies.policy)
        .unwrap_or_else(|| record.effective_policy());
    if applied == Some(Policy::None) {
        findings.push(Finding::new(
            FindingCode::DmarcPolicyNone,
            &records.domain,
            Detail::None,
        ));
    }

    for (uri, authorisation) in authorisations {
        let report = |name: &str, error: Option<LookupError>| Detail::Report {
            uri: uri.uri.clone(),
            name: Some(name.to_owned()),
            error,
        };
        match authorisation {
            ReportAuthorisation::Unauthorised { name } => findings.push(Finding::new(
                FindingCode::DmarcExternalReportUnauthorised,
                subject,
                report(name, None),
            )),
            ReportAuthorisation::Failed {
                error: LookupError::NotSent,
                ..
            } => findings.push(incomplete("dmarc", &records.domain)),
            ReportAuthorisation::Failed { name, error } => findings.push(Finding::new(
                FindingCode::DmarcExternalReportLookupFailed,
                subject,
                report(name, Some(error.clone())),
            )),
            _ => {}
        }
    }
    findings
}
