use super::{Detail, Finding, FindingCode, Severity, lookup_failure};
use crate::discover::{FetchFailure, MxDiscovery, PolicyFetch, RecordSet};
use crate::mta_sts::{MAX_AGE_LIMIT, Mode, MtaStsPolicy, MtaStsRecord};
use crate::tls_rpt::TlsRptRecord;
use crate::{FaultCode, Parsed};

/// The findings for the MTA-STS and TLS-RPT records of a domain, the policy
/// when it was fetched, and the MX hosts it must cover.
pub fn mta_sts_findings(
    record: &RecordSet<MtaStsRecord>,
    policy: Option<&PolicyFetch>,
    tls_rpt: &RecordSet<TlsRptRecord>,
    mx: Option<&MxDiscovery>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    tag_list_findings(
        "mta_sts",
        record,
        FindingCode::MtaStsSyntax,
        FindingCode::MtaStsMultipleRecords,
        &mut findings,
    );
    tag_list_findings(
        "tls_rpt",
        tls_rpt,
        FindingCode::TlsRptSyntax,
        FindingCode::TlsRptSyntax,
        &mut findings,
    );
    if record.single().is_some() && tls_rpt.is_absent() {
        findings.push(Finding::new(
            FindingCode::TlsRptMissingWithMtaSts,
            &tls_rpt.name,
            Detail::None,
        ));
    }
    match policy {
        Some(PolicyFetch::Unreachable {
            failure: FetchFailure::NotSent,
            ..
        }) => findings.push(super::incomplete("mta_sts", &record.name)),
        Some(PolicyFetch::Unreachable { url, failure }) => findings.push(Finding::new(
            FindingCode::MtaStsPolicyUnreachable,
            &record.name,
            Detail::Unreachable {
                url: url.clone(),
                failure: failure.clone(),
            },
        )),
        Some(PolicyFetch::Fetched { url, body, policy }) => {
            policy_findings(url, body, policy, mx, &mut findings)
        }
        None => {}
    }
    findings
}

fn tag_list_findings<T>(
    check: &str,
    set: &RecordSet<T>,
    syntax: FindingCode,
    multiple: FindingCode,
    findings: &mut Vec<Finding>,
) {
    if let Some(error) = set.failure() {
        findings.push(lookup_failure(check, &set.name, error));
        return;
    }
    if set.is_multiple() {
        let texts = set.records.iter().map(|r| r.text.clone()).collect();
        findings.push(Finding::new(multiple, &set.name, Detail::Records { texts }));
        return;
    }
    if let Some(published) = set.single() {
        for fault in published
            .parsed
            .faults
            .iter()
            .filter(|fault| fault.code != FaultCode::UnknownTag)
        {
            let finding = Finding::new(
                syntax,
                &set.name,
                Detail::Fault {
                    fault: fault.clone(),
                    text: published.text.clone(),
                },
            );
            findings.push(if fault.code.is_advisory() {
                finding.severity(Severity::Warning)
            } else {
                finding
            });
        }
    }
}

fn policy_findings(
    url: &str,
    body: &str,
    policy: &Parsed<MtaStsPolicy>,
    mx: Option<&MxDiscovery>,
    findings: &mut Vec<Finding>,
) {
    for fault in &policy.faults {
        if fault.code == FaultCode::InvalidTagValue && fault.name.as_deref() == Some("max_age") {
            let written = policy
                .record
                .fields
                .iter()
                .find(|field| field.name == "max_age");
            findings.push(Finding::new(
                FindingCode::MtaStsMaxAgeOutOfRange,
                url,
                Detail::MaxAge {
                    seconds: written.and_then(|field| field.value.parse().ok()),
                    limit: MAX_AGE_LIMIT,
                },
            ));
            continue;
        }
        findings.push(Finding::new(
            FindingCode::MtaStsSyntax,
            url,
            Detail::Fault {
                fault: fault.clone(),
                text: body.to_owned(),
            },
        ));
    }
    let mode = policy.record.mode;
    if mode == Some(Mode::Testing) {
        findings.push(Finding::new(FindingCode::MtaStsTesting, url, Detail::None));
    }
    let applies = matches!(mode, Some(Mode::Enforce | Mode::Testing));
    if let Some(mx) = mx.filter(|mx| applies && !mx.is_null()) {
        for host in mx
            .hosts
            .iter()
            .filter(|host| !host.is_null() && !policy.record.covers(&host.exchange))
        {
            findings.push(Finding::new(
                FindingCode::MtaStsMxNotCovered,
                url,
                Detail::Uncovered {
                    exchange: host.exchange.clone(),
                },
            ));
        }
    }
}
