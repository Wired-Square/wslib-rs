use wslib_dns::Resolver;

use super::{Detail, Finding, FindingCode, Severity, lookup_failure};
use crate::FaultCode;
use crate::discover::{COMMON_SELECTORS, DkimDiscovery, dkim, join_all, probe_dkim};

/// RFC 8301 §3.2: verifiers must refuse RSA keys shorter than this.
pub const RSA_MINIMUM_BITS: u32 = 1024;
/// RFC 8301 §3.2: signers should use at least this.
pub const RSA_RECOMMENDED_BITS: u32 = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DkimCheck {
    /// The selectors asked for, then any the probe found.
    pub selectors: Vec<DkimDiscovery>,
    pub findings: Vec<Finding>,
}

/// Looks up `selectors`, and the common selectors too when `probe` is set,
/// all concurrently.
pub async fn check_dkim(
    resolver: &impl Resolver,
    domain: &str,
    selectors: &[String],
    probe: bool,
) -> DkimCheck {
    let asked = join_all(
        selectors
            .iter()
            .map(|selector| dkim(resolver, selector, domain)),
    )
    .await;
    let mut found = asked.clone();
    if probe {
        let others: Vec<&str> = COMMON_SELECTORS
            .iter()
            .copied()
            .filter(|common| {
                !selectors
                    .iter()
                    .any(|asked| asked.eq_ignore_ascii_case(common))
            })
            .collect();
        found.extend(probe_dkim(resolver, domain, others).await);
    }
    let mut findings: Vec<Finding> = asked
        .iter()
        .filter(|selector| selector.records.is_absent())
        .map(|selector| {
            Finding::new(
                FindingCode::DkimKeyMissing,
                &selector.records.name,
                Detail::None,
            )
        })
        .collect();
    findings.extend(dkim_findings(&found));
    DkimCheck {
        selectors: found,
        findings,
    }
}

/// The findings for selectors that were looked up; an absent one is only a
/// finding when the caller expected it, so it isn't one here.
pub fn dkim_findings(selectors: &[DkimDiscovery]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for selector in selectors {
        let set = &selector.records;
        if let Some(error) = set.failure() {
            findings.push(lookup_failure("dkim", &set.name, error));
            continue;
        }
        if set.is_multiple() {
            let texts = set.records.iter().map(|r| r.text.clone()).collect();
            findings.push(Finding::new(
                FindingCode::DkimMultipleRecords,
                &set.name,
                Detail::Records { texts },
            ));
            continue;
        }
        let Some(published) = set.single() else {
            continue;
        };
        for fault in published
            .parsed
            .faults
            .iter()
            .filter(|fault| fault.code != FaultCode::UnknownTag)
        {
            let finding = Finding::new(
                FindingCode::DkimSyntax,
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
        let record = &published.parsed.record;
        if record.is_revoked() {
            findings.push(Finding::new(
                FindingCode::DkimKeyRevoked,
                &set.name,
                Detail::None,
            ));
        }
        if record.is_testing() {
            findings.push(Finding::new(
                FindingCode::DkimTestingMode,
                &set.name,
                Detail::None,
            ));
        }
        match record.rsa_bits {
            Some(bits) if bits < RSA_MINIMUM_BITS => {
                findings.push(Finding::new(
                    FindingCode::DkimRsaKeyTooShort,
                    &set.name,
                    Detail::KeySize { bits },
                ));
            }
            Some(bits) if bits < RSA_RECOMMENDED_BITS => {
                findings.push(Finding::new(
                    FindingCode::DkimRsaKeyWeak,
                    &set.name,
                    Detail::KeySize { bits },
                ));
            }
            _ => {}
        }
    }
    findings
}
