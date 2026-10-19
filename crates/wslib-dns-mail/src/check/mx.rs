use std::net::IpAddr;

use wslib_dns::{DnssecStatus, Resolver};

use super::{Detail, Finding, FindingCode, Severity, lookup_failure};
use crate::discover::{DnsblResult, DnsblStatus, MxDiscovery, TlsaSet, dnsbl, join_all, mx};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MxCheck {
    pub mx: MxDiscovery,
    /// Every exchange address against every zone given.
    pub dnsbl: Vec<DnsblResult>,
    pub findings: Vec<Finding>,
}

/// Inspects the MX hosts of `domain` and, for each zone in `dnsbl_zones`,
/// asks whether their addresses are listed.
pub async fn check_mx(resolver: &impl Resolver, domain: &str, dnsbl_zones: &[String]) -> MxCheck {
    let mx = mx(resolver, domain).await;
    let mut addresses: Vec<IpAddr> = mx
        .hosts
        .iter()
        .flat_map(|host| host.addresses.iter().copied())
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    let queries: Vec<(IpAddr, &str)> = addresses
        .iter()
        .flat_map(|&address| dnsbl_zones.iter().map(move |zone| (address, zone.as_str())))
        .collect();
    let dnsbl = join_all(
        queries
            .into_iter()
            .map(|(address, zone)| dnsbl(resolver, address, zone)),
    )
    .await;
    let findings = mx_findings(&mx, &dnsbl);
    MxCheck {
        mx,
        dnsbl,
        findings,
    }
}

pub fn mx_findings(mx: &MxDiscovery, dnsbl: &[DnsblResult]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let domain = &mx.domain;
    match &mx.error {
        Some(error) if error.is_absent() => {
            findings.push(Finding::new(FindingCode::MxMissing, domain, Detail::None));
            return findings;
        }
        Some(error) => {
            findings.push(lookup_failure("mx", domain, error));
            return findings;
        }
        None => {}
    }
    if mx.has_null_with_others() {
        findings.push(Finding::new(
            FindingCode::MxNullWithOthers,
            domain,
            Detail::None,
        ));
    }
    if mx.is_null() {
        return findings;
    }
    let deliverable = mx.hosts.iter().any(|host| !host.addresses.is_empty());
    for host in mx.hosts.iter().filter(|host| !host.is_null()) {
        let exchange = |target: Option<String>| Detail::Exchange {
            exchange: host.exchange.clone(),
            target,
        };
        if host.is_ip_literal() {
            findings.push(Finding::new(
                FindingCode::MxExchangeIsIpLiteral,
                domain,
                exchange(None),
            ));
            continue;
        }
        if let Some(target) = &host.cname {
            findings.push(Finding::new(
                FindingCode::MxExchangeIsCname,
                domain,
                exchange(Some(target.clone())),
            ));
        }
        match &host.address_error {
            Some(error) if error.is_absent() => {
                let finding =
                    Finding::new(FindingCode::MxExchangeNoAddress, domain, exchange(None));
                // Mail still flows through the hosts that resolve, as with a
                // provider's ownership-check MX left at a low preference.
                findings.push(if deliverable {
                    finding.severity(Severity::Warning)
                } else {
                    finding
                });
            }
            Some(error) => findings.push(lookup_failure("mx", &host.exchange, error)),
            None => {}
        }
        if let Some(tlsa) = &host.tlsa {
            findings.extend(dane_findings(mx, &host.exchange, tlsa));
        }
        for reverse in &host.reverse {
            let address = || Detail::Address {
                exchange: host.exchange.clone(),
                address: reverse.address,
                names: reverse.names.clone(),
            };
            match &reverse.error {
                Some(error) if !error.is_absent() => {
                    findings.push(lookup_failure(
                        "mx",
                        &wslib_dns::reverse_name(reverse.address),
                        error,
                    ));
                }
                _ if reverse.names.is_empty() => {
                    findings.push(Finding::new(
                        FindingCode::MxPtrMissing,
                        &host.exchange,
                        address(),
                    ));
                }
                _ if !reverse.forward_confirmed => {
                    findings.push(Finding::new(
                        FindingCode::MxFcrdnsMismatch,
                        &host.exchange,
                        address(),
                    ));
                }
                _ => {}
            }
        }
    }
    for result in dnsbl {
        let listed = || Detail::Listed {
            address: result.address,
            zone: result.zone.clone(),
            codes: result.codes.clone(),
            reason: result.reason.clone(),
        };
        match &result.status {
            DnsblStatus::Listed => findings.push(Finding::new(
                FindingCode::MxListed,
                result.address.to_string(),
                listed(),
            )),
            DnsblStatus::QueryBlocked => {
                findings.push(Finding::new(
                    FindingCode::MxDnsblQueryBlocked,
                    result.address.to_string(),
                    listed(),
                ));
            }
            DnsblStatus::Failed(error) => {
                findings.push(lookup_failure("dnsbl", &result.name, error))
            }
            DnsblStatus::NotListed => {}
        }
    }
    findings
}

/// RFC 7672 §2.2: a client uses TLSA only from a secure answer, reached from a
/// secure MX answer.
fn dane_findings(mx: &MxDiscovery, exchange: &str, tlsa: &TlsaSet) -> Vec<Finding> {
    let mut findings = Vec::new();
    match &tlsa.error {
        Some(error) if error.is_absent() => return findings,
        Some(error) => return vec![lookup_failure("mx", &tlsa.name, error)],
        None => {}
    }
    let insecure = |code, status| {
        Finding::new(
            code,
            &tlsa.name,
            Detail::Tlsa {
                exchange: exchange.to_owned(),
                name: tlsa.name.clone(),
                status,
            },
        )
    };
    // Indeterminate means the resolver got no signatures, which
    // dnssec_unsupported_resolver reports; it's no fault of the domain's.
    if tlsa.dnssec == Some(DnssecStatus::Insecure) {
        findings.push(insecure(FindingCode::DaneTlsaInsecure, tlsa.dnssec));
    } else if tlsa.dnssec == Some(DnssecStatus::Secure) && mx.dnssec == Some(DnssecStatus::Insecure)
    {
        findings.push(insecure(FindingCode::DaneMxInsecure, mx.dnssec));
    }
    for (index, record) in tlsa.records.iter().enumerate() {
        findings.extend(record.faults.iter().map(|fault| {
            Finding::new(
                FindingCode::DaneTlsaSyntax,
                &tlsa.name,
                Detail::TlsaFault {
                    name: tlsa.name.clone(),
                    record: index,
                    fault: fault.clone(),
                },
            )
        }));
        if record.usage.is_pkix() {
            findings.push(Finding::new(
                FindingCode::DaneTlsaUsageDiscouraged,
                &tlsa.name,
                Detail::TlsaUsage {
                    name: tlsa.name.clone(),
                    record: index,
                    usage: record.usage,
                },
            ));
        }
    }
    findings
}
