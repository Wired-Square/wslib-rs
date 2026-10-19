//! The netblocks an SPF tree authorises, and where each came from.

use std::net::IpAddr;

use super::tree::{SpfNode, SpfTree, TermOutcome};
use super::{Mechanism, Qualifier, Term};
use crate::address::{PRIVATE_IPV4, PRIVATE_IPV6, host_mask, overlaps, range};

/// Every `ip4`, `ip6`, `a` and `mx` netblock in a tree, with totals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Flattened {
    /// In evaluation order.
    pub netblocks: Vec<Netblock>,
    /// Networks reached by more than one path.
    pub duplicates: Vec<DuplicateNetblock>,
    /// Networks inside another, different one.
    pub overlaps: Vec<Overlap>,
    /// IPv4 addresses `pass` netblocks authorise, each counted once however
    /// many blocks hold it.
    pub total_ipv4_addresses: u64,
    /// Distinct IPv6 networks among the `pass` netblocks.
    pub ipv6_prefix_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Netblock {
    /// The network in canonical form: host bits cleared, prefix always given.
    pub cidr: String,
    /// The path to it: the root domain, then `include:…` (or `redirect=…`)
    /// for each record passed through, and `a:…` or `mx:…` plus the exchange
    /// for a resolved one.
    pub source: Vec<String>,
    pub qualifier: Qualifier,
    /// IPv4 addresses in it; 0 for IPv6.
    pub ip_count: u64,
    pub is_ipv6: bool,
    /// Resolved from an `a` or `mx` rather than written in the record, so it
    /// changes when the DNS does.
    pub dynamic: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DuplicateNetblock {
    pub cidr: String,
    pub occurrences: usize,
    pub sources: Vec<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Overlap {
    pub cidr: String,
    pub source: Vec<String>,
    pub within: String,
    pub within_source: Vec<String>,
}

impl SpfTree {
    pub fn flatten(&self) -> Flattened {
        let mut netblocks = Vec::new();
        collect(
            &self.root,
            &mut vec![self.root.domain.clone()],
            &mut netblocks,
        );
        summarise(netblocks)
    }
}

fn collect(node: &SpfNode, source: &mut Vec<String>, out: &mut Vec<Netblock>) {
    let Some(record) = node.record().map(|parsed| &parsed.record) else {
        return;
    };
    for (index, term) in record.terms.iter().enumerate() {
        let lookup = node.lookups.iter().find(|lookup| lookup.term == index);
        let Term::Directive {
            qualifier,
            mechanism,
        } = &term.term
        else {
            if let (Some(lookup), Term::Redirect(_)) = (lookup, &term.term) {
                descend(lookup, source, out);
            }
            continue;
        };
        let qualifier = *qualifier;
        match (mechanism, lookup.map(|lookup| &lookup.outcome)) {
            (Mechanism::Ip4 { address, prefix }, _) => {
                out.push(block(
                    IpAddr::V4(*address),
                    prefix.unwrap_or(32),
                    qualifier,
                    source.clone(),
                    false,
                ));
            }
            (Mechanism::Ip6 { address, prefix }, _) => {
                out.push(block(
                    IpAddr::V6(*address),
                    prefix.unwrap_or(128),
                    qualifier,
                    source.clone(),
                    false,
                ));
            }
            (Mechanism::A { cidr, .. }, Some(TermOutcome::Addresses(addresses))) => {
                let mut path = source.clone();
                path.push(format!("a:{}", target(lookup, &node.domain)));
                for &address in addresses {
                    out.push(block(
                        address,
                        cidr.prefix_for(address),
                        qualifier,
                        path.clone(),
                        true,
                    ));
                }
            }
            (Mechanism::Mx { cidr, .. }, Some(TermOutcome::Exchanges(exchanges))) => {
                for exchange in exchanges {
                    let mut path = source.clone();
                    path.push(format!("mx:{}", target(lookup, &node.domain)));
                    path.push(exchange.host.clone());
                    for &address in &exchange.addresses {
                        out.push(block(
                            address,
                            cidr.prefix_for(address),
                            qualifier,
                            path.clone(),
                            true,
                        ));
                    }
                }
            }
            (Mechanism::Include(_), Some(_)) => descend(lookup.expect("matched Some"), source, out),
            _ => {}
        }
    }
}

fn target<'a>(lookup: Option<&'a super::tree::TermLookup>, domain: &'a str) -> &'a str {
    lookup
        .and_then(|lookup| lookup.target.as_deref())
        .unwrap_or(domain)
}

fn descend(lookup: &super::tree::TermLookup, source: &mut Vec<String>, out: &mut Vec<Netblock>) {
    if let TermOutcome::Record(child) = &lookup.outcome {
        let step = if lookup.text.to_ascii_lowercase().starts_with("redirect=") {
            format!("redirect={}", child.domain)
        } else {
            format!("include:{}", child.domain)
        };
        source.push(step);
        collect(child, source, out);
        source.pop();
    }
}

impl Netblock {
    /// Whether every address in it is globally routable: none is private,
    /// loopback, link-local, shared, multicast, reserved or for
    /// documentation. Lets a public tool drop netblocks that would map
    /// internal addresses.
    pub fn is_global(&self) -> bool {
        let Some((address, prefix)) = self.cidr.split_once('/') else {
            return false;
        };
        match (address.parse(), prefix.parse()) {
            (Ok(address), Ok(prefix)) => wslib_dns::is_global_network(address, prefix),
            _ => false,
        }
    }

    /// Whether it overlaps private or local space: RFC 1918, shared, loopback
    /// and link-local IPv4, or loopback, unique-local and link-local IPv6.
    pub fn is_private(&self) -> bool {
        overlaps(&self.cidr, PRIVATE_IPV4, PRIVATE_IPV6)
    }
}

fn block(
    address: IpAddr,
    prefix: u8,
    qualifier: Qualifier,
    source: Vec<String>,
    dynamic: bool,
) -> Netblock {
    let (network, is_ipv6) = match address {
        IpAddr::V4(v4) => (
            IpAddr::V4(((u128::from(u32::from(v4)) & !host_mask(32, prefix)) as u32).into()),
            false,
        ),
        IpAddr::V6(v6) => (
            IpAddr::V6((u128::from(v6) & !host_mask(128, prefix)).into()),
            true,
        ),
    };
    Netblock {
        cidr: format!("{network}/{prefix}"),
        source,
        qualifier,
        ip_count: if is_ipv6 { 0 } else { 1u64 << (32 - prefix) },
        is_ipv6,
        dynamic,
    }
}

fn summarise(netblocks: Vec<Netblock>) -> Flattened {
    let mut distinct: Vec<&Netblock> = Vec::new();
    let mut duplicates: Vec<DuplicateNetblock> = Vec::new();
    for netblock in &netblocks {
        match distinct.iter().find(|seen| seen.cidr == netblock.cidr) {
            Some(first) => match duplicates.iter_mut().find(|d| d.cidr == netblock.cidr) {
                Some(duplicate) => {
                    duplicate.occurrences += 1;
                    duplicate.sources.push(netblock.source.clone());
                }
                None => duplicates.push(DuplicateNetblock {
                    cidr: netblock.cidr.clone(),
                    occurrences: 2,
                    sources: vec![first.source.clone(), netblock.source.clone()],
                }),
            },
            None => distinct.push(netblock),
        }
    }

    let ranges: Vec<(&Netblock, (bool, u128, u128))> = distinct
        .iter()
        .filter_map(|netblock| Some((*netblock, range(&netblock.cidr)?)))
        .collect();
    let mut overlaps = Vec::new();
    for (inner, (v6, start, end)) in &ranges {
        if let Some((outer, _)) =
            ranges
                .iter()
                .find(|(outer, (outer_v6, outer_start, outer_end))| {
                    outer.cidr != inner.cidr
                        && outer_v6 == v6
                        && outer_start <= start
                        && end <= outer_end
                })
        {
            overlaps.push(Overlap {
                cidr: inner.cidr.clone(),
                source: inner.source.clone(),
                within: outer.cidr.clone(),
                within_source: outer.source.clone(),
            });
        }
    }

    let mut authorised: Vec<(bool, u128, u128)> = netblocks
        .iter()
        .filter(|netblock| netblock.qualifier == Qualifier::Pass)
        .filter_map(|netblock| range(&netblock.cidr))
        .collect();
    authorised.sort_unstable();
    authorised.dedup();
    let v4: Vec<(u128, u128)> = authorised
        .iter()
        .filter(|(v6, ..)| !v6)
        .map(|(_, s, e)| (*s, *e))
        .collect();
    let mut total_ipv4_addresses = 0u64;
    let mut covered_to: Option<u128> = None;
    for (start, end) in v4 {
        let from = covered_to.map_or(start, |covered| start.max(covered + 1));
        if from <= end {
            total_ipv4_addresses += u64::try_from(end - from + 1).unwrap_or(u64::MAX);
        }
        covered_to = Some(covered_to.map_or(end, |covered| covered.max(end)));
    }
    let ipv6_prefix_count =
        u32::try_from(authorised.iter().filter(|(v6, ..)| *v6).count()).unwrap_or(u32::MAX);

    Flattened {
        netblocks,
        duplicates,
        overlaps,
        total_ipv4_addresses,
        ipv6_prefix_count,
    }
}
