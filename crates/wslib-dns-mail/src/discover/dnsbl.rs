use std::net::{IpAddr, Ipv4Addr};

use wslib_dns::{LookupError, Resolver, reversed_labels};

/// What a DNS blocklist said about an address.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DnsblResult {
    pub address: IpAddr,
    pub zone: String,
    pub name: String,
    pub status: DnsblStatus,
    /// The A records the zone answered with: listing codes when listed, the
    /// zone's refusal codes when blocked.
    pub codes: Vec<Ipv4Addr>,
    /// The zone's TXT explanation, when it answered with codes.
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DnsblStatus {
    Listed,
    /// NXDOMAIN or NODATA: not on this list.
    NotListed,
    /// The zone answered, but not with a listing code: it refused the query,
    /// as Spamhaus does with `127.255.255.252`–`255` for public and cloud
    /// resolvers. Not listed, but not known to be clean either.
    QueryBlocked,
    Failed(LookupError),
}

impl DnsblResult {
    pub fn is_listed(&self) -> bool {
        self.status == DnsblStatus::Listed
    }
}

/// Asks the blocklist `zone` about `address`, by its reversed octets (or
/// nibbles, for IPv6) under the zone.
pub async fn dnsbl(resolver: &impl Resolver, address: IpAddr, zone: &str) -> DnsblResult {
    let zone = wslib_dns::normalise(zone);
    let name = format!("{}.{zone}", reversed_labels(address));
    let (status, codes) = match resolver.a(&name).await {
        Ok(answer) if answer.records.iter().any(is_listing_code) => {
            (DnsblStatus::Listed, answer.records)
        }
        Ok(answer) => (DnsblStatus::QueryBlocked, answer.records),
        Err(error) if error.is_absent() => (DnsblStatus::NotListed, Vec::new()),
        Err(error) => (DnsblStatus::Failed(error), Vec::new()),
    };
    let reason = if codes.is_empty() {
        None
    } else {
        resolver
            .txt(&name)
            .await
            .ok()
            .and_then(|answer| answer.records.first().map(|txt| txt.joined()))
    };
    DnsblResult {
        address,
        zone,
        name,
        status,
        codes,
        reason,
    }
}

/// `127.0.0.2` to `127.0.0.127`, the listing convention of every major list.
fn is_listing_code(code: &Ipv4Addr) -> bool {
    let [a, b, c, d] = code.octets();
    a == 127 && b == 0 && c == 0 && (2..=127).contains(&d)
}
