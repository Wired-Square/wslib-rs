use std::net::IpAddr;

use wslib_dns::{LookupError, Resolver};

use super::{ascii, join_all};
use crate::dane::{DaneRecord, parse_tlsa};

/// A domain's MX records, each inspected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct MxDiscovery {
    pub domain: String,
    /// Why the MX query returned no records.
    pub error: Option<LookupError>,
    /// In order of preference.
    pub hosts: Vec<MxHost>,
    /// The MX answer's DNSSEC status, from a validating resolver. DANE needs
    /// it Secure (RFC 7672 §2.2).
    pub dnssec: Option<wslib_dns::DnssecStatus>,
}

impl MxDiscovery {
    /// RFC 7505: a single MX of preference 0 for `.`, saying the domain
    /// accepts no mail.
    pub fn is_null(&self) -> bool {
        matches!(self.hosts.as_slice(), [host] if host.is_null() && host.preference == 0)
    }

    /// A null MX entry beside other hosts, which RFC 7505 §3 forbids.
    pub fn has_null_with_others(&self) -> bool {
        self.hosts.len() > 1 && self.hosts.iter().any(MxHost::is_null)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct MxHost {
    pub preference: u16,
    pub exchange: String,
    /// The name the exchange is an alias for, from the CNAME chain its
    /// address answer came with: RFC 2181 §10.3 says it must not be one.
    pub cname: Option<String>,
    pub addresses: Vec<IpAddr>,
    /// Why the exchange has no addresses.
    pub address_error: Option<LookupError>,
    /// One per address.
    pub reverse: Vec<ReverseDns>,
    /// `_25._tcp.<exchange>`, looked up only by a validating resolver.
    pub tlsa: Option<TlsaSet>,
}

/// The TLSA records for an MX host's SMTP port.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TlsaSet {
    pub name: String,
    pub records: Vec<DaneRecord>,
    pub dnssec: Option<wslib_dns::DnssecStatus>,
    /// Why the query returned no records.
    pub error: Option<LookupError>,
}

impl MxHost {
    pub fn is_null(&self) -> bool {
        self.exchange == "."
    }

    /// An address where a host name belongs, which RFC 5321 doesn't allow.
    pub fn is_ip_literal(&self) -> bool {
        let exchange = self.exchange.trim_start_matches('[').trim_end_matches(']');
        exchange.parse::<IpAddr>().is_ok()
    }
}

/// An address's PTR names and whether any of them resolves back to it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReverseDns {
    pub address: IpAddr,
    pub names: Vec<String>,
    pub error: Option<LookupError>,
    /// Forward-confirmed reverse DNS: a PTR name has the address.
    pub forward_confirmed: bool,
}

/// The MX records of `domain`, with each exchange's addresses, whether it is
/// an alias, and the reverse DNS of every address, all looked up
/// concurrently.
pub async fn mx(resolver: &impl Resolver, domain: &str) -> MxDiscovery {
    let domain = ascii(domain);
    let (mut records, error, dnssec) = match resolver.mx(&domain).await {
        Ok(answer) => (answer.records, None, answer.dnssec),
        Err(error) => (Vec::new(), Some(error), None),
    };
    records.sort_by(|a, b| {
        a.preference
            .cmp(&b.preference)
            .then_with(|| a.exchange.cmp(&b.exchange))
    });
    let hosts = join_all(
        records
            .into_iter()
            .map(|record| inspect(resolver, record.preference, record.exchange)),
    )
    .await;
    MxDiscovery {
        domain,
        error,
        hosts,
        dnssec,
    }
}

async fn inspect(resolver: &impl Resolver, preference: u16, exchange: String) -> MxHost {
    let mut host = MxHost {
        preference,
        exchange,
        cname: None,
        addresses: Vec::new(),
        address_error: None,
        reverse: Vec::new(),
        tlsa: None,
    };
    if host.is_null() || host.is_ip_literal() {
        return host;
    }
    match resolver.ip(&host.exchange).await {
        Ok(answer) => {
            host.cname = answer.canonical_name;
            host.addresses = answer.records;
        }
        Err(error) => host.address_error = Some(error),
    }
    host.reverse = join_all(
        host.addresses
            .iter()
            .map(|&address| reverse(resolver, address)),
    )
    .await;
    if resolver.validates() {
        host.tlsa = Some(tlsa(resolver, &host.exchange).await);
    }
    host
}

async fn reverse(resolver: &impl Resolver, address: IpAddr) -> ReverseDns {
    let (names, error) = match resolver.ptr(address).await {
        Ok(answer) => (answer.records, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let forward = join_all(names.iter().map(|name| resolver.ip(name))).await;
    let forward_confirmed = forward.iter().any(|lookup| {
        lookup
            .as_ref()
            .is_ok_and(|answer| answer.records.contains(&address))
    });
    ReverseDns {
        address,
        names,
        error,
        forward_confirmed,
    }
}

async fn tlsa(resolver: &impl Resolver, exchange: &str) -> TlsaSet {
    let name = format!("_25._tcp.{exchange}");
    match resolver.tlsa(&name).await {
        Ok(answer) => TlsaSet {
            records: answer.records.iter().map(parse_tlsa).collect(),
            dnssec: answer.dnssec,
            error: None,
            name,
        },
        Err(error) => TlsaSet {
            name,
            records: Vec::new(),
            dnssec: None,
            error: Some(error),
        },
    }
}
