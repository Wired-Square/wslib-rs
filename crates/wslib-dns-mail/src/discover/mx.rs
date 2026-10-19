use std::net::IpAddr;

use wslib_dns::{LookupError, Resolver};

use super::{ascii, join_all};

/// A domain's MX records, each inspected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MxDiscovery {
    pub domain: String,
    /// Why the MX query returned no records.
    pub error: Option<LookupError>,
    /// In order of preference.
    pub hosts: Vec<MxHost>,
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
pub struct MxHost {
    pub preference: u16,
    pub exchange: String,
    /// The exchange's own CNAME target: RFC 2181 §10.3 says it must be
    /// neither an alias nor point at one.
    pub cname: Option<String>,
    pub cname_error: Option<LookupError>,
    pub addresses: Vec<IpAddr>,
    /// Why the exchange has no addresses.
    pub address_error: Option<LookupError>,
    /// One per address.
    pub reverse: Vec<ReverseDns>,
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
    let (mut records, error) = match resolver.mx(&domain).await {
        Ok(answer) => (answer.records, None),
        Err(error) => (Vec::new(), Some(error)),
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
    }
}

async fn inspect(resolver: &impl Resolver, preference: u16, exchange: String) -> MxHost {
    let mut host = MxHost {
        preference,
        exchange,
        cname: None,
        cname_error: None,
        addresses: Vec::new(),
        address_error: None,
        reverse: Vec::new(),
    };
    if host.is_null() || host.is_ip_literal() {
        return host;
    }
    match resolver.cname(&host.exchange).await {
        Ok(answer) => host.cname = answer.records.into_iter().next(),
        Err(error) if error.is_absent() => {}
        Err(error) => host.cname_error = Some(error),
    }
    match resolver.ip(&host.exchange).await {
        Ok(answer) => host.addresses = answer.records,
        Err(error) => host.address_error = Some(error),
    }
    host.reverse = join_all(
        host.addresses
            .iter()
            .map(|&address| reverse(resolver, address)),
    )
    .await;
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
