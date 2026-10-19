use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_resolver::config::{
    CLOUDFLARE, ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
};
use hickory_resolver::lookup::Lookup as HickoryLookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use hickory_resolver::{TokioResolver, system_conf};

use crate::{Answer, Lookup, LookupError, Mx, Resolver, Txt, normalise};

/// A [`Resolver`] over hickory's stub resolver, with its TTL cache.
#[derive(Clone)]
pub struct HickoryResolver {
    inner: TokioResolver,
}

impl std::fmt::Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolver")
            .field("options", self.inner.options())
            .finish_non_exhaustive()
    }
}

/// How long to wait for each server and how many times to ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HickoryOptions {
    pub timeout: Duration,
    pub attempts: usize,
}

/// 2 s and 2 attempts.
impl Default for HickoryOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            attempts: 2,
        }
    }
}

impl HickoryResolver {
    /// The system's resolvers (`/etc/resolv.conf` on Unix, which is how a
    /// Lambda in a VPC reaches the VPC resolver), or Cloudflare when the system
    /// configuration can't be read.
    pub fn from_system(options: HickoryOptions) -> Result<Self, LookupError> {
        let (config, opts) = system_conf::read_system_conf().unwrap_or_else(|_| {
            (
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                ResolverOpts::default(),
            )
        });
        Self::build(config, opts, options)
    }

    /// Exactly these nameservers, over UDP with TCP fallback.
    pub fn from_nameservers(
        nameservers: impl IntoIterator<Item = SocketAddr>,
        options: HickoryOptions,
    ) -> Result<Self, LookupError> {
        let config =
            ResolverConfig::from_name_servers(nameservers.into_iter().map(nameserver).collect());
        Self::build(config, ResolverOpts::default(), options)
    }

    fn build(
        config: ResolverConfig,
        mut opts: ResolverOpts,
        options: HickoryOptions,
    ) -> Result<Self, LookupError> {
        opts.timeout = options.timeout;
        opts.attempts = options.attempts;
        // resolv.conf leaves EDNS0 off unless it says `options edns0`, which caps
        // UDP answers at 512 bytes and sends large TXT sets round again over TCP.
        opts.edns0 = true;
        // hickory 0.26 races queries across servers by default, and in that
        // race the second truncated UDP answer reads as "TCP already tried",
        // failing any answer too big for UDP whenever there are two servers.
        opts.num_concurrent_reqs = 1;
        let inner = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|error| LookupError::Other(error.to_string()))?;
        Ok(Self { inner })
    }

    async fn query<T>(
        &self,
        name: &str,
        record_type: RecordType,
        extract: impl Fn(&RData) -> Option<T>,
    ) -> Lookup<T> {
        // Fully qualified, so resolv.conf search domains are never appended.
        let name = Name::from_ascii(format!("{}.", crate::name::query_name(name)))
            .map_err(|error| LookupError::Other(format!("invalid name: {error}")))?;
        let lookup = self
            .inner
            .lookup(name, record_type)
            .await
            .map_err(classify)?;
        answer(&lookup, extract)
    }
}

fn nameserver(address: SocketAddr) -> NameServerConfig {
    let connections = [ConnectionConfig::udp(), ConnectionConfig::tcp()]
        .into_iter()
        .map(|mut connection| {
            connection.port = address.port();
            connection
        })
        .collect();
    NameServerConfig::new(address.ip(), true, connections)
}

fn answer<T>(lookup: &HickoryLookup, extract: impl Fn(&RData) -> Option<T>) -> Lookup<T> {
    let mut ttl = None::<u32>;
    let records: Vec<T> = lookup
        .answers()
        .iter()
        .filter_map(|record| {
            let value = extract(&record.data)?;
            ttl = Some(ttl.map_or(record.ttl, |t| t.min(record.ttl)));
            Some(value)
        })
        .collect();
    if records.is_empty() {
        // An answer section holding only a CNAME whose target doesn't exist
        // comes back as a success, with NXDOMAIN in the header.
        return Err(match lookup.message().metadata.response_code {
            ResponseCode::NXDomain => LookupError::NxDomain,
            _ => LookupError::NoData,
        });
    }
    Ok(Answer { records, ttl })
}

fn classify(error: NetError) -> LookupError {
    match error {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords { response_code, .. })) => {
            match response_code {
                ResponseCode::NXDomain => LookupError::NxDomain,
                ResponseCode::NoError => LookupError::NoData,
                code => response_code_error(code),
            }
        }
        NetError::Dns(DnsError::ResponseCode(code)) => response_code_error(code),
        NetError::Timeout => LookupError::Timeout,
        other => LookupError::Other(other.to_string()),
    }
}

fn response_code_error(code: ResponseCode) -> LookupError {
    match code {
        ResponseCode::ServFail => LookupError::ServFail,
        ResponseCode::Refused => LookupError::Refused,
        ResponseCode::NXDomain => LookupError::NxDomain,
        code => LookupError::Other(format!("response code {code}")),
    }
}

fn name(name: &Name) -> String {
    normalise(&name.to_ascii())
}

impl Resolver for HickoryResolver {
    async fn txt(&self, name: &str) -> Lookup<Txt> {
        self.query(name, RecordType::TXT, |data| match data {
            RData::TXT(txt) => Some(Txt::new(txt.txt_data.iter().map(|s| s.to_vec()).collect())),
            _ => None,
        })
        .await
    }

    async fn a(&self, name: &str) -> Lookup<Ipv4Addr> {
        self.query(name, RecordType::A, |data| match data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .await
    }

    async fn aaaa(&self, name: &str) -> Lookup<Ipv6Addr> {
        self.query(name, RecordType::AAAA, |data| match data {
            RData::AAAA(aaaa) => Some(aaaa.0),
            _ => None,
        })
        .await
    }

    async fn mx(&self, name: &str) -> Lookup<Mx> {
        self.query(name, RecordType::MX, |data| match data {
            RData::MX(mx) => Some(Mx {
                preference: mx.preference,
                exchange: self::name(&mx.exchange),
            }),
            _ => None,
        })
        .await
    }

    async fn ns(&self, name: &str) -> Lookup<String> {
        self.query(name, RecordType::NS, |data| match data {
            RData::NS(ns) => Some(self::name(&ns.0)),
            _ => None,
        })
        .await
    }

    async fn cname(&self, name: &str) -> Lookup<String> {
        self.query(name, RecordType::CNAME, |data| match data {
            RData::CNAME(cname) => Some(self::name(&cname.0)),
            _ => None,
        })
        .await
    }

    async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
        self.query(
            &crate::reverse_name(ip),
            RecordType::PTR,
            |data| match data {
                RData::PTR(ptr) => Some(self::name(&ptr.0)),
                _ => None,
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::Query;

    fn no_records(code: ResponseCode) -> NetError {
        NoRecords::new(Query::default(), code).into()
    }

    #[test]
    fn negative_answers_keep_nxdomain_and_nodata_apart() {
        assert_eq!(
            classify(no_records(ResponseCode::NXDomain)),
            LookupError::NxDomain
        );
        assert_eq!(
            classify(no_records(ResponseCode::NoError)),
            LookupError::NoData
        );
        assert_eq!(
            classify(no_records(ResponseCode::ServFail)),
            LookupError::ServFail
        );
    }

    #[test]
    fn failure_codes_map_one_to_one() {
        let code = |c| NetError::Dns(DnsError::ResponseCode(c));
        assert_eq!(
            classify(code(ResponseCode::ServFail)),
            LookupError::ServFail
        );
        assert_eq!(classify(code(ResponseCode::Refused)), LookupError::Refused);
        assert_eq!(classify(NetError::Timeout), LookupError::Timeout);
        assert!(matches!(
            classify(code(ResponseCode::FormErr)),
            LookupError::Other(_)
        ));
        assert!(matches!(
            classify(NetError::NoConnections),
            LookupError::Other(_)
        ));
    }
}
