use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use hickory_resolver::proto::op::{Edns, Message, MessageType, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::hickory::{collect, extract, fully_qualified};
use crate::{Answer, DEFAULT_MAX_CNAME_HOPS, Lookup, LookupError, Mx, Resolver, Tlsa, Txt};

/// A [`Resolver`] that asks each zone's own authoritative servers, walking down
/// from the root, so no resolver's cache can hand back a stale answer or
/// NXDOMAIN. It caches delegations only, never answers or their absence, and
/// clones share that cache.
#[derive(Clone)]
pub struct AuthoritativeResolver {
    walker: Arc<Walker<Network>>,
}

impl fmt::Debug for AuthoritativeResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthoritativeResolver")
            .field("options", &self.walker.options)
            .finish_non_exhaustive()
    }
}

/// How long to wait for each server, how many passes to make over a zone's
/// servers, and how many queries one lookup may send in all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthoritativeOptions {
    pub timeout: Duration,
    pub attempts: usize,
    pub max_queries: usize,
}

/// 2 s, 2 attempts and 64 queries.
impl Default for AuthoritativeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            attempts: 2,
            max_queries: 64,
        }
    }
}

impl AuthoritativeResolver {
    pub fn new(options: AuthoritativeOptions) -> Self {
        let network = Network {
            port: 53,
            timeout: options.timeout,
        };
        Self {
            walker: Arc::new(Walker::new(network, root_hints(), options)),
        }
    }

    /// The NS set the parent zone publishes for `name`, asked of the parent's
    /// servers.
    pub async fn delegation(&self, name: &str) -> Lookup<String> {
        self.walker.delegation(&fully_qualified(name)?).await
    }

    async fn query<T>(
        &self,
        name: &str,
        record_type: RecordType,
        extract: impl Fn(&RData) -> Option<T>,
    ) -> Lookup<T> {
        self.walker
            .lookup(&fully_qualified(name)?, record_type, extract)
            .await
    }
}

impl Resolver for AuthoritativeResolver {
    async fn txt(&self, name: &str) -> Lookup<Txt> {
        self.query(name, RecordType::TXT, extract::txt).await
    }

    async fn a(&self, name: &str) -> Lookup<Ipv4Addr> {
        self.query(name, RecordType::A, extract::a).await
    }

    async fn aaaa(&self, name: &str) -> Lookup<Ipv6Addr> {
        self.query(name, RecordType::AAAA, extract::aaaa).await
    }

    async fn mx(&self, name: &str) -> Lookup<Mx> {
        self.query(name, RecordType::MX, extract::mx).await
    }

    async fn ns(&self, name: &str) -> Lookup<String> {
        self.query(name, RecordType::NS, extract::ns).await
    }

    async fn cname(&self, name: &str) -> Lookup<String> {
        self.query(name, RecordType::CNAME, extract::cname).await
    }

    async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
        self.query(&crate::reverse_name(ip), RecordType::PTR, extract::ptr)
            .await
    }

    #[cfg(feature = "__dnssec")]
    async fn ds(&self, name: &str) -> Lookup<crate::Ds> {
        self.query(name, RecordType::DS, extract::ds).await
    }

    async fn tlsa(&self, name: &str) -> Lookup<Tlsa> {
        self.query(name, RecordType::TLSA, extract::tlsa).await
    }
}

const MAX_NAMESERVER_DEPTH: usize = 4;

/// DNS Flag Day 2020's EDNS buffer size, which avoids IP fragmentation.
const EDNS_PAYLOAD: u16 = 1232;

trait Transport: Send + Sync {
    fn exchange(
        &self,
        server: IpAddr,
        query: &Message,
    ) -> impl Future<Output = Result<Message, LookupError>> + Send;
}

struct Walker<T> {
    transport: T,
    roots: Delegation,
    options: AuthoritativeOptions,
    cache: Mutex<HashMap<Name, (Delegation, Instant)>>,
}

#[derive(Clone, Debug)]
struct Delegation {
    zone: Name,
    nameservers: Vec<Nameserver>,
    ttl: u32,
}

#[derive(Clone, Debug)]
struct Nameserver {
    name: Name,
    /// `None` until looked up when the referral carried no glue.
    addresses: Option<Vec<IpAddr>>,
}

enum Step {
    Answer(Message),
    Referral(Delegation),
}

struct Call {
    queries_left: usize,
    depth: usize,
}

struct Found {
    records: Vec<Record>,
    canonical_name: Option<Name>,
}

impl<T: Transport> Walker<T> {
    fn new(transport: T, roots: Delegation, options: AuthoritativeOptions) -> Self {
        Self {
            transport,
            roots,
            options,
            cache: Mutex::default(),
        }
    }

    fn call(&self) -> Call {
        Call {
            queries_left: self.options.max_queries,
            depth: 0,
        }
    }

    async fn lookup<V>(
        &self,
        name: &Name,
        record_type: RecordType,
        extract: impl Fn(&RData) -> Option<V>,
    ) -> Lookup<V> {
        let found = self.records(name, record_type, &mut self.call()).await?;
        let (records, ttl) = collect(&found.records, extract);
        if records.is_empty() {
            return Err(LookupError::NoData);
        }
        Ok(Answer {
            records,
            ttl,
            canonical_name: found.canonical_name.as_ref().map(crate::hickory::name),
            dnssec: None,
        })
    }

    async fn delegation(&self, name: &Name) -> Lookup<String> {
        if name.is_root() {
            return Err(LookupError::Other("the root zone has no parent".into()));
        }
        match self
            .walk(name, RecordType::NS, true, &mut self.call())
            .await?
        {
            Step::Referral(cut) => Ok(Answer {
                records: cut
                    .nameservers
                    .iter()
                    .map(|nameserver| crate::hickory::name(&nameserver.name))
                    .collect(),
                ttl: Some(cut.ttl),
                canonical_name: None,
                dnssec: None,
            }),
            Step::Answer(message) => {
                let (records, ttl) =
                    collect(&records_at(&message, name, RecordType::NS), extract::ns);
                if records.is_empty() {
                    return Err(absence(&message));
                }
                Ok(Answer {
                    records,
                    ttl,
                    canonical_name: None,
                    dnssec: None,
                })
            }
        }
    }

    /// The records of `record_type` at `name`, following CNAMEs, from the
    /// authoritative servers of each zone on the way.
    async fn records(
        &self,
        name: &Name,
        record_type: RecordType,
        call: &mut Call,
    ) -> Result<Found, LookupError> {
        let parent_side = record_type == RecordType::DS;
        let mut current = name.clone();
        let mut hops = 0;
        loop {
            let asked = current.clone();
            let message = match self.walk(&asked, record_type, parent_side, call).await? {
                Step::Answer(message) => message,
                Step::Referral(_) => {
                    return Err(LookupError::Other(format!(
                        "the parent of {asked} referred its DS query to the child"
                    )));
                }
            };
            loop {
                let records = records_at(&message, &current, record_type);
                if !records.is_empty() {
                    let canonical_name = (current != *name).then_some(current);
                    return Ok(Found {
                        records,
                        canonical_name,
                    });
                }
                let Some(target) = cname_target(&message, &current, record_type) else {
                    break;
                };
                hops += 1;
                if hops > DEFAULT_MAX_CNAME_HOPS {
                    return Err(LookupError::Other(format!(
                        "more than {DEFAULT_MAX_CNAME_HOPS} CNAMEs from {name}"
                    )));
                }
                current = target;
            }
            if current == asked {
                return Err(absence(&message));
            }
        }
    }

    /// Follows referrals down from the closest known delegation to the
    /// authoritative answer. With `parent_side`, starts strictly above `name`
    /// and stops at the referral to `name` itself.
    async fn walk(
        &self,
        name: &Name,
        record_type: RecordType,
        parent_side: bool,
        call: &mut Call,
    ) -> Result<Step, LookupError> {
        let query = Query::query(name.clone(), record_type);
        let mut zone = self.closest_delegation(name, parent_side);
        loop {
            let step = self.ask(&zone, &query, call).await;
            match step {
                Ok(Step::Referral(cut)) => {
                    self.remember(&cut);
                    if parent_side && cut.zone == *name {
                        return Ok(Step::Referral(cut));
                    }
                    zone = cut;
                }
                Ok(answer) => return Ok(answer),
                Err(error) => {
                    self.cache().remove(&zone.zone);
                    return Err(error);
                }
            }
        }
    }

    /// Asks the zone's servers in turn until one answers authoritatively or
    /// refers further down.
    async fn ask(
        &self,
        zone: &Delegation,
        query: &Query,
        call: &mut Call,
    ) -> Result<Step, LookupError> {
        let mut nameservers = zone.nameservers.clone();
        nameservers.sort_by_key(|nameserver| nameserver.addresses.is_none());
        let mut failures = Failures::default();
        for _ in 0..self.options.attempts {
            for nameserver in &mut nameservers {
                if nameserver.addresses.is_none() {
                    let addresses = self.addresses_of(&nameserver.name, &zone.zone, call).await;
                    nameserver.addresses = Some(addresses);
                }
                for server in preferred(nameserver.addresses.as_deref().unwrap_or_default()) {
                    if call.queries_left == 0 {
                        return Err(self.out_of_budget());
                    }
                    call.queries_left -= 1;
                    let response = self.transport.exchange(server, &message(query)).await;
                    match response.and_then(|response| step(response, &zone.zone, query.name())) {
                        Ok(step) => return Ok(step),
                        Err(error) => failures.note(error),
                    }
                }
            }
        }
        if call.queries_left == 0 {
            return Err(self.out_of_budget());
        }
        Err(failures.into_error(&zone.zone))
    }

    /// A glueless nameserver's addresses: A, or AAAA when it has none.
    fn addresses_of<'a>(
        &'a self,
        nameserver: &'a Name,
        zone: &'a Name,
        call: &'a mut Call,
    ) -> Pin<Box<dyn Future<Output = Vec<IpAddr>> + Send + 'a>> {
        Box::pin(async move {
            // A name inside the zone it serves can only be found through
            // that zone's servers.
            if zone.zone_of(nameserver) || call.depth == MAX_NAMESERVER_DEPTH {
                return Vec::new();
            }
            call.depth += 1;
            let mut addresses = Vec::new();
            for record_type in [RecordType::A, RecordType::AAAA] {
                if let Ok(found) = self.records(nameserver, record_type, call).await {
                    addresses.extend(found.records.iter().filter_map(|r| r.data.ip_addr()));
                }
                if !addresses.is_empty() {
                    break;
                }
            }
            call.depth -= 1;
            addresses
        })
    }

    fn out_of_budget(&self) -> LookupError {
        LookupError::Other(format!(
            "gave up after {} queries",
            self.options.max_queries
        ))
    }

    fn cache(&self) -> MutexGuard<'_, HashMap<Name, (Delegation, Instant)>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn closest_delegation(&self, name: &Name, strictly_above: bool) -> Delegation {
        let cache = self.cache();
        let now = Instant::now();
        let mut zone = if strictly_above {
            name.base_name()
        } else {
            name.clone()
        };
        while !zone.is_root() {
            if let Some((delegation, expiry)) = cache.get(&zone)
                && *expiry > now
            {
                return delegation.clone();
            }
            zone = zone.base_name();
        }
        self.roots.clone()
    }

    fn remember(&self, delegation: &Delegation) {
        let now = Instant::now();
        let mut cache = self.cache();
        cache.retain(|_, (_, expiry)| *expiry > now);
        let expiry = now + Duration::from_secs(delegation.ttl.into());
        cache.insert(delegation.zone.clone(), (delegation.clone(), expiry));
    }
}

#[derive(Default)]
struct Failures {
    tried: bool,
    dns: Option<LookupError>,
    other: Option<LookupError>,
}

impl Failures {
    fn note(&mut self, error: LookupError) {
        self.tried = true;
        match error {
            LookupError::Timeout => {}
            LookupError::ServFail | LookupError::Refused => self.dns = Some(error),
            error => self.other = Some(error),
        }
    }

    fn into_error(self, zone: &Name) -> LookupError {
        if !self.tried {
            return LookupError::Other(format!("found no address for any nameserver of {zone}"));
        }
        self.dns.or(self.other).unwrap_or(LookupError::Timeout)
    }
}

fn message(query: &Query) -> Message {
    let mut message = Message::query();
    message.add_query(query.clone());
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    message.set_edns(edns);
    message
}

/// What a response from one of `zone`'s servers means for a query about
/// `name`; an error sends the walk on to the next server.
fn step(response: Message, zone: &Name, name: &Name) -> Result<Step, LookupError> {
    let metadata = response.metadata;
    match metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain if metadata.authoritative => {
            Ok(Step::Answer(response))
        }
        ResponseCode::NoError => referral(&response, zone, name)
            .map(Step::Referral)
            .ok_or_else(|| {
                LookupError::Other(format!(
                    "a server for {zone} gave neither an authoritative answer nor a referral for {name}"
                ))
            }),
        ResponseCode::ServFail => Err(LookupError::ServFail),
        ResponseCode::Refused => Err(LookupError::Refused),
        code => Err(LookupError::Other(format!(
            "a server for {zone} answered {code} for {name}"
        ))),
    }
}

/// A referral to a zone strictly below `zone` that holds `name`, with the
/// glue `zone`'s servers may vouch for.
fn referral(response: &Message, zone: &Name, name: &Name) -> Option<Delegation> {
    if !response.answers.is_empty() {
        return None;
    }
    let cut = &response
        .authorities
        .iter()
        .find(|record| record.record_type() == RecordType::NS)?
        .name;
    if cut == zone || !zone.zone_of(cut) || !cut.zone_of(name) {
        return None;
    }
    let mut ttl = u32::MAX;
    let nameservers = response
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::NS(ns) if record.name == *cut => {
                ttl = ttl.min(record.ttl);
                Some(ns.0.clone())
            }
            _ => None,
        })
        .map(|name| Nameserver {
            addresses: glue(response, zone, &name),
            name,
        })
        .collect();
    Some(Delegation {
        zone: cut.clone(),
        nameservers,
        ttl,
    })
}

fn glue(response: &Message, zone: &Name, nameserver: &Name) -> Option<Vec<IpAddr>> {
    if !zone.zone_of(nameserver) {
        return None;
    }
    let addresses: Vec<IpAddr> = response
        .additionals
        .iter()
        .filter(|record| record.name == *nameserver)
        .filter_map(|record| record.data.ip_addr())
        .collect();
    (!addresses.is_empty()).then_some(addresses)
}

fn records_at(message: &Message, name: &Name, record_type: RecordType) -> Vec<Record> {
    message
        .answers
        .iter()
        .filter(|record| record.name == *name && record.record_type() == record_type)
        .cloned()
        .collect()
}

fn cname_target(message: &Message, name: &Name, record_type: RecordType) -> Option<Name> {
    if record_type == RecordType::CNAME {
        return None;
    }
    message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::CNAME(target) if record.name == *name => Some(target.0.clone()),
            _ => None,
        })
}

fn absence(message: &Message) -> LookupError {
    match message.metadata.response_code {
        ResponseCode::NXDomain => LookupError::NxDomain,
        _ => LookupError::NoData,
    }
}

/// IPv4 addresses, or IPv6 when there are none.
fn preferred(addresses: &[IpAddr]) -> impl Iterator<Item = IpAddr> + '_ {
    let has_ipv4 = addresses.iter().any(IpAddr::is_ipv4);
    addresses
        .iter()
        .copied()
        .filter(move |address| address.is_ipv4() == has_ipv4)
}

/// The root servers' addresses, from IANA's root hints file (`named.root`).
fn root_hints() -> Delegation {
    const ROOT_SERVERS: [(char, &str, &str); 13] = [
        ('a', "198.41.0.4", "2001:503:ba3e::2:30"),
        ('b', "170.247.170.2", "2801:1b8:10::b"),
        ('c', "192.33.4.12", "2001:500:2::c"),
        ('d', "199.7.91.13", "2001:500:2d::d"),
        ('e', "192.203.230.10", "2001:500:a8::e"),
        ('f', "192.5.5.241", "2001:500:2f::f"),
        ('g', "192.112.36.4", "2001:500:12::d0d"),
        ('h', "198.97.190.53", "2001:500:1::53"),
        ('i', "192.36.148.17", "2001:7fe::53"),
        ('j', "192.58.128.30", "2001:503:c27::2:30"),
        ('k', "193.0.14.129", "2001:7fd::1"),
        ('l', "199.7.83.42", "2001:500:9f::42"),
        ('m', "202.12.27.33", "2001:dc3::35"),
    ];
    Delegation {
        zone: Name::root(),
        nameservers: ROOT_SERVERS
            .iter()
            .map(|&(letter, ipv4, ipv6)| Nameserver {
                name: Name::from_ascii(format!("{letter}.root-servers.net."))
                    .expect("a root server's name is valid"),
                addresses: Some(
                    [ipv4, ipv6]
                        .map(|address| address.parse().expect("a root address is valid"))
                        .to_vec(),
                ),
            })
            .collect(),
        ttl: 0,
    }
}

/// UDP with EDNS, and TCP when the UDP answer comes back truncated.
struct Network {
    port: u16,
    timeout: Duration,
}

impl Transport for Network {
    async fn exchange(&self, server: IpAddr, query: &Message) -> Result<Message, LookupError> {
        let server = SocketAddr::new(server, self.port);
        let bytes = query
            .to_vec()
            .map_err(|error| LookupError::Other(error.to_string()))?;
        let response = within(self.timeout, over_udp(server, &bytes, query)).await?;
        if !response.metadata.truncation {
            return Ok(response);
        }
        within(self.timeout, over_tcp(server, &bytes, query)).await
    }
}

async fn within<T>(
    timeout: Duration,
    exchange: impl Future<Output = Result<T, LookupError>>,
) -> Result<T, LookupError> {
    tokio::time::timeout(timeout, exchange)
        .await
        .unwrap_or(Err(LookupError::Timeout))
}

async fn over_udp(
    server: SocketAddr,
    bytes: &[u8],
    query: &Message,
) -> Result<Message, LookupError> {
    let unspecified = match server {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind((unspecified, 0))
        .await
        .map_err(io(server))?;
    // Connected, so the kernel drops datagrams from any other address.
    socket.connect(server).await.map_err(io(server))?;
    socket.send(bytes).await.map_err(io(server))?;
    let mut buffer = [0; 4096];
    loop {
        let len = socket.recv(&mut buffer).await.map_err(io(server))?;
        if let Ok(response) = Message::from_vec(&buffer[..len])
            && answers(query, &response)
        {
            return Ok(response);
        }
    }
}

async fn over_tcp(
    server: SocketAddr,
    bytes: &[u8],
    query: &Message,
) -> Result<Message, LookupError> {
    let mut stream = TcpStream::connect(server).await.map_err(io(server))?;
    let length = u16::try_from(bytes.len()).expect("a single-question query fits in 64 KiB");
    stream
        .write_all(&[&length.to_be_bytes()[..], bytes].concat())
        .await
        .map_err(io(server))?;
    let length = stream.read_u16().await.map_err(io(server))?;
    let mut buffer = vec![0; length.into()];
    stream.read_exact(&mut buffer).await.map_err(io(server))?;
    let response = Message::from_vec(&buffer)
        .map_err(|error| LookupError::Other(format!("{server}: {error}")))?;
    if !answers(query, &response) {
        return Err(LookupError::Other(format!(
            "{server}: the answer over TCP is for another query"
        )));
    }
    Ok(response)
}

fn answers(query: &Message, response: &Message) -> bool {
    response.metadata.id == query.metadata.id
        && response.metadata.message_type == MessageType::Response
        && response.queries == query.queries
}

fn io(server: SocketAddr) -> impl Fn(std::io::Error) -> LookupError {
    move |error| LookupError::Other(format!("{server}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::OpCode;
    use hickory_resolver::proto::rr::rdata::{A, CNAME, NS, TXT};

    fn name(name: &str) -> Name {
        fully_qualified(name).unwrap()
    }

    fn ns(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 3600, RData::NS(NS(name(target))))
    }

    fn a(owner: &str, address: [u8; 4]) -> Record {
        Record::from_rdata(name(owner), 300, RData::A(A(address.into())))
    }

    fn txt(owner: &str, text: &str) -> Record {
        Record::from_rdata(name(owner), 60, RData::TXT(TXT::new(vec![text.into()])))
    }

    fn cname(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
    }

    struct Zone {
        origin: Name,
        records: Vec<Record>,
    }

    fn zone(origin: &str, records: Vec<Record>) -> Zone {
        Zone {
            origin: name(origin),
            records,
        }
    }

    /// A server missing from [`FakeNet`] never answers.
    enum Server {
        Zones(Vec<Zone>),
        /// Answers every query with this code, without AA or records.
        Code(ResponseCode),
        /// Refers every query to this zone.
        Refers(&'static str),
    }

    #[derive(Default)]
    struct FakeNet {
        servers: HashMap<IpAddr, Server>,
        asked: Mutex<Vec<IpAddr>>,
    }

    impl FakeNet {
        fn with(mut self, address: [u8; 4], server: Server) -> Self {
            self.servers.insert(address.into(), server);
            self
        }
    }

    impl Transport for FakeNet {
        async fn exchange(&self, server: IpAddr, query: &Message) -> Result<Message, LookupError> {
            assert!(!query.metadata.recursion_desired);
            assert_eq!(query.max_payload(), EDNS_PAYLOAD);
            self.asked.lock().unwrap().push(server);
            let question = query.queries[0].clone();
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.add_query(question.clone());
            match self.servers.get(&server) {
                None => return Err(LookupError::Timeout),
                Some(Server::Code(code)) => response.metadata.response_code = *code,
                Some(Server::Refers(cut)) => {
                    response.add_authority(ns(cut, &format!("ns.{cut}")));
                }
                Some(Server::Zones(zones)) => serve(zones, &question, &mut response),
            }
            Ok(response)
        }
    }

    /// Answers as an authoritative server for the deepest of `zones` holding
    /// the name; DS is answered on the parent side of a cut.
    fn serve(zones: &[Zone], question: &Query, response: &mut Message) {
        let (qname, qtype) = (question.name(), question.query_type());
        let parent_side = |owner: &Name| qtype == RecordType::DS && owner == qname;
        let Some(zone) = zones
            .iter()
            .filter(|zone| zone.origin.zone_of(qname) && !parent_side(&zone.origin))
            .max_by_key(|zone| zone.origin.num_labels())
        else {
            response.metadata.response_code = ResponseCode::Refused;
            return;
        };
        let cut = zone.records.iter().find(|record| {
            record.record_type() == RecordType::NS
                && record.name != zone.origin
                && record.name.zone_of(qname)
                && !parent_side(&record.name)
        });
        if let Some(cut) = cut {
            for record in zone.records.iter().filter(|r| r.name == cut.name) {
                let RData::NS(target) = &record.data else {
                    continue;
                };
                response.add_authority(record.clone());
                response.add_additionals(
                    zone.records
                        .iter()
                        .filter(|r| r.name == target.0 && r.data.ip_addr().is_some())
                        .cloned(),
                );
            }
            return;
        }
        response.metadata.authoritative = true;
        let mut current = qname.clone();
        for _ in 0..10 {
            let at = |record_type| {
                zone.records
                    .iter()
                    .filter(|r| r.name == current && r.record_type() == record_type)
                    .cloned()
                    .collect::<Vec<_>>()
            };
            let matching = at(qtype);
            if !matching.is_empty() {
                response.add_answers(matching);
                return;
            }
            let Some(alias) = at(RecordType::CNAME)
                .pop()
                .filter(|_| qtype != RecordType::CNAME)
            else {
                break;
            };
            let RData::CNAME(target) = &alias.data else {
                unreachable!()
            };
            current = target.0.clone();
            response.add_answer(alias);
            if !zone.origin.zone_of(&current) {
                return;
            }
        }
        if !zone.records.iter().any(|r| current.zone_of(&r.name)) {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
    }

    const ROOT: [u8; 4] = [10, 0, 0, 1];
    const COM: [u8; 4] = [10, 0, 1, 1];
    const NET: [u8; 4] = [10, 0, 1, 2];
    const EXAMPLE: [u8; 4] = [10, 0, 2, 1];
    const EXAMPLE_NET: [u8; 4] = [10, 0, 3, 1];
    const BROKEN: [[u8; 4]; 4] = [[10, 0, 5, 1], [10, 0, 5, 2], [10, 0, 5, 3], [10, 0, 5, 4]];

    fn internet() -> FakeNet {
        use Server::Zones;
        FakeNet::default()
            .with(
                ROOT,
                Zones(vec![zone(
                    ".",
                    vec![
                        ns("com", "ns.com"),
                        a("ns.com", COM),
                        ns("net", "ns.net"),
                        a("ns.net", NET),
                    ],
                )]),
            )
            .with(
                COM,
                Zones(vec![zone(
                    "com",
                    vec![
                        ns("example.com", "ns1.example.com"),
                        a("ns1.example.com", EXAMPLE),
                        ns("glueless.com", "ns.example.net"),
                        a("ns.example.net", [10, 9, 9, 9]),
                        ns("loop.com", "ns.loop.net"),
                        ns("self.com", "ns.self.com"),
                        ns("broken.com", "ns1.broken.com"),
                        ns("broken.com", "ns2.broken.com"),
                        ns("broken.com", "ns3.broken.com"),
                        ns("broken.com", "ns4.broken.com"),
                        a("ns1.broken.com", BROKEN[0]),
                        a("ns2.broken.com", BROKEN[1]),
                        a("ns3.broken.com", BROKEN[2]),
                        a("ns4.broken.com", BROKEN[3]),
                    ],
                )]),
            )
            .with(
                NET,
                Zones(vec![zone(
                    "net",
                    vec![
                        ns("example.net", "ns.example.net"),
                        a("ns.example.net", EXAMPLE_NET),
                        ns("loop.net", "ns.loop.com"),
                    ],
                )]),
            )
            .with(
                EXAMPLE,
                Zones(vec![
                    zone(
                        "example.com",
                        vec![
                            ns("example.com", "ns1.example.com"),
                            ns("example.com", "ns2.example.com"),
                            a("ns1.example.com", EXAMPLE),
                            txt("example.com", "v=spf1 -all"),
                            cname("www.example.com", "host.example.net"),
                            cname("dangling.example.com", "gone.example.net"),
                            cname("loop1.example.com", "loop2.example.com"),
                            cname("loop2.example.com", "loop1.example.com"),
                            ns("sub.example.com", "ns1.example.com"),
                        ],
                    ),
                    zone(
                        "sub.example.com",
                        vec![
                            ns("sub.example.com", "ns1.example.com"),
                            ns("sub.example.com", "ns3.example.com"),
                        ],
                    ),
                ]),
            )
            .with(
                EXAMPLE_NET,
                Zones(vec![
                    zone(
                        "example.net",
                        vec![
                            ns("example.net", "ns.example.net"),
                            a("ns.example.net", EXAMPLE_NET),
                            a("host.example.net", [192, 0, 2, 7]),
                        ],
                    ),
                    zone(
                        "glueless.com",
                        vec![
                            ns("glueless.com", "ns.example.net"),
                            txt("glueless.com", "hello"),
                        ],
                    ),
                ]),
            )
    }

    fn walker_with(net: FakeNet, options: AuthoritativeOptions) -> Walker<FakeNet> {
        let root = Nameserver {
            name: name("a.root-servers.net"),
            addresses: Some(vec![ROOT.into()]),
        };
        let roots = Delegation {
            zone: Name::root(),
            nameservers: vec![root],
            ttl: 0,
        };
        Walker::new(net, roots, options)
    }

    fn walker(net: FakeNet) -> Walker<FakeNet> {
        walker_with(net, AuthoritativeOptions::default())
    }

    fn asked(walker: &Walker<FakeNet>) -> Vec<IpAddr> {
        std::mem::take(&mut walker.transport.asked.lock().unwrap())
    }

    async fn txt_of(walker: &Walker<FakeNet>, owner: &str) -> Lookup<String> {
        let answer = walker
            .lookup(&name(owner), RecordType::TXT, extract::txt)
            .await?;
        Ok(answer.map(|txt| txt.joined()))
    }

    async fn broken(servers: Vec<([u8; 4], Server)>) -> (Lookup<String>, usize) {
        let net = servers
            .into_iter()
            .fold(internet(), |net, (address, server)| {
                net.with(address, server)
            });
        let walker = walker(net);
        let answer = txt_of(&walker, "broken.com").await;
        (answer, asked(&walker).len())
    }

    #[tokio::test]
    async fn walks_down_from_the_root_then_starts_at_the_cached_delegation() {
        let walker = walker(internet());
        let answer = walker
            .lookup(&name("example.com"), RecordType::TXT, extract::txt)
            .await
            .unwrap();
        assert_eq!(answer.records, [Txt::from("v=spf1 -all")]);
        assert_eq!(answer.ttl, Some(60));
        assert_eq!(answer.dnssec, None);
        assert_eq!(asked(&walker), [ROOT, COM, EXAMPLE].map(IpAddr::from));
        txt_of(&walker, "example.com").await.unwrap();
        assert_eq!(asked(&walker), [IpAddr::from(EXAMPLE)]);
    }

    #[tokio::test]
    async fn absence_is_asked_afresh_every_time() {
        let walker = walker(internet());
        txt_of(&walker, "example.com").await.unwrap();
        asked(&walker);
        for _ in 0..2 {
            assert_eq!(
                txt_of(&walker, "nothing.example.com").await,
                Err(LookupError::NxDomain)
            );
            let a = walker
                .lookup(&name("example.com"), RecordType::A, extract::a)
                .await;
            assert_eq!(a, Err(LookupError::NoData));
        }
        assert_eq!(asked(&walker), [IpAddr::from(EXAMPLE); 4]);
    }

    #[tokio::test]
    async fn glueless_nameservers_are_looked_up_and_foreign_glue_ignored() {
        let walker = walker(internet());
        assert_eq!(
            txt_of(&walker, "glueless.com").await.unwrap().records,
            ["hello"]
        );
        assert!(!asked(&walker).contains(&IpAddr::from([10, 9, 9, 9])));
    }

    #[tokio::test]
    async fn cnames_are_followed_into_other_zones() {
        let walker = walker(internet());
        let answer = walker
            .lookup(&name("www.example.com"), RecordType::A, extract::a)
            .await
            .unwrap();
        assert_eq!(answer.records, [Ipv4Addr::new(192, 0, 2, 7)]);
        assert_eq!(answer.canonical_name.as_deref(), Some("host.example.net"));

        let hop = walker
            .lookup(&name("www.example.com"), RecordType::CNAME, extract::cname)
            .await
            .unwrap();
        assert_eq!(hop.records, ["host.example.net"]);
        assert_eq!(hop.canonical_name, None);

        assert_eq!(
            txt_of(&walker, "dangling.example.com").await,
            Err(LookupError::NxDomain)
        );
        assert!(matches!(
            txt_of(&walker, "loop1.example.com").await,
            Err(LookupError::Other(_))
        ));
    }

    #[tokio::test]
    async fn failing_servers_are_passed_over() {
        let fine = zone("broken.com", vec![txt("broken.com", "fine")]);
        let (answer, _) = broken(vec![
            (BROKEN[1], Server::Code(ResponseCode::Refused)),
            (BROKEN[2], Server::Code(ResponseCode::NoError)),
            (BROKEN[3], Server::Zones(vec![fine])),
        ])
        .await;
        assert_eq!(answer.unwrap().records, ["fine"]);
    }

    #[tokio::test]
    async fn when_every_server_fails_the_error_is_never_absence() {
        let (answer, queries) = broken(vec![]).await;
        assert_eq!(answer, Err(LookupError::Timeout));
        assert_eq!(queries, 2 + 4 * 2);
        let refused = vec![(BROKEN[1], Server::Code(ResponseCode::Refused))];
        assert_eq!(broken(refused).await.0, Err(LookupError::Refused));
        let servfail = vec![(BROKEN[0], Server::Code(ResponseCode::ServFail))];
        assert_eq!(broken(servfail).await.0, Err(LookupError::ServFail));
        for code in [ResponseCode::NoError, ResponseCode::NXDomain] {
            let lame = vec![(BROKEN[0], Server::Code(code))];
            assert!(matches!(broken(lame).await.0, Err(LookupError::Other(_))));
        }
    }

    #[tokio::test]
    async fn referrals_up_sideways_or_in_place_are_refused() {
        for cut in ["com", "example.org", "broken.com"] {
            let (answer, _) = broken(vec![(BROKEN[0], Server::Refers(cut))]).await;
            assert!(
                matches!(answer, Err(LookupError::Other(_))),
                "{cut}: {answer:?}"
            );
        }
    }

    #[tokio::test]
    async fn delegation_is_the_ns_set_the_parent_publishes() {
        let walker = walker(internet());
        let parent = walker.delegation(&name("example.com")).await.unwrap();
        assert_eq!(parent.records, ["ns1.example.com"]);
        assert_eq!(parent.ttl, Some(3600));
        assert!(!asked(&walker).contains(&IpAddr::from(EXAMPLE)));

        let apex = walker
            .lookup(&name("example.com"), RecordType::NS, extract::ns)
            .await
            .unwrap();
        assert_eq!(apex.records, ["ns1.example.com", "ns2.example.com"]);

        assert_eq!(
            walker.delegation(&name("nothing.com")).await,
            Err(LookupError::NxDomain)
        );
        assert_eq!(
            walker.delegation(&name("ns1.example.com")).await,
            Err(LookupError::NoData)
        );
        let shared = walker.delegation(&name("sub.example.com")).await.unwrap();
        assert_eq!(shared.records, ["ns1.example.com", "ns3.example.com"]);
    }

    #[tokio::test]
    async fn ds_is_asked_of_the_parent_even_with_the_child_cached() {
        let walker = walker(internet());
        txt_of(&walker, "example.com").await.unwrap();
        asked(&walker);
        let ds = walker
            .records(&name("example.com"), RecordType::DS, &mut walker.call())
            .await;
        assert!(matches!(ds, Err(LookupError::NoData)));
        assert_eq!(asked(&walker), [IpAddr::from(COM)]);
    }

    #[tokio::test]
    async fn nameservers_that_cannot_be_found_are_an_error() {
        let walker = walker(internet());
        assert!(matches!(
            txt_of(&walker, "loop.com").await,
            Err(LookupError::Other(_))
        ));
        assert!(matches!(
            txt_of(&walker, "self.com").await,
            Err(LookupError::Other(message)) if message.contains("no address")
        ));
    }

    #[tokio::test]
    async fn a_lookup_stops_at_its_query_budget() {
        let options = AuthoritativeOptions {
            max_queries: 2,
            ..AuthoritativeOptions::default()
        };
        let walker = walker_with(internet(), options);
        assert_eq!(
            txt_of(&walker, "example.com").await,
            Err(LookupError::Other("gave up after 2 queries".into()))
        );
    }

    fn reply(query: &Message, answers: Vec<Record>) -> Message {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.metadata.authoritative = true;
        response.add_queries(query.queries.clone());
        response.add_answers(answers);
        response
    }

    /// Answers UDP with a stray datagram, then a truncated answer; TCP in
    /// full. Returns the port, the same for both.
    async fn truncating_server() -> u16 {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let tcp = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            while let Ok((len, peer)) = udp.recv_from(&mut buffer).await {
                let query = Message::from_vec(&buffer[..len]).unwrap();
                let mut stray = reply(&query, vec![txt("example.com", "stray")]);
                stray.metadata.id = stray.metadata.id.wrapping_add(1);
                let mut truncated = reply(&query, vec![]);
                truncated.metadata.truncation = true;
                for message in [stray, truncated] {
                    udp.send_to(&message.to_vec().unwrap(), peer).await.unwrap();
                }
            }
        });
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                let mut query = vec![0; stream.read_u16().await.unwrap().into()];
                stream.read_exact(&mut query).await.unwrap();
                let query = Message::from_vec(&query).unwrap();
                let answer = reply(&query, vec![txt("example.com", "over tcp")])
                    .to_vec()
                    .unwrap();
                let length = u16::try_from(answer.len()).unwrap().to_be_bytes();
                stream
                    .write_all(&[&length[..], &answer].concat())
                    .await
                    .unwrap();
            }
        });
        port
    }

    fn local(port: u16) -> Network {
        Network {
            port,
            timeout: Duration::from_millis(500),
        }
    }

    #[tokio::test]
    async fn a_truncated_udp_answer_is_asked_again_over_tcp() {
        let network = local(truncating_server().await);
        let query = message(&Query::query(name("example.com"), RecordType::TXT));
        let response = network
            .exchange(Ipv4Addr::LOCALHOST.into(), &query)
            .await
            .unwrap();
        let (records, _) = collect(&response.answers, extract::txt);
        assert_eq!(records, [Txt::from("over tcp")]);
    }

    #[tokio::test]
    async fn silence_is_a_timeout() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let network = local(silent.local_addr().unwrap().port());
        let query = message(&Query::query(name("example.com"), RecordType::TXT));
        assert_eq!(
            network.exchange(Ipv4Addr::LOCALHOST.into(), &query).await,
            Err(LookupError::Timeout)
        );
    }

    #[test]
    fn ipv6_is_used_only_without_ipv4() {
        let v4 = IpAddr::from([192, 0, 2, 1]);
        let v6 = IpAddr::from(Ipv6Addr::LOCALHOST);
        assert_eq!(preferred(&[v6, v4]).collect::<Vec<_>>(), [v4]);
        assert_eq!(preferred(&[v6]).collect::<Vec<_>>(), [v6]);
    }
}
