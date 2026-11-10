use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use crate::name::query_name;
use crate::{
    Answer, DnssecStatus, Ds, Lookup, LookupError, Mx, RecordType, Resolver, Tlsa, Txt, normalise,
    reverse_name,
};

/// An in-memory zone for tests, which counts the queries made of it.
///
/// A name with no entry at all answers NXDOMAIN; a name with records of other
/// types answers NODATA. [`with_error`](Self::with_error) overrides one type and
/// [`with_failure`](Self::with_failure) every type.
///
/// ```
/// use wslib_dns::{FakeResolver, LookupError, RecordType, Resolver};
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let dns = FakeResolver::new()
///     .with_txt("example.com", ["v=spf1 -all"])
///     .with_error("_dmarc.example.com", RecordType::Txt, LookupError::ServFail);
/// assert_eq!(dns.txt("example.com").await.unwrap().records[0].joined(), "v=spf1 -all");
/// assert_eq!(dns.mx("example.com").await, Err(LookupError::NoData));
/// assert_eq!(dns.txt("_dmarc.example.com").await, Err(LookupError::ServFail));
/// assert_eq!(dns.txt("example.net").await, Err(LookupError::NxDomain));
/// assert_eq!(dns.total_queries(), 4);
/// # });
/// ```
#[derive(Debug, Default)]
pub struct FakeResolver {
    names: HashMap<String, Entry>,
    queries: Mutex<BTreeMap<(String, RecordType), usize>>,
    validating: bool,
}

#[derive(Debug, Default)]
struct Entry {
    txt: Vec<Txt>,
    a: Vec<Ipv4Addr>,
    aaaa: Vec<Ipv6Addr>,
    mx: Vec<Mx>,
    ns: Vec<String>,
    cname: Option<String>,
    ptr: Vec<String>,
    tlsa: Vec<Tlsa>,
    ds: Vec<Ds>,
    dnssec: Option<DnssecStatus>,
    errors: HashMap<RecordType, LookupError>,
    all_types: Option<LookupError>,
}

impl FakeResolver {
    pub fn new() -> Self {
        Self::default()
    }

    fn entry(&mut self, name: &str) -> &mut Entry {
        self.names.entry(query_name(name)).or_default()
    }

    /// Adds one TXT record per string, each a single character-string.
    pub fn with_txt<'a>(mut self, name: &str, records: impl IntoIterator<Item = &'a str>) -> Self {
        self.entry(name)
            .txt
            .extend(records.into_iter().map(Txt::from));
        self
    }

    /// Adds one TXT record made of several character-strings.
    pub fn with_txt_strings<'a>(
        mut self,
        name: &str,
        strings: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let strings = strings.into_iter().map(|s| s.as_bytes().to_vec()).collect();
        self.entry(name).txt.push(Txt::new(strings));
        self
    }

    /// Adds A or AAAA records by address family.
    pub fn with_ip(mut self, name: &str, addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        let entry = self.entry(name);
        for address in addresses {
            match address {
                IpAddr::V4(v4) => entry.a.push(v4),
                IpAddr::V6(v6) => entry.aaaa.push(v6),
            }
        }
        self
    }

    pub fn with_mx(mut self, name: &str, preference: u16, exchange: &str) -> Self {
        self.entry(name).mx.push(Mx::new(preference, exchange));
        self
    }

    pub fn with_ns(mut self, name: &str, host: &str) -> Self {
        self.entry(name).ns.push(normalise(host));
        self
    }

    /// Makes `name` an alias of `target`. Other queries at `name` answer from
    /// the target, as a recursive resolver's do, counted once under `name`.
    pub fn with_cname(mut self, name: &str, target: &str) -> Self {
        self.entry(name).cname = Some(query_name(target));
        self
    }

    pub fn with_ds(mut self, name: &str, record: Ds) -> Self {
        self.entry(name).ds.push(record);
        self
    }

    pub fn with_tlsa(mut self, name: &str, record: Tlsa) -> Self {
        self.entry(name).tlsa.push(record);
        self
    }

    /// Validates, as [`with_dnssec`](Self::with_dnssec) also does: answers
    /// at names given no status are Insecure.
    pub fn validating(mut self) -> Self {
        self.validating = true;
        self
    }

    /// Validates, marking every answer at `name` with a DNSSEC status. For a
    /// bogus name, use [`LookupError::Bogus`] with
    /// [`with_failure`](Self::with_failure).
    pub fn with_dnssec(mut self, name: &str, status: DnssecStatus) -> Self {
        self.entry(name).dnssec = Some(status);
        self.validating()
    }

    pub fn with_ptr(mut self, ip: IpAddr, host: &str) -> Self {
        self.entry(&reverse_name(ip)).ptr.push(normalise(host));
        self
    }

    /// Answers queries of one type at `name` with `error`.
    pub fn with_error(mut self, name: &str, record_type: RecordType, error: LookupError) -> Self {
        self.entry(name).errors.insert(record_type, error);
        self
    }

    /// Answers every query at `name` with `error`; NXDOMAIN, SERVFAIL and a
    /// timeout are the usual ones.
    pub fn with_failure(mut self, name: &str, error: LookupError) -> Self {
        self.entry(name).all_types = Some(error);
        self
    }

    /// Queries made for `name` and type so far.
    pub fn queries(&self, name: &str, record_type: RecordType) -> usize {
        let queries = self
            .queries
            .lock()
            .expect("query counts are never poisoned");
        queries
            .get(&(query_name(name), record_type))
            .copied()
            .unwrap_or(0)
    }

    pub fn total_queries(&self) -> usize {
        let queries = self
            .queries
            .lock()
            .expect("query counts are never poisoned");
        queries.values().sum()
    }

    /// Every name and type queried, with its count, in name order.
    pub fn query_counts(&self) -> Vec<(String, RecordType, usize)> {
        let queries = self
            .queries
            .lock()
            .expect("query counts are never poisoned");
        queries
            .iter()
            .map(|((name, t), n)| (name.clone(), *t, *n))
            .collect()
    }

    fn answer<T: Clone>(
        &self,
        name: &str,
        record_type: RecordType,
        records: impl Fn(&Entry) -> Vec<T>,
    ) -> Lookup<T> {
        let name = query_name(name);
        *self
            .queries
            .lock()
            .expect("query counts are never poisoned")
            .entry((name.clone(), record_type))
            .or_default() += 1;
        let mut entry = self.names.get(&name).ok_or(LookupError::NxDomain)?;
        let mut canonical_name = None;
        if record_type != RecordType::Cname {
            for _ in 0..crate::DEFAULT_MAX_CNAME_HOPS {
                let Some(target) = &entry.cname else { break };
                entry = self.names.get(target).ok_or(LookupError::NxDomain)?;
                canonical_name = Some(target.clone());
            }
        }
        if let Some(error) = entry.errors.get(&record_type).or(entry.all_types.as_ref()) {
            return Err(error.clone());
        }
        let records = records(entry);
        if records.is_empty() {
            Err(LookupError::NoData)
        } else {
            Ok(Answer {
                canonical_name,
                dnssec: entry
                    .dnssec
                    .or(self.validating.then_some(DnssecStatus::Insecure)),
                ..Answer::new(records)
            })
        }
    }
}

impl Resolver for FakeResolver {
    async fn txt(&self, name: &str) -> Lookup<Txt> {
        self.answer(name, RecordType::Txt, |e| e.txt.clone())
    }

    async fn a(&self, name: &str) -> Lookup<Ipv4Addr> {
        self.answer(name, RecordType::A, |e| e.a.clone())
    }

    async fn aaaa(&self, name: &str) -> Lookup<Ipv6Addr> {
        self.answer(name, RecordType::Aaaa, |e| e.aaaa.clone())
    }

    async fn mx(&self, name: &str) -> Lookup<Mx> {
        self.answer(name, RecordType::Mx, |e| e.mx.clone())
    }

    async fn ns(&self, name: &str) -> Lookup<String> {
        self.answer(name, RecordType::Ns, |e| e.ns.clone())
    }

    async fn cname(&self, name: &str) -> Lookup<String> {
        self.answer(name, RecordType::Cname, |e| {
            e.cname.iter().cloned().collect()
        })
    }

    async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
        self.answer(&reverse_name(ip), RecordType::Ptr, |e| e.ptr.clone())
    }

    async fn tlsa(&self, name: &str) -> Lookup<Tlsa> {
        self.answer(name, RecordType::Tlsa, |e| e.tlsa.clone())
    }

    async fn ds(&self, name: &str) -> Lookup<Ds> {
        self.answer(name, RecordType::Ds, |e| e.ds.clone())
    }

    /// The zone's one NS set stands in for the parent's.
    async fn delegation(&self, name: &str) -> Lookup<String> {
        self.ns(name).await
    }

    fn validates(&self) -> bool {
        self.validating
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CnameChainError, DEFAULT_MAX_CNAME_HOPS};

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn absent_names_and_absent_types_are_told_apart() {
        let dns = FakeResolver::new().with_ip("example.com", ["192.0.2.1".parse().unwrap()]);
        block_on(async {
            assert_eq!(
                dns.a("example.com").await.unwrap().records,
                ["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
            );
            assert_eq!(dns.txt("example.com").await, Err(LookupError::NoData));
            assert_eq!(
                dns.txt("missing.example.com").await,
                Err(LookupError::NxDomain)
            );
        });
    }

    #[test]
    fn errors_override_one_type_or_every_type() {
        let dns = FakeResolver::new()
            .with_txt("example.com", ["hello"])
            .with_error("example.com", RecordType::Mx, LookupError::Timeout)
            .with_failure("example.net", LookupError::Refused);
        block_on(async {
            assert!(dns.txt("example.com").await.is_ok());
            assert_eq!(dns.mx("example.com").await, Err(LookupError::Timeout));
            assert_eq!(dns.a("example.net").await, Err(LookupError::Refused));
            assert_eq!(dns.txt("example.net").await, Err(LookupError::Refused));
        });
    }

    #[test]
    fn queries_are_counted_per_name_and_type() {
        let dns = FakeResolver::new().with_txt("example.com", ["x"]);
        block_on(async {
            dns.txt("example.com").await.ok();
            dns.txt("EXAMPLE.com.").await.ok();
            dns.a("example.com").await.ok();
        });
        assert_eq!(dns.queries("example.com", RecordType::Txt), 2);
        assert_eq!(dns.queries("example.com", RecordType::A), 1);
        assert_eq!(dns.total_queries(), 3);
    }

    #[test]
    fn internationalised_names_are_queried_as_a_labels() {
        let dns = FakeResolver::new().with_txt("bücher.example", ["v=spf1 -all"]);
        assert!(block_on(dns.txt("BÜCHER.example.")).is_ok());
        assert!(block_on(dns.txt("xn--bcher-kva.example")).is_ok());
        assert_eq!(dns.queries("xn--bcher-kva.example", RecordType::Txt), 2);
    }

    #[test]
    fn service_names_survive_idna() {
        let dns = FakeResolver::new().with_txt("_dmarc.example.com", ["v=DMARC1; p=none"]);
        assert!(block_on(dns.txt("_DMARC.example.com")).is_ok());
    }

    #[test]
    fn multi_string_txt_joins_without_a_separator() {
        let dns = FakeResolver::new()
            .with_txt_strings("example.com", ["v=spf1 include:a.example", ".com -all"]);
        let txt = block_on(dns.txt("example.com")).unwrap();
        assert_eq!(txt.records[0].strings.len(), 2);
        assert_eq!(txt.records[0].joined(), "v=spf1 include:a.example.com -all");
    }

    #[test]
    fn ptr_is_keyed_by_the_reverse_name() {
        let ip: IpAddr = "2001:db8::25".parse().unwrap();
        let dns = FakeResolver::new().with_ptr(ip, "Mail.Example.com.");
        assert_eq!(block_on(dns.ptr(ip)).unwrap().records, ["mail.example.com"]);
        assert_eq!(dns.queries(&reverse_name(ip), RecordType::Ptr), 1);
    }

    #[test]
    fn ip_merges_both_families_and_prefers_a_failure_to_absence() {
        let dns = FakeResolver::new()
            .with_ip(
                "both.example.com",
                ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            )
            .with_ip("v4.example.com", ["192.0.2.2".parse().unwrap()])
            .with_error("v4.example.com", RecordType::Aaaa, LookupError::Timeout)
            .with_ns("broken.example.com", "ns.example.net")
            .with_error(
                "broken.example.com",
                RecordType::Aaaa,
                LookupError::ServFail,
            );
        block_on(async {
            assert_eq!(dns.ip("both.example.com").await.unwrap().records.len(), 2);
            assert_eq!(dns.ip("v4.example.com").await.unwrap().records.len(), 1);
            assert_eq!(
                dns.ip("broken.example.com").await,
                Err(LookupError::ServFail)
            );
            assert_eq!(
                dns.ip("missing.example.com").await,
                Err(LookupError::NxDomain)
            );
        });
    }

    #[test]
    fn first_txt_picks_the_first_accepted_record_and_tells_absence_from_failure() {
        let dns = FakeResolver::new()
            .with_txt("example.com", ["google-site-verification=x", "v=spf1 -all"])
            .with_ip("plain.example.com", ["192.0.2.1".parse().unwrap()])
            .with_error("broken.example.com", RecordType::Txt, LookupError::ServFail);
        let is_spf = |text: &str| text.starts_with("v=spf1");
        block_on(async {
            assert_eq!(
                dns.first_txt("example.com", is_spf).await,
                Ok(Some("v=spf1 -all".into()))
            );
            assert_eq!(dns.first_txt("plain.example.com", is_spf).await, Ok(None));
            assert_eq!(dns.first_txt("missing.example.com", is_spf).await, Ok(None));
            assert_eq!(
                dns.first_txt("broken.example.com", is_spf).await,
                Err(LookupError::ServFail)
            );
        });
    }

    #[test]
    fn exists_is_any_answer_but_nxdomain() {
        let dns = FakeResolver::new()
            .with_ns("example.com", "ns1.example.net")
            .with_ip("www.example.com", ["192.0.2.1".parse().unwrap()])
            .with_failure("broken.example.com", LookupError::Timeout);
        block_on(async {
            assert_eq!(dns.exists("example.com").await, Ok(true));
            assert_eq!(dns.exists("www.example.com").await, Ok(true));
            assert_eq!(dns.exists("missing.example.com").await, Ok(false));
            assert_eq!(
                dns.exists("broken.example.com").await,
                Err(LookupError::Timeout)
            );
        });
    }

    #[test]
    fn the_fake_answers_delegation_from_its_ns_set() {
        let dns = FakeResolver::new().with_ns("example.com", "ns1.example.net");
        assert_eq!(
            block_on(dns.delegation("example.com")).unwrap().records,
            ["ns1.example.net"]
        );
        assert_eq!(
            block_on(dns.delegation("example.net")),
            Err(LookupError::NxDomain)
        );
    }

    #[test]
    fn present_is_the_records_or_none_when_absent() {
        let dns = FakeResolver::new()
            .with_mx("example.com", 10, "mail.example.com")
            .with_error("example.net", RecordType::Mx, LookupError::Refused);
        block_on(async {
            assert_eq!(
                crate::present(dns.mx("example.com").await).unwrap().len(),
                1
            );
            assert_eq!(crate::present(dns.mx("example.org").await), Ok(Vec::new()));
            assert_eq!(
                crate::present(dns.mx("example.net").await),
                Err(LookupError::Refused)
            );
        });
    }

    #[test]
    fn cname_chain_follows_to_the_terminal_name() {
        let dns = FakeResolver::new()
            .with_cname("s1._domainkey.example.com", "s1.dkim.example.net")
            .with_cname("s1.dkim.example.net", "s1.keys.example.org")
            .with_txt("s1.keys.example.org", ["v=DKIM1; p="]);
        let chain =
            block_on(dns.cname_chain("s1._domainkey.example.com", DEFAULT_MAX_CNAME_HOPS)).unwrap();
        assert_eq!(chain.terminal(), "s1.keys.example.org");
        assert_eq!(chain.names.len(), 3);
        assert!(chain.is_aliased());
        assert!(chain.reaches("S1.DKIM.Example.NET."));
        assert!(!chain.reaches("s2.dkim.example.net"));
        assert_eq!(
            block_on(dns.txt("s1._domainkey.example.com"))
                .unwrap()
                .records[0]
                .joined(),
            "v=DKIM1; p="
        );
        assert_eq!(
            block_on(dns.txt("s1._domainkey.example.com"))
                .unwrap()
                .canonical_name
                .as_deref(),
            Some("s1.keys.example.org")
        );
        assert_eq!(
            block_on(dns.txt("s1.keys.example.org"))
                .unwrap()
                .canonical_name,
            None
        );

        let direct =
            block_on(dns.cname_chain("s1.keys.example.org", DEFAULT_MAX_CNAME_HOPS)).unwrap();
        assert!(!direct.is_aliased());
    }

    #[test]
    fn cname_chain_detects_loops_caps_hops_and_reports_failures() {
        let dns = FakeResolver::new()
            .with_cname("a.example.com", "b.example.com")
            .with_cname("b.example.com", "a.example.com")
            .with_cname("c0.example.com", "c1.example.com")
            .with_cname("c1.example.com", "c2.example.com")
            .with_cname("c2.example.com", "c3.example.com")
            .with_error("d.example.com", RecordType::Cname, LookupError::ServFail);
        block_on(async {
            assert!(matches!(
                dns.cname_chain("a.example.com", 8).await,
                Err(CnameChainError::Loop { names }) if names == ["a.example.com", "b.example.com", "a.example.com"]
            ));
            assert!(matches!(
                dns.cname_chain("c0.example.com", 2).await,
                Err(CnameChainError::TooLong { .. })
            ));
            assert_eq!(
                dns.cname_chain("c0.example.com", 3)
                    .await
                    .unwrap()
                    .terminal(),
                "c3.example.com"
            );
            assert!(matches!(
                dns.cname_chain("d.example.com", 8).await,
                Err(CnameChainError::Lookup {
                    error: LookupError::ServFail,
                    ..
                })
            ));
        });
    }

    #[test]
    fn answers_carry_the_status_set_for_their_name() {
        let dns = FakeResolver::new()
            .with_mx("example.com", 10, "mail.example.com")
            .with_dnssec("example.com", DnssecStatus::Secure)
            .with_tlsa(
                "_25._tcp.mail.example.com",
                Tlsa {
                    usage: 3,
                    selector: 1,
                    matching: 1,
                    data: vec![0xab; 32],
                },
            )
            .with_failure("bogus.example.com", LookupError::Bogus);
        block_on(async {
            assert_eq!(
                dns.mx("example.com").await.unwrap().dnssec,
                Some(DnssecStatus::Secure)
            );
            assert_eq!(
                dns.tlsa("_25._tcp.mail.example.com").await.unwrap().dnssec,
                Some(DnssecStatus::Insecure)
            );
            assert_eq!(
                dns.tlsa("_25._tcp.mail.example.com").await.unwrap().records[0].usage,
                3
            );
            assert_eq!(dns.a("bogus.example.com").await, Err(LookupError::Bogus));
        });
        assert!(dns.validates());
        assert!(!FakeResolver::new().validates());
    }
}
