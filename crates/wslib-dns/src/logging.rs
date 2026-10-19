use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Instant;

use crate::{Lookup, LookupError, Mx, RecordType, Resolver, Txt, reverse_name};

/// A [`Resolver`] that records every query it passes on and how it ended, so a
/// caller can show its working.
#[derive(Debug)]
pub struct LoggingResolver<R> {
    inner: R,
    log: Mutex<Vec<QueryRecord>>,
}

/// One query and its outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QueryRecord {
    pub name: String,
    pub record_type: RecordType,
    /// The records in presentation form, or why there were none.
    pub outcome: Result<Vec<String>, LookupError>,
    pub elapsed_ms: u64,
}

impl<R: Resolver> LoggingResolver<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            log: Mutex::new(Vec::new()),
        }
    }

    /// The queries so far, in the order they finished.
    pub fn log(&self) -> Vec<QueryRecord> {
        self.log
            .lock()
            .expect("the query log is never poisoned")
            .clone()
    }

    pub fn into_log(self) -> Vec<QueryRecord> {
        self.log
            .into_inner()
            .expect("the query log is never poisoned")
    }

    async fn logged<T: Presentation>(
        &self,
        name: &str,
        record_type: RecordType,
        query: impl Future<Output = Lookup<T>>,
    ) -> Lookup<T> {
        let started = Instant::now();
        let result = query.await;
        let record = QueryRecord {
            name: crate::normalise(name),
            record_type,
            outcome: match &result {
                Ok(answer) => Ok(answer
                    .records
                    .iter()
                    .map(Presentation::presentation)
                    .collect()),
                Err(error) => Err(error.clone()),
            },
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        self.log
            .lock()
            .expect("the query log is never poisoned")
            .push(record);
        result
    }
}

impl<R: Resolver> Resolver for LoggingResolver<R> {
    async fn txt(&self, name: &str) -> Lookup<Txt> {
        self.logged(name, RecordType::Txt, self.inner.txt(name))
            .await
    }

    async fn a(&self, name: &str) -> Lookup<Ipv4Addr> {
        self.logged(name, RecordType::A, self.inner.a(name)).await
    }

    async fn aaaa(&self, name: &str) -> Lookup<Ipv6Addr> {
        self.logged(name, RecordType::Aaaa, self.inner.aaaa(name))
            .await
    }

    async fn mx(&self, name: &str) -> Lookup<Mx> {
        self.logged(name, RecordType::Mx, self.inner.mx(name)).await
    }

    async fn ns(&self, name: &str) -> Lookup<String> {
        self.logged(name, RecordType::Ns, self.inner.ns(name)).await
    }

    async fn cname(&self, name: &str) -> Lookup<String> {
        self.logged(name, RecordType::Cname, self.inner.cname(name))
            .await
    }

    async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
        self.logged(&reverse_name(ip), RecordType::Ptr, self.inner.ptr(ip))
            .await
    }
}

trait Presentation {
    fn presentation(&self) -> String;
}

impl Presentation for Txt {
    fn presentation(&self) -> String {
        self.joined()
    }
}

impl Presentation for Mx {
    fn presentation(&self) -> String {
        format!("{} {}", self.preference, self.exchange)
    }
}

impl Presentation for String {
    fn presentation(&self) -> String {
        self.clone()
    }
}

impl Presentation for Ipv4Addr {
    fn presentation(&self) -> String {
        self.to_string()
    }
}

impl Presentation for Ipv6Addr {
    fn presentation(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeResolver;

    #[test]
    fn every_query_is_recorded_with_its_outcome() {
        let dns = LoggingResolver::new(
            FakeResolver::new()
                .with_mx("example.com", 10, "mail.example.com")
                .with_error("_dmarc.example.com", RecordType::Txt, LookupError::Timeout),
        );
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                dns.mx("example.com").await.ok();
                dns.txt("_dmarc.example.com").await.ok();
            });
        let log = dns.into_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].record_type, RecordType::Mx);
        assert_eq!(log[0].outcome, Ok(vec!["10 mail.example.com".to_owned()]));
        assert_eq!(log[1].name, "_dmarc.example.com");
        assert_eq!(log[1].outcome, Err(LookupError::Timeout));
    }
}
