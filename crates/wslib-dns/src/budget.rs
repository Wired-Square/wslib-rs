use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use crate::{Ds, Lookup, LookupError, Mx, Resolver, Tlsa, Txt};

/// A [`Resolver`] that stops sending queries at a deadline or after a number
/// of them, answering [`LookupError::NotSent`] instead, so a caller can bound
/// the work for one request and tell what was cut short.
///
/// A query already sent when the deadline passes runs to the inner
/// resolver's own timeout.
#[derive(Debug)]
pub struct BudgetResolver<R> {
    inner: R,
    deadline: Option<Instant>,
    max_queries: Option<u32>,
    sent: AtomicU32,
    refused: AtomicU32,
}

impl<R: Resolver> BudgetResolver<R> {
    pub fn new(inner: R, deadline: Option<Instant>, max_queries: Option<u32>) -> Self {
        Self {
            inner,
            deadline,
            max_queries,
            sent: AtomicU32::new(0),
            refused: AtomicU32::new(0),
        }
    }

    pub fn queries_sent(&self) -> u32 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Queries answered [`LookupError::NotSent`].
    pub fn queries_refused(&self) -> u32 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    fn admit(&self) -> Result<(), LookupError> {
        let late = self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline);
        let spent = !late
            && self.max_queries.is_some_and(|max| {
                self.sent
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |sent| {
                        (sent < max).then_some(sent + 1)
                    })
                    .is_err()
            });
        if late || spent {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return Err(LookupError::NotSent);
        }
        if self.max_queries.is_none() {
            self.sent.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl<R: Resolver> Resolver for BudgetResolver<R> {
    async fn txt(&self, name: &str) -> Lookup<Txt> {
        self.admit()?;
        self.inner.txt(name).await
    }

    async fn a(&self, name: &str) -> Lookup<Ipv4Addr> {
        self.admit()?;
        self.inner.a(name).await
    }

    async fn aaaa(&self, name: &str) -> Lookup<Ipv6Addr> {
        self.admit()?;
        self.inner.aaaa(name).await
    }

    async fn mx(&self, name: &str) -> Lookup<Mx> {
        self.admit()?;
        self.inner.mx(name).await
    }

    async fn ns(&self, name: &str) -> Lookup<String> {
        self.admit()?;
        self.inner.ns(name).await
    }

    async fn cname(&self, name: &str) -> Lookup<String> {
        self.admit()?;
        self.inner.cname(name).await
    }

    async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
        self.admit()?;
        self.inner.ptr(ip).await
    }

    async fn tlsa(&self, name: &str) -> Lookup<Tlsa> {
        self.admit()?;
        self.inner.tlsa(name).await
    }

    async fn ds(&self, name: &str) -> Lookup<Ds> {
        self.admit()?;
        self.inner.ds(name).await
    }

    fn validates(&self) -> bool {
        self.inner.validates()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::FakeResolver;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn the_budget_caps_queries_sent() {
        let dns = BudgetResolver::new(
            FakeResolver::new().with_txt("example.com", ["x"]),
            None,
            Some(2),
        );
        block_on(async {
            assert!(dns.txt("example.com").await.is_ok());
            assert_eq!(dns.a("example.com").await, Err(LookupError::NoData));
            assert_eq!(dns.txt("example.com").await, Err(LookupError::NotSent));
        });
        assert_eq!((dns.queries_sent(), dns.queries_refused()), (2, 1));
        assert_eq!(dns.into_inner().total_queries(), 2);
    }

    #[test]
    fn a_passed_deadline_sends_nothing() {
        let past = Instant::now() - Duration::from_secs(1);
        let dns = BudgetResolver::new(FakeResolver::new(), Some(past), None);
        assert_eq!(block_on(dns.mx("example.com")), Err(LookupError::NotSent));
        assert_eq!(dns.queries_sent(), 0);
    }

    #[test]
    fn not_sent_is_neither_absence_nor_an_answer() {
        assert!(!LookupError::NotSent.is_absent());
    }
}
