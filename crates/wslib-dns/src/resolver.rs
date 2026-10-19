use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::pin;
use std::task::Poll;

use crate::{Answer, Ds, Lookup, LookupError, Mx, Tlsa, Txt, normalise};

/// The hop limit [`Resolver::cname_chain`] callers use unless they have a reason
/// not to.
pub const DEFAULT_MAX_CNAME_HOPS: usize = 8;

/// An asynchronous DNS client. Names it returns are [normalised](normalise).
///
/// Each method makes one query. Implementations keep no state a caller can
/// observe besides a cache, so one can be shared across tasks.
pub trait Resolver: Send + Sync {
    fn txt(&self, name: &str) -> impl Future<Output = Lookup<Txt>> + Send;
    fn a(&self, name: &str) -> impl Future<Output = Lookup<Ipv4Addr>> + Send;
    fn aaaa(&self, name: &str) -> impl Future<Output = Lookup<Ipv6Addr>> + Send;
    fn mx(&self, name: &str) -> impl Future<Output = Lookup<Mx>> + Send;
    fn ns(&self, name: &str) -> impl Future<Output = Lookup<String>> + Send;
    /// One hop: the name's own CNAME target.
    fn cname(&self, name: &str) -> impl Future<Output = Lookup<String>> + Send;
    fn ptr(&self, ip: IpAddr) -> impl Future<Output = Lookup<String>> + Send;

    /// TLSA (RFC 6698), such as `_25._tcp.<host>`. A resolver that doesn't
    /// support it answers [`LookupError::Other`].
    fn tlsa(&self, name: &str) -> impl Future<Output = Lookup<Tlsa>> + Send {
        let _ = name;
        async {
            Err(LookupError::Other(
                "this resolver doesn't look up TLSA".into(),
            ))
        }
    }

    /// The DS records the parent zone publishes for `name`. A resolver that
    /// doesn't support it answers [`LookupError::Other`].
    fn ds(&self, name: &str) -> impl Future<Output = Lookup<Ds>> + Send {
        let _ = name;
        async {
            Err(LookupError::Other(
                "this resolver doesn't look up DS".into(),
            ))
        }
    }

    /// Whether answers carry a DNSSEC status, so a missing one means the
    /// query failed rather than the resolver not looking.
    fn validates(&self) -> bool {
        false
    }

    /// A and AAAA, queried together. Addresses from either side are an answer
    /// even if the other side failed; with none, a failure outranks absence.
    fn ip(&self, name: &str) -> impl Future<Output = Lookup<IpAddr>> + Send {
        async move {
            let (v4, v6) = join(self.a(name), self.aaaa(name)).await;
            merge_addresses(v4, v6)
        }
    }

    /// Follows CNAMEs from `name` to the name that holds the records, up to
    /// `max_hops` of them.
    fn cname_chain(
        &self,
        name: &str,
        max_hops: usize,
    ) -> impl Future<Output = Result<CnameChain, CnameChainError>> + Send {
        async move {
            let mut names = vec![normalise(name)];
            loop {
                let current = names
                    .last()
                    .expect("the chain starts with the queried name");
                let next = match self.cname(current).await {
                    Ok(answer) => match answer.records.into_iter().next() {
                        Some(next) => next,
                        None => return Ok(CnameChain { names }),
                    },
                    Err(error) if error.is_absent() => return Ok(CnameChain { names }),
                    Err(error) => return Err(CnameChainError::Lookup { names, error }),
                };
                let looped = names.contains(&next);
                names.push(next);
                if looped {
                    return Err(CnameChainError::Loop { names });
                }
                if names.len() > max_hops + 1 {
                    return Err(CnameChainError::TooLong { names });
                }
            }
        }
    }
}

macro_rules! delegate_resolver {
    ($($wrapper:ty),+) => {$(
        impl<R: Resolver> Resolver for $wrapper {
            fn txt(&self, name: &str) -> impl Future<Output = Lookup<Txt>> + Send {
                (**self).txt(name)
            }
            fn a(&self, name: &str) -> impl Future<Output = Lookup<Ipv4Addr>> + Send {
                (**self).a(name)
            }
            fn aaaa(&self, name: &str) -> impl Future<Output = Lookup<Ipv6Addr>> + Send {
                (**self).aaaa(name)
            }
            fn mx(&self, name: &str) -> impl Future<Output = Lookup<Mx>> + Send {
                (**self).mx(name)
            }
            fn ns(&self, name: &str) -> impl Future<Output = Lookup<String>> + Send {
                (**self).ns(name)
            }
            fn cname(&self, name: &str) -> impl Future<Output = Lookup<String>> + Send {
                (**self).cname(name)
            }
            fn ptr(&self, ip: IpAddr) -> impl Future<Output = Lookup<String>> + Send {
                (**self).ptr(ip)
            }
            fn tlsa(&self, name: &str) -> impl Future<Output = Lookup<Tlsa>> + Send {
                (**self).tlsa(name)
            }
            fn ds(&self, name: &str) -> impl Future<Output = Lookup<Ds>> + Send {
                (**self).ds(name)
            }
            fn validates(&self) -> bool {
                (**self).validates()
            }
        }
    )+};
}

delegate_resolver!(&R, std::sync::Arc<R>);

/// The names a CNAME chain passed through, starting with the one queried.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CnameChain {
    pub names: Vec<String>,
}

impl CnameChain {
    /// The name that holds the records.
    pub fn terminal(&self) -> &str {
        self.names
            .last()
            .expect("the chain starts with the queried name")
    }

    /// Whether the queried name was an alias at all.
    pub fn is_aliased(&self) -> bool {
        self.names.len() > 1
    }
}

/// Why [`Resolver::cname_chain`] stopped short; each carries the names reached.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "code"))]
#[non_exhaustive]
pub enum CnameChainError {
    /// The last name is one seen earlier in the chain.
    Loop {
        names: Vec<String>,
    },
    TooLong {
        names: Vec<String>,
    },
    Lookup {
        names: Vec<String>,
        error: LookupError,
    },
}

impl std::fmt::Display for CnameChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loop { names } => write!(f, "CNAME loop: {}", names.join(" -> ")),
            Self::TooLong { names } => write!(f, "CNAME chain too long: {}", names.join(" -> ")),
            Self::Lookup { names, error } => {
                write!(
                    f,
                    "CNAME lookup of {} failed: {error}",
                    names.last().map_or("", String::as_str)
                )
            }
        }
    }
}

impl std::error::Error for CnameChainError {}

fn merge_addresses(v4: Lookup<Ipv4Addr>, v6: Lookup<Ipv6Addr>) -> Lookup<IpAddr> {
    let v4 = v4.map(|answer| answer.map(IpAddr::V4));
    let v6 = v6.map(|answer| answer.map(IpAddr::V6));
    match (v4, v6) {
        (Ok(a), Ok(b)) => Ok(Answer {
            ttl: [a.ttl, b.ttl].into_iter().flatten().min(),
            dnssec: [a.dnssec, b.dnssec].into_iter().flatten().min(),
            canonical_name: a.canonical_name.or(b.canonical_name),
            records: [a.records, b.records].concat(),
        }),
        (Ok(answer), Err(_)) | (Err(_), Ok(answer)) => Ok(answer),
        (Err(a), Err(b)) => Err(match (a.is_absent(), b.is_absent()) {
            (true, false) => b,
            _ => a,
        }),
    }
}

/// Polls both futures to completion without a runtime's help, so the trait's
/// provided methods stay executor-agnostic.
pub(crate) async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let mut a = pin!(a);
    let mut b = pin!(b);
    let (mut a_out, mut b_out) = (None, None);
    poll_fn(|cx| {
        if a_out.is_none()
            && let Poll::Ready(out) = a.as_mut().poll(cx)
        {
            a_out = Some(out);
        }
        if b_out.is_none()
            && let Poll::Ready(out) = b.as_mut().poll(cx)
        {
            b_out = Some(out);
        }
        if a_out.is_some() && b_out.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    (
        a_out.expect("polled to completion"),
        b_out.expect("polled to completion"),
    )
}
