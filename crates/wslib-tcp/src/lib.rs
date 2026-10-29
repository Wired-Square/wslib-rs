//! A TCP connect that resolves its endpoint every time and tries each address
//! within one budget.

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{
    net::{TcpStream, ToSocketAddrs, lookup_host},
    time::{Instant, timeout, timeout_at},
};

/// Why a connection failed or was lost; each message is one short line.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("cannot resolve {endpoint}: {reason}")]
    Resolve {
        endpoint: String,
        reason: ResolveError,
    },
    #[error("connect to {addr} failed: {source}")]
    Connect { addr: SocketAddr, source: io::Error },
    #[error("connect to {addr} timed out after {after:?}")]
    ConnectTimeout { addr: SocketAddr, after: Duration },
    #[error("timed out after {after:?}")]
    Timeout { after: Duration },
    #[error("connection failed: {0}")]
    Io(io::Error),
    #[error("connection closed by the device")]
    Closed,
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl TransportError {
    /// A copy, its `io::Error` rebuilt from the OS code, or the kind and message.
    pub fn duplicate(&self) -> Self {
        match self {
            Self::Resolve { endpoint, reason } => Self::Resolve {
                endpoint: endpoint.clone(),
                reason: match reason {
                    ResolveError::Io(e) => ResolveError::Io(duplicate_io(e)),
                    ResolveError::NoAddresses => ResolveError::NoAddresses,
                    ResolveError::TimedOut => ResolveError::TimedOut,
                },
            },
            Self::Connect { addr, source } => Self::Connect {
                addr: *addr,
                source: duplicate_io(source),
            },
            Self::ConnectTimeout { addr, after } => Self::ConnectTimeout {
                addr: *addr,
                after: *after,
            },
            Self::Timeout { after } => Self::Timeout { after: *after },
            Self::Io(e) => Self::Io(duplicate_io(e)),
            Self::Closed => Self::Closed,
            Self::Protocol(message) => Self::Protocol(message.clone()),
        }
    }
}

fn duplicate_io(e: &io::Error) -> io::Error {
    e.raw_os_error().map_or_else(
        || io::Error::new(e.kind(), e.to_string()),
        io::Error::from_raw_os_error,
    )
}

/// Why an endpoint gave no address to try.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("{0}")]
    Io(io::Error),
    #[error("no addresses")]
    NoAddresses,
    #[error("timed out")]
    TimedOut,
}

/// `host:port` as an endpoint, an IPv6 literal bracketed.
pub fn tcp_endpoint(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::from((ip, port)).to_string(),
        Err(_) => format!("{host}:{port}"),
    }
}

/// Every address `host` (a name or an IP literal) resolves to on `port`,
/// through the system resolver; never empty on `Ok`.
pub async fn resolve(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, ResolveError> {
    resolve_by(deadline_after(timeout), lookup((host, port))).await
}

async fn lookup(target: impl ToSocketAddrs) -> Result<Vec<SocketAddr>, ResolveError> {
    addresses(lookup_host(target).await.map(Iterator::collect))
}

fn addresses(found: io::Result<Vec<SocketAddr>>) -> Result<Vec<SocketAddr>, ResolveError> {
    match found {
        Err(e) => Err(ResolveError::Io(e)),
        Ok(addrs) if addrs.is_empty() => Err(ResolveError::NoAddresses),
        Ok(addrs) => Ok(addrs),
    }
}

async fn resolve_by(
    deadline: Instant,
    lookup: impl Future<Output = Result<Vec<SocketAddr>, ResolveError>>,
) -> Result<Vec<SocketAddr>, ResolveError> {
    timeout_at(deadline, lookup)
        .await
        .unwrap_or(Err(ResolveError::TimedOut))
}

/// `budget` from now, or about 30 years for a budget past what `Instant` holds.
fn deadline_after(budget: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(budget)
        .unwrap_or_else(|| now + Duration::from_secs(86_400 * 365 * 30))
}

/// A stream to `endpoint` (`host:port`), resolved now; `connect_timeout`
/// covers resolving and every address tried.
pub async fn connect(
    endpoint: &str,
    connect_timeout: Duration,
) -> Result<TcpStream, TransportError> {
    connect_with(endpoint, connect_timeout, lookup(endpoint)).await
}

async fn connect_with(
    endpoint: &str,
    connect_timeout: Duration,
    lookup: impl Future<Output = Result<Vec<SocketAddr>, ResolveError>>,
) -> Result<TcpStream, TransportError> {
    let deadline = deadline_after(connect_timeout);
    let resolve_failed = |reason| TransportError::Resolve {
        endpoint: endpoint.to_owned(),
        reason,
    };
    let addrs = resolve_by(deadline, lookup).await.map_err(resolve_failed)?;
    connect_any(&addrs, deadline)
        .await
        .unwrap_or_else(|| Err(resolve_failed(ResolveError::NoAddresses)))
}

/// Each address gets an equal share of what is left of the budget, so one that
/// silently drops the SYN cannot starve the rest. `None` when there is nothing
/// to try.
async fn connect_any(
    addrs: &[SocketAddr],
    deadline: Instant,
) -> Option<Result<TcpStream, TransportError>> {
    let mut last = None;
    for (i, &addr) in addrs.iter().enumerate() {
        let share = deadline.saturating_duration_since(Instant::now()) / (addrs.len() - i) as u32;
        let attempt = match timeout(share, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Some(Ok(stream)),
            Ok(Err(source)) => TransportError::Connect { addr, source },
            Err(_) => TransportError::ConnectTimeout {
                addr,
                after: Duration::from_millis(share.as_micros().div_ceil(1000) as u64),
            },
        };
        last = Some(Err(attempt));
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpSocket};

    async fn within<F: Future>(test: F) -> F::Output {
        timeout(Duration::from_secs(5), test)
            .await
            .expect("test timed out")
    }

    /// A loopback address a connect hangs on, as against a host that drops the
    /// SYN: a listener that never accepts, its backlog full. Keep the guard
    /// alive while the address must stay silent.
    async fn silent_addr() -> (impl Sized, SocketAddr) {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = socket.local_addr().unwrap();
        let listener = socket.listen(1).unwrap();
        let mut filler = Vec::new();
        let silent = loop {
            match timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => filler.push(stream),
                Ok(Err(_)) => break unaliased_loopback(addr.port()).await,
                Err(_) => break addr,
            }
            assert!(filler.len() < 64, "the backlog never filled");
        };
        ((listener, filler), silent)
    }

    /// macOS resets a connect to a full backlog, but leaves a SYN to an
    /// unconfigured loopback address unanswered. Linux answers all of 127/8.
    async fn unaliased_loopback(port: u16) -> SocketAddr {
        let addr = SocketAddr::from(([127, 0, 0, 2], port));
        let answered = timeout(Duration::from_millis(100), TcpStream::connect(addr)).await;
        assert!(
            answered.is_err(),
            "no silent address here: {addr} answered {answered:?}"
        );
        addr
    }

    async fn refused_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    /// Windows retries a SYN refused by a closed loopback port for about 2 s.
    const REFUSAL_MS: u64 = 3000;

    fn deadline_in(millis: u64) -> Instant {
        Instant::now() + Duration::from_millis(millis)
    }

    #[tokio::test]
    async fn an_ip_literal_resolves_and_a_maximal_timeout_does_not_overflow() {
        let addrs = resolve("127.0.0.1", 8080, Duration::MAX).await;
        assert_eq!(addrs.unwrap(), ["127.0.0.1:8080".parse().unwrap()]);
    }

    #[test]
    fn a_failed_or_empty_lookup_is_a_resolve_error() {
        let failed = addresses(Err(io::Error::other("no such host")));
        assert!(matches!(failed, Err(ResolveError::Io(_))), "{failed:?}");
        let empty = addresses(Ok(Vec::new()));
        assert!(matches!(empty, Err(ResolveError::NoAddresses)), "{empty:?}");
    }

    #[tokio::test]
    async fn a_lookup_past_its_deadline_times_out() {
        let err = resolve_by(Instant::now(), std::future::pending())
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::TimedOut), "{err:?}");
    }

    #[test]
    fn an_ipv6_host_is_bracketed_and_a_name_is_left_alone() {
        assert_eq!(tcp_endpoint("::1", 502), "[::1]:502");
        assert_eq!(tcp_endpoint("10.0.0.5", 502), "10.0.0.5:502");
        assert_eq!(tcp_endpoint("plc.local", 1502), "plc.local:1502");
    }

    #[tokio::test]
    async fn a_refused_address_falls_through_to_the_next() {
        within(async {
            let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addrs = [refused_addr().await, live.local_addr().unwrap()];
            let result = connect_any(&addrs, deadline_in(REFUSAL_MS)).await;
            assert!(matches!(result, Some(Ok(_))));
        })
        .await
    }

    #[tokio::test]
    async fn the_last_failure_is_the_one_reported() {
        within(async {
            let addr = refused_addr().await;
            let result = connect_any(&[addr], deadline_in(REFUSAL_MS)).await;
            assert!(
                matches!(result, Some(Err(TransportError::Connect { addr: a, .. })) if a == addr)
            );
            assert!(connect_any(&[], deadline_in(1000)).await.is_none());
        })
        .await
    }

    #[tokio::test]
    async fn a_silent_address_times_out_on_its_share_of_the_budget() {
        within(async {
            let (_guard, silent) = silent_addr().await;
            let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addrs = [silent, live.local_addr().unwrap()];
            let result = connect_any(&addrs, deadline_in(400)).await;
            assert!(matches!(result, Some(Ok(_))));

            let result = connect_any(&[silent], deadline_in(400)).await;
            assert!(
                matches!(result, Some(Err(TransportError::ConnectTimeout { addr, .. })) if addr == silent)
            );
        })
        .await
    }

    #[tokio::test]
    async fn a_connect_reaches_a_listener_by_its_endpoint() {
        within(async {
            let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = live.local_addr().unwrap().to_string();
            assert!(connect(&endpoint, Duration::from_secs(1)).await.is_ok());
        })
        .await
    }

    #[tokio::test]
    async fn a_maximal_connect_budget_does_not_overflow() {
        within(async {
            let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = live.local_addr().unwrap().to_string();
            assert!(connect(&endpoint, Duration::MAX).await.is_ok());
        })
        .await
    }

    #[tokio::test]
    async fn a_failed_resolve_names_the_endpoint() {
        let err = connect_with("plc.local:502", Duration::from_secs(1), async {
            Err(ResolveError::NoAddresses)
        })
        .await
        .unwrap_err();
        assert!(
            matches!(&err, TransportError::Resolve { endpoint, reason: ResolveError::NoAddresses } if endpoint == "plc.local:502"),
            "{err:?}"
        );
    }

    #[test]
    fn a_duplicate_keeps_the_os_code_or_the_kind_and_message() {
        let addr: SocketAddr = "127.0.0.1:502".parse().unwrap();
        let os = TransportError::Connect {
            addr,
            source: io::Error::from_raw_os_error(61),
        };
        assert!(
            matches!(os.duplicate(), TransportError::Connect { source, .. } if source.raw_os_error() == Some(61))
        );
        let custom = TransportError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "gone"));
        assert_eq!(custom.duplicate().to_string(), custom.to_string());
    }
}
