//! The Streamable-HTTP listener. rmcp supplies the protocol transport; this
//! module owns what sits around it — who may connect, the bearer gate, and
//! the connection log the application shows its user.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{Method, StatusCode, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
pub use ipnet::IpNet;
use rmcp::ServerHandler;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio_util::sync::CancellationToken;

/// Told when a client is first seen and when it is judged gone. The id is the
/// legacy `Mcp-Session-Id`, or `""` for stateless 2026-07-28 traffic, which
/// carries no identity the transport layer can see.
pub trait ConnectionObserver: Send + Sync + 'static {
    fn connected(&self, session_id: &str);
    fn disconnected(&self, session_id: &str);
}

/// What the request's `Host` header may name — the DNS-rebinding defence the
/// spec asks for. This is about the URL the client typed, not where the client
/// is; see [`ClientPolicy`] for that. `Any` is for a listener reached by a LAN
/// or DNS name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HostPolicy {
    #[default]
    Loopback,
    Any,
}

/// Which peer addresses may connect at all. Checked before the bearer token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClientPolicy {
    #[default]
    Any,
    Loopback,
    /// Loopback, RFC 1918, IPv4 link-local, IPv6 unique-local and link-local.
    Private,
    Subnets(Vec<IpNet>),
}

impl ClientPolicy {
    pub fn allows(&self, ip: IpAddr) -> bool {
        // A `[::]` listener reports IPv4 peers as `::ffff:a.b.c.d`.
        let ip = ip.to_canonical();
        match self {
            ClientPolicy::Any => true,
            ClientPolicy::Loopback => ip.is_loopback(),
            ClientPolicy::Private => match ip {
                IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
                IpAddr::V6(v6) => {
                    v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
                }
            },
            ClientPolicy::Subnets(nets) => nets.iter().any(|net| net.contains(&ip)),
        }
    }
}

#[derive(Clone)]
pub struct HttpConfig {
    pub path: String,
    /// `None` or empty = no auth. Compared in constant time when set.
    pub bearer_token: Option<String>,
    pub allowed_hosts: HostPolicy,
    pub allowed_clients: ClientPolicy,
    /// Empty = allow all (rmcp's semantics). MCP clients send no `Origin`, so
    /// this only ever affects a browser page.
    pub allowed_origins: Vec<String>,
    /// A tools-only server has nothing to stream: answer with a plain JSON
    /// body. rmcp still falls back to SSE if a handler emits first.
    pub json_response: bool,
    /// `None` disables connection tracking altogether.
    pub observer: Option<Arc<dyn ConnectionObserver>>,
    /// How long a client may be quiet before it is reported gone. Protocol
    /// 2026-07-28 has no disconnect signal, and legacy clients rarely send
    /// `DELETE`, so idleness is the only evidence for either.
    pub idle_disconnect: Duration,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            path: "/mcp".to_string(),
            bearer_token: None,
            allowed_hosts: HostPolicy::default(),
            allowed_clients: ClientPolicy::default(),
            allowed_origins: Vec::new(),
            json_response: true,
            observer: None,
            idle_disconnect: Duration::from_secs(90),
        }
    }
}

/// The `Origin` values a page served from this server's own port could send.
pub fn loopback_origins(port: u16) -> Vec<String> {
    ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .map(|host| format!("http://{host}:{port}"))
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("failed to bind MCP listener on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("MCP listener I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Bind synchronously so a port conflict surfaces as an error to the caller
/// rather than crashing a spawned task. A stop→start on the same port races
/// the OS releasing the socket, so `AddrInUse` is retried for `retry_for`;
/// a genuine conflict still fails.
pub fn bind_with_retry(
    addr: SocketAddr,
    retry_for: Duration,
) -> Result<std::net::TcpListener, HttpError> {
    let deadline = Instant::now() + retry_for;
    let listener = loop {
        match std::net::TcpListener::bind(addr) {
            Ok(l) => break l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(source) => return Err(HttpError::Bind { addr, source }),
        }
    };
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Own `listener` until `cancel` fires. `factory` builds the handler for each
/// session (or each request, under the stateless 2026-07-28 transport), so it
/// should be cheap — share the router behind an `Arc`. Must run on a tokio
/// runtime; the idle watchdog is joined inside rather than spawned, so the
/// final "disconnected" drain completes before this returns.
pub async fn serve<S>(
    listener: std::net::TcpListener,
    factory: impl Fn() -> S + Send + Sync + 'static,
    config: HttpConfig,
    cancel: CancellationToken,
) -> Result<(), HttpError>
where
    S: ServerHandler + Send + 'static,
{
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let local = listener.local_addr()?;

    let mut transport = StreamableHttpServerConfig::default()
        .with_cancellation_token(cancel.child_token())
        .with_allowed_origins(config.allowed_origins)
        .with_json_response(config.json_response);
    if config.allowed_hosts == HostPolicy::Any {
        transport = transport.disable_allowed_hosts();
    }
    let service = StreamableHttpService::new(
        move || Ok(factory()),
        LocalSessionManager::default().into(),
        transport,
    );

    let gate = Arc::new(Gate {
        token: config.bearer_token.filter(|t| !t.is_empty()),
        clients: config.allowed_clients,
        activity: config.observer.map(|observer| Activity {
            observer,
            last_seen: Mutex::new(HashMap::new()),
        }),
    });
    let router = axum::Router::new()
        .nest_service(&config.path, service)
        .layer(axum::middleware::from_fn_with_state(
            gate.clone(),
            gate_middleware,
        ));

    tracing::info!(%local, path = %config.path, "MCP listener bound");
    let stop = cancel.child_token();
    let served = async {
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await;
        stop.cancel();
        result
    };
    let (served, ()) = tokio::join!(
        served,
        idle_watchdog(gate, config.idle_disconnect, stop.clone())
    );
    tracing::info!(%local, "MCP listener stopped");
    Ok(served?)
}

struct Gate {
    token: Option<String>,
    clients: ClientPolicy,
    activity: Option<Activity>,
}

struct Activity {
    observer: Arc<dyn ConnectionObserver>,
    last_seen: Mutex<HashMap<String, Instant>>,
}

impl Activity {
    fn note(&self, key: &str) {
        let Ok(mut map) = self.last_seen.lock() else {
            return;
        };
        match map.get_mut(key) {
            Some(last) => *last = Instant::now(),
            None => {
                map.insert(key.to_string(), Instant::now());
                self.observer.connected(key);
            }
        }
    }

    fn drop_key(&self, key: &str) {
        if self
            .last_seen
            .lock()
            .map(|mut m| m.remove(key).is_some())
            .unwrap_or(false)
        {
            self.observer.disconnected(key);
        }
    }

    fn expire(&self, idle: Duration) {
        let expired: Vec<String> = self
            .last_seen
            .lock()
            .map(|mut m| {
                m.extract_if(|_, last| last.elapsed() >= idle)
                    .map(|(k, _)| k)
                    .collect()
            })
            .unwrap_or_default();
        for key in expired {
            self.observer.disconnected(&key);
        }
    }
}

/// Compare two secrets without leaking their common prefix length through
/// timing. Length is not secret, the value is.
fn secret_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Stateless traffic shares the empty key. A legacy request carries its
/// session id — except the `initialize` that mints it, which returns it on
/// the response.
fn activity_key(
    is_stateless: bool,
    request_sid: Option<&str>,
    response_sid: Option<&str>,
) -> String {
    if is_stateless {
        return String::new();
    }
    request_sid.or(response_sid).unwrap_or_default().to_string()
}

fn header<'r>(req: &'r axum::http::HeaderMap, name: &str) -> Option<&'r str> {
    req.get(name).and_then(|v| v.to_str().ok())
}

async fn gate_middleware(
    State(gate): State<Arc<Gate>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if !gate.clients.allows(peer.ip()) {
        tracing::warn!(%peer, "MCP request refused: client address not allowed");
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(token) = &gate.token {
        let presented = header(req.headers(), AUTHORIZATION.as_str())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|v| secret_eq(v.as_bytes(), token.as_bytes()));
        if !presented {
            tracing::warn!(%peer, "MCP request refused: bad or missing bearer token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let is_delete = req.method() == Method::DELETE;
    let request_sid = header(req.headers(), "mcp-session-id").map(str::to_string);
    // Every 2026-07-28 POST carries Mcp-Method; its absence marks a legacy one.
    let is_stateless = req.headers().contains_key("mcp-method");

    let resp = next.run(req).await;

    if let Some(activity) = &gate.activity
        && resp.status().is_success()
    {
        let key = activity_key(
            is_stateless,
            request_sid.as_deref(),
            header(resp.headers(), "mcp-session-id"),
        );
        if is_delete {
            activity.drop_key(&key);
        } else {
            activity.note(&key);
        }
    }
    resp
}

/// Report clients quiet for `idle` as gone, and every remaining one when the
/// server stops — otherwise a client that exits without saying goodbye (every
/// stateless one, most legacy ones) leaves an unmatched "connected" forever.
async fn idle_watchdog(gate: Arc<Gate>, idle: Duration, stop: CancellationToken) {
    let Some(activity) = &gate.activity else {
        return;
    };
    let tick = (idle / 2).clamp(Duration::from_millis(100), Duration::from_secs(15));
    loop {
        let stopping = tokio::select! {
            _ = stop.cancelled() => true,
            _ = tokio::time::sleep(tick) => false,
        };
        activity.expire(if stopping { Duration::ZERO } else { idle });
        if stopping {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn secret_eq_compares_values_not_prefixes() {
        assert!(secret_eq(b"abc", b"abc"));
        assert!(!secret_eq(b"abc", b"abd"));
        assert!(!secret_eq(b"abc", b"ab"));
        assert!(secret_eq(b"", b""));
    }

    #[test]
    fn loopback_origins_cover_the_three_spellings() {
        assert_eq!(
            loopback_origins(8787),
            [
                "http://127.0.0.1:8787",
                "http://localhost:8787",
                "http://[::1]:8787"
            ]
        );
    }

    #[test]
    fn client_policy_classifies_addresses() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(ClientPolicy::Any.allows(ip("8.8.8.8")));
        assert!(ClientPolicy::Loopback.allows(ip("127.0.0.1")));
        assert!(ClientPolicy::Loopback.allows(ip("::1")));
        assert!(!ClientPolicy::Loopback.allows(ip("192.168.1.5")));
        assert!(ClientPolicy::Private.allows(ip("192.168.1.5")));
        assert!(ClientPolicy::Private.allows(ip("10.0.0.1")));
        assert!(ClientPolicy::Private.allows(ip("fd00::1")));
        assert!(ClientPolicy::Private.allows(ip("::ffff:192.168.1.5")));
        assert!(!ClientPolicy::Private.allows(ip("8.8.8.8")));
        let lan = ClientPolicy::Subnets(vec!["192.168.1.0/24".parse().unwrap()]);
        assert!(lan.allows(ip("192.168.1.200")));
        assert!(!lan.allows(ip("192.168.2.1")));
        assert!(!lan.allows(ip("127.0.0.1")));
    }

    #[test]
    fn activity_key_prefers_stateless_then_request_then_response() {
        assert_eq!(activity_key(true, Some("s1"), Some("s2")), "");
        assert_eq!(activity_key(false, Some("s1"), Some("s2")), "s1");
        assert_eq!(activity_key(false, None, Some("s2")), "s2");
        assert_eq!(activity_key(false, None, None), "");
    }

    #[derive(Default)]
    struct Counting {
        connected: AtomicUsize,
        disconnected: AtomicUsize,
    }
    impl ConnectionObserver for Counting {
        fn connected(&self, _: &str) {
            self.connected.fetch_add(1, Ordering::SeqCst);
        }
        fn disconnected(&self, _: &str) {
            self.disconnected.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn activity_reports_first_sight_and_expiry() {
        let observer = Arc::new(Counting::default());
        let activity = Activity {
            observer: observer.clone(),
            last_seen: Mutex::new(HashMap::new()),
        };
        activity.note("a");
        activity.note("a");
        activity.note("b");
        assert_eq!(observer.connected.load(Ordering::SeqCst), 2);
        activity.expire(Duration::from_secs(60));
        assert_eq!(observer.disconnected.load(Ordering::SeqCst), 0);
        activity.drop_key("a");
        activity.drop_key("a");
        assert_eq!(observer.disconnected.load(Ordering::SeqCst), 1);
        activity.expire(Duration::ZERO);
        assert_eq!(observer.disconnected.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn bind_with_retry_reports_a_real_conflict() {
        let first = bind_with_retry("127.0.0.1:0".parse().unwrap(), Duration::ZERO).unwrap();
        let addr = first.local_addr().unwrap();
        let err = bind_with_retry(addr, Duration::from_millis(100)).unwrap_err();
        assert!(
            matches!(err, HttpError::Bind { addr: a, .. } if a == addr),
            "{err}"
        );
    }
}
