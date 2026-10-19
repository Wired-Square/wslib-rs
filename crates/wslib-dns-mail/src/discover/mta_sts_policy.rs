use crate::Parsed;
use crate::mta_sts::MtaStsPolicy;

/// The outcome of fetching a domain's MTA-STS policy file (RFC 8461 §3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
pub enum PolicyFetch {
    /// `body` is the file as served, which the policy's spans index.
    Fetched {
        url: String,
        body: String,
        policy: Parsed<MtaStsPolicy>,
    },
    Unreachable {
        url: String,
        failure: FetchFailure,
    },
}

/// Why a policy file couldn't be used. A sender treats each the same way: as
/// no policy.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
#[non_exhaustive]
pub enum FetchFailure {
    /// Connecting, TLS or the request failed; the message is the client's.
    Request {
        message: String,
    },
    /// Not `200 OK`.
    Status {
        status: u16,
    },
    /// A redirect, which §3.3 says senders must not follow.
    Redirect {
        location: Option<String>,
    },
    /// Not `text/plain`.
    ContentType {
        content_type: Option<String>,
    },
    TooLarge {
        limit: usize,
    },
    NotUtf8,
    /// The policy host resolves to an address that isn't globally routable,
    /// so nothing was requested: fetching it would let anyone who controls a
    /// domain's DNS point the checker at private or local services.
    NonGlobalAddress {
        address: std::net::IpAddr,
    },
    /// The policy host's addresses couldn't be looked up.
    Lookup {
        error: wslib_dns::LookupError,
    },
    /// The caller's deadline or query budget had run out, so nothing was
    /// requested.
    NotSent,
}

/// Policy files longer than this are refused, as senders may (§3.3).
pub const POLICY_SIZE_LIMIT: usize = 64 * 1024;

/// Where a domain's policy is served from.
pub fn policy_url(domain: &str) -> String {
    format!(
        "https://mta-sts.{}/.well-known/mta-sts.txt",
        super::ascii(domain)
    )
}

/// Makes the `reqwest::ClientBuilder` each policy fetch starts from, so the
/// caller chooses the TLS provider and timeouts. Each fetch adds its own
/// address pinning and turns redirects off. Give it no proxy: a proxy resolves
/// the policy host itself, past the address check.
#[cfg(feature = "http")]
#[derive(Clone)]
pub struct HttpClients(std::sync::Arc<dyn Fn() -> reqwest::ClientBuilder + Send + Sync>);

#[cfg(feature = "http")]
impl HttpClients {
    pub fn new(make: impl Fn() -> reqwest::ClientBuilder + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(make))
    }
}

#[cfg(feature = "http")]
impl std::fmt::Debug for HttpClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpClients")
    }
}

/// Fetches and parses the MTA-STS policy of `domain`. The policy host is
/// resolved through `resolver`, refused unless every address is globally
/// routable, and connected to only at those addresses, so a domain can't
/// steer the request into a private network. `timeout` bounds the request.
#[cfg(feature = "http")]
pub async fn mta_sts_policy(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    domain: &str,
    timeout: Option<std::time::Duration>,
) -> PolicyFetch {
    let host = format!("mta-sts.{}", super::ascii(domain));
    fetch(
        resolver,
        clients,
        &host,
        policy_url(domain),
        timeout,
        Reach::GlobalOnly,
    )
    .await
}

/// Which addresses a fetch may connect to. Only crate tests reach loopback.
#[cfg(feature = "http")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    GlobalOnly,
    #[cfg(test)]
    Anywhere,
}

#[cfg(feature = "http")]
pub(crate) async fn fetch(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    host: &str,
    url: String,
    timeout: Option<std::time::Duration>,
    reach: Reach,
) -> PolicyFetch {
    match read(resolver, clients, host, &url, timeout, reach).await {
        Ok(body) => PolicyFetch::Fetched {
            policy: crate::mta_sts::parse_policy(&body),
            url,
            body,
        },
        Err(failure) => PolicyFetch::Unreachable { url, failure },
    }
}

#[cfg(feature = "http")]
async fn read(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    host: &str,
    url: &str,
    timeout: Option<std::time::Duration>,
    reach: Reach,
) -> Result<String, FetchFailure> {
    use wslib_dns::LookupError;
    if timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(FetchFailure::NotSent);
    }
    let addresses = match resolver.ip(host).await {
        Ok(answer) => answer.records,
        Err(LookupError::NotSent) => return Err(FetchFailure::NotSent),
        Err(error) => return Err(FetchFailure::Lookup { error }),
    };
    if reach == Reach::GlobalOnly
        && let Some(&address) = addresses
            .iter()
            .find(|&&address| !crate::address::is_global(address))
    {
        return Err(FetchFailure::NonGlobalAddress { address });
    }
    let request_failed = |error: reqwest::Error| FetchFailure::Request {
        message: error.to_string(),
    };
    let pinned: Vec<std::net::SocketAddr> = addresses
        .iter()
        .map(|&address| std::net::SocketAddr::new(address, 443))
        .collect();
    let client = (clients.0)()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &pinned)
        .build()
        .map_err(request_failed)?;
    let mut request = client.get(url);
    if let Some(timeout) = timeout {
        request = request.timeout(timeout);
    }
    let mut response = request.send().await.map_err(request_failed)?;
    let status = response.status();
    if status.is_redirection() {
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        return Err(FetchFailure::Redirect { location });
    }
    if status != reqwest::StatusCode::OK {
        return Err(FetchFailure::Status {
            status: status.as_u16(),
        });
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let plain = content_type.as_deref().is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/plain"))
    });
    if !plain {
        return Err(FetchFailure::ContentType { content_type });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(request_failed)? {
        if body.len() + chunk.len() > POLICY_SIZE_LIMIT {
            return Err(FetchFailure::TooLarge {
                limit: POLICY_SIZE_LIMIT,
            });
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| FetchFailure::NotUtf8)
}

#[cfg(all(test, feature = "http"))]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wslib_dns::FakeResolver;

    use super::*;

    const HOST: &str = "mta-sts.example.com";

    /// Serves one raw HTTP response to every connection on a local port, and
    /// counts the connections.
    async fn serve(response: Vec<u8>) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let response = response.clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 2048];
                    let read = stream.read(&mut request).await.unwrap_or(0);
                    assert!(request[..read].starts_with(b"GET "));
                    stream.write_all(&response).await.ok();
                    stream.shutdown().await.ok();
                });
            }
        });
        (port, connections)
    }

    fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for header in headers {
            head.push_str(header);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        [head.into_bytes(), body.to_vec()].concat()
    }

    fn clients() -> HttpClients {
        HttpClients::new(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
            reqwest::Client::builder()
        })
    }

    fn loopback() -> FakeResolver {
        FakeResolver::new().with_ip(HOST, ["127.0.0.1".parse().unwrap()])
    }

    async fn local_fetch(raw: Vec<u8>) -> PolicyFetch {
        let (port, _) = serve(raw).await;
        let url = format!("http://{HOST}:{port}/.well-known/mta-sts.txt");
        fetch(&loopback(), &clients(), HOST, url, None, Reach::Anywhere).await
    }

    async fn failure(raw: Vec<u8>) -> FetchFailure {
        match local_fetch(raw).await {
            PolicyFetch::Unreachable { failure, .. } => failure,
            fetched => panic!("expected a failure, got {fetched:?}"),
        }
    }

    const POLICY: &str =
        "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n";

    #[test]
    fn the_url_is_under_the_mta_sts_host() {
        assert_eq!(
            policy_url("Example.COM."),
            "https://mta-sts.example.com/.well-known/mta-sts.txt"
        );
    }

    #[tokio::test]
    async fn a_plain_text_policy_is_fetched_and_parsed() {
        let fetched = local_fetch(response(
            "200 OK",
            &["Content-Type: text/plain; charset=utf-8"],
            POLICY.as_bytes(),
        ))
        .await;
        let PolicyFetch::Fetched { body, policy, .. } = fetched else {
            panic!("the policy is served");
        };
        assert_eq!(body, POLICY);
        assert!(policy.is_usable());
    }

    #[tokio::test]
    async fn anything_but_a_plain_200_is_refused() {
        assert_eq!(
            failure(response(
                "404 Not Found",
                &["Content-Type: text/plain"],
                b""
            ))
            .await,
            FetchFailure::Status { status: 404 }
        );
        assert_eq!(
            failure(response(
                "302 Found",
                &["Location: https://example.com/policy"],
                b""
            ))
            .await,
            FetchFailure::Redirect {
                location: Some("https://example.com/policy".into())
            }
        );
        assert_eq!(
            failure(response(
                "200 OK",
                &["Content-Type: text/html"],
                POLICY.as_bytes()
            ))
            .await,
            FetchFailure::ContentType {
                content_type: Some("text/html".into())
            }
        );
        assert_eq!(
            failure(response("200 OK", &[], POLICY.as_bytes())).await,
            FetchFailure::ContentType { content_type: None }
        );
        assert_eq!(
            failure(response(
                "200 OK",
                &["Content-Type: text/plain"],
                &[0xff, 0xfe]
            ))
            .await,
            FetchFailure::NotUtf8
        );
        let body = vec![b'#'; POLICY_SIZE_LIMIT + 1];
        assert_eq!(
            failure(response("200 OK", &["Content-Type: text/plain"], &body)).await,
            FetchFailure::TooLarge {
                limit: POLICY_SIZE_LIMIT
            }
        );
    }

    #[tokio::test]
    async fn a_policy_host_on_a_private_or_local_address_is_never_contacted() {
        let (port, connections) = serve(response(
            "200 OK",
            &["Content-Type: text/plain"],
            POLICY.as_bytes(),
        ))
        .await;
        for addresses in [
            vec!["127.0.0.1"],
            vec!["10.0.3.7"],
            vec!["169.254.169.254"],
            vec!["198.51.100.7", "::1"],
        ] {
            let dns =
                FakeResolver::new().with_ip(HOST, addresses.iter().map(|a| a.parse().unwrap()));
            let fetched = mta_sts_policy(&dns, &clients(), "example.com", None).await;
            assert!(
                matches!(
                    fetched,
                    PolicyFetch::Unreachable {
                        failure: FetchFailure::NonGlobalAddress { .. },
                        ..
                    }
                ),
                "{addresses:?}: {fetched:?}"
            );
        }
        let url = format!("http://{HOST}:{port}/.well-known/mta-sts.txt");
        let fetched = fetch(&loopback(), &clients(), HOST, url, None, Reach::GlobalOnly).await;
        assert!(matches!(
            fetched,
            PolicyFetch::Unreachable {
                failure: FetchFailure::NonGlobalAddress { .. },
                ..
            }
        ));
        assert_eq!(connections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lookup_failures_and_no_time_left_send_nothing() {
        let dns = FakeResolver::new().with_error(
            HOST,
            wslib_dns::RecordType::A,
            wslib_dns::LookupError::ServFail,
        );
        let PolicyFetch::Unreachable { failure, .. } =
            mta_sts_policy(&dns, &clients(), "example.com", None).await
        else {
            panic!("a failed lookup fetches nothing");
        };
        assert!(matches!(failure, FetchFailure::Lookup { .. }));
        let PolicyFetch::Unreachable { failure, .. } =
            mta_sts_policy(&loopback(), &clients(), "example.com", Some(Duration::ZERO)).await
        else {
            panic!("nothing is sent");
        };
        assert_eq!(failure, FetchFailure::NotSent);
    }
}
