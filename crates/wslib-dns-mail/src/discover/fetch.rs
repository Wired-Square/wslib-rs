//! The one way this crate fetches over HTTPS: for a URL a domain's DNS
//! controls, so it must never reach a private network.

/// Why a fetched file couldn't be used.
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
    /// A redirect, which is never followed.
    Redirect {
        location: Option<String>,
    },
    /// Not `text/plain`.
    ContentType {
        content_type: Option<String>,
    },
    /// Past `limit` bytes: as sent, or after gzip decompression when
    /// `decompressed`.
    TooLarge {
        limit: usize,
        decompressed: bool,
    },
    /// The body claimed to be gzip and wasn't.
    Undecodable,
    /// Not an `https:` URL, or one with credentials in it.
    InvalidUrl,
    NotUtf8,
    /// The host resolves to an address that isn't globally routable,
    /// so nothing was requested: fetching it would let anyone who controls a
    /// domain's DNS point the checker at private or local services.
    NonGlobalAddress {
        address: std::net::IpAddr,
    },
    /// The host's addresses couldn't be looked up.
    Lookup {
        error: wslib_dns::LookupError,
    },
    /// The caller's deadline or query budget had run out, so nothing was
    /// requested.
    NotSent,
}

/// Makes the `reqwest::ClientBuilder` each fetch starts from, so the caller
/// chooses the TLS provider and timeouts. Each fetch adds its own address
/// pinning and user agent and turns redirects off. Give it no proxy: a proxy
/// resolves the host itself, past the address check.
#[cfg(feature = "http")]
#[derive(Clone)]
pub struct HttpClients {
    make: std::sync::Arc<dyn Fn() -> reqwest::ClientBuilder + Send + Sync>,
    user_agent: String,
}

/// Sent unless [`HttpClients::user_agent`] says otherwise. Some hosts refuse
/// a request with none, and reqwest sends none by default.
#[cfg(feature = "http")]
pub const DEFAULT_USER_AGENT: &str = concat!(
    "wslib-dns-mail/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Wired-Square/wslib-rs)"
);

#[cfg(feature = "http")]
impl HttpClients {
    pub fn new(make: impl Fn() -> reqwest::ClientBuilder + Send + Sync + 'static) -> Self {
        Self {
            make: std::sync::Arc::new(make),
            user_agent: DEFAULT_USER_AGENT.to_owned(),
        }
    }

    /// Sends `user_agent`; it's applied after the caller's builder, so one
    /// set there is replaced by this.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    fn builder(&self) -> reqwest::ClientBuilder {
        (self.make)()
            .user_agent(self.user_agent.clone())
            .redirect(reqwest::redirect::Policy::none())
    }
}

#[cfg(feature = "http")]
impl std::fmt::Debug for HttpClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpClients")
    }
}

/// Which addresses a fetch may connect to. Only crate tests reach loopback.
#[cfg(feature = "http")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    GlobalOnly,
    #[cfg(test)]
    Anywhere,
}

/// A `200 OK` response's headers that matter here, and its body.
#[cfg(feature = "http")]
pub(crate) struct Got {
    pub content_type: Option<String>,
    pub gzip: bool,
    pub body: Vec<u8>,
}

/// GETs `url` safely: `https:` with no credentials; the host resolved
/// through `resolver` (or an IP literal taken as is) and refused unless every
/// address is globally routable; the connection pinned to those addresses;
/// no redirects; `200 OK` only; and the body cut off past `limit` bytes.
#[cfg(feature = "http")]
pub(crate) async fn get(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    url: &str,
    timeout: Option<std::time::Duration>,
    reach: Reach,
    limit: usize,
    accept: &str,
) -> Result<Got, FetchFailure> {
    use std::net::{IpAddr, SocketAddr};

    use wslib_dns::LookupError;

    if timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(FetchFailure::NotSent);
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| FetchFailure::InvalidUrl)?;
    let scheme_allowed =
        parsed.scheme() == "https" || (reach != Reach::GlobalOnly && parsed.scheme() == "http");
    if !scheme_allowed || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FetchFailure::InvalidUrl);
    }
    let port = parsed
        .port_or_known_default()
        .ok_or(FetchFailure::InvalidUrl)?;
    let (host, addresses) = match parsed.host().ok_or(FetchFailure::InvalidUrl)? {
        url::Host::Ipv4(v4) => (None, vec![IpAddr::V4(v4)]),
        url::Host::Ipv6(v6) => (None, vec![IpAddr::V6(v6)]),
        url::Host::Domain(domain) => match resolver.ip(domain).await {
            Ok(answer) => (Some(domain.to_owned()), answer.records),
            Err(LookupError::NotSent) => return Err(FetchFailure::NotSent),
            Err(error) => return Err(FetchFailure::Lookup { error }),
        },
    };
    if reach == Reach::GlobalOnly
        && let Some(&address) = addresses
            .iter()
            .find(|&&address| !wslib_dns::is_global(address))
    {
        return Err(FetchFailure::NonGlobalAddress { address });
    }
    let request_failed = |error: reqwest::Error| FetchFailure::Request {
        message: error.to_string(),
    };
    let mut builder = clients.builder();
    if let Some(host) = &host {
        let pinned: Vec<SocketAddr> = addresses
            .iter()
            .map(|&address| SocketAddr::new(address, port))
            .collect();
        builder = builder.resolve_to_addrs(host, &pinned);
    }
    let client = builder.build().map_err(request_failed)?;
    let mut request = client.get(parsed).header(reqwest::header::ACCEPT, accept);
    if let Some(timeout) = timeout {
        request = request.timeout(timeout);
    }
    let mut response = request.send().await.map_err(request_failed)?;
    let status = response.status();
    if status.is_redirection() {
        let location = header(&response, reqwest::header::LOCATION);
        return Err(FetchFailure::Redirect { location });
    }
    if status != reqwest::StatusCode::OK {
        return Err(FetchFailure::Status {
            status: status.as_u16(),
        });
    }
    let content_type = header(&response, reqwest::header::CONTENT_TYPE);
    let gzip = header(&response, reqwest::header::CONTENT_ENCODING)
        .is_some_and(|encoding| encoding.trim().eq_ignore_ascii_case("gzip"));
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(request_failed)? {
        if body.len() + chunk.len() > limit {
            return Err(FetchFailure::TooLarge {
                limit,
                decompressed: false,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Got {
        content_type,
        gzip,
        body,
    })
}

#[cfg(feature = "http")]
fn header(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The media type of a `Content-Type`, without parameters, lowercased.
pub(crate) fn media_type(content_type: Option<&str>) -> Option<String> {
    let media = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    (!media.is_empty()).then_some(media)
}

#[cfg(all(test, feature = "http"))]
pub(crate) mod testing {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::HttpClients;

    /// Serves one raw HTTP response to every connection on a local port, and
    /// counts the connections.
    pub(crate) async fn serve(response: Vec<u8>) -> (u16, Arc<AtomicUsize>) {
        serve_with(move |_| response.clone()).await
    }

    /// As [`serve`], answering each request with what `respond` makes of it.
    pub(crate) async fn serve_with(
        respond: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
    ) -> (u16, Arc<AtomicUsize>) {
        let respond = Arc::new(respond);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let respond = respond.clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 2048];
                    let read = stream.read(&mut request).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&request[..read]).into_owned();
                    assert!(request.starts_with("GET "));
                    stream.write_all(&respond(&request)).await.ok();
                    stream.shutdown().await.ok();
                });
            }
        });
        (port, connections)
    }

    pub(crate) fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
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

    pub(crate) fn clients() -> HttpClients {
        HttpClients::new(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
            reqwest::Client::builder()
        })
    }
}
