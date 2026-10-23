//! An app behind Home Assistant's ingress proxy: the check every request passes
//! on the peer it came from, the caller the proxy names, and the base path it
//! serves the app under.
//!
//! **The proxy's headers are read only behind the arrival proof**, which
//! [`gate`] and [`recognise`] alone set, on a request whose connection's peer,
//! canonicalised, is one of the [`Peers`]. Anyone else can send the same
//! headers.
//!
//! **The proof is the process's, not one router's**: [`arrived`] and [`Caller`]
//! trust a request any `gate` or `recognise` marked, so wrap only the routers
//! that face the proxy.
//!
//! **A trusted loopback address trusts every process in the container**, and
//! on an add-on with `host_network` every process on the host, so loopback is
//! trusted only when asked for.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, FromRequestParts, OptionalFromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap};
use wslib_http_error::ApiError;
use wslib_http_scaffold::BasePath;

/// The Supervisor's address on the add-on network, which the proxy calls from.
pub(crate) const SUPERVISOR: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 30, 32, 2));

/// The Home Assistant user's id.
pub const USER_ID: &str = "x-remote-user-id";
/// The Home Assistant user's name.
pub const USER_NAME: &str = "x-remote-user-name";
/// The Home Assistant user's display name.
pub const DISPLAY_NAME: &str = "x-remote-user-display-name";
/// The base path the proxy serves the app under.
pub const INGRESS_PATH: &str = "x-ingress-path";

const REFUSAL: &str = "this app answers its ingress proxy alone";

/// The peers whose requests arrived through the proxy, and the paths [`gate`]
/// answers for anyone.
#[derive(Clone, Debug)]
pub struct Peers {
    trusted: Vec<IpAddr>,
    exempt: Vec<String>,
    refusal: String,
}

impl Peers {
    /// The Supervisor, `172.30.32.2`.
    pub fn home_assistant() -> Self {
        Self::new([SUPERVISOR])
    }

    pub fn new(peers: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            trusted: peers.into_iter().map(|peer| peer.to_canonical()).collect(),
            exempt: Vec::new(),
            refusal: REFUSAL.to_owned(),
        }
    }

    /// Also `127.0.0.1` and `::1`: every process that can reach them.
    pub fn with_loopback(mut self) -> Self {
        self.trusted.extend([
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]);
        self
    }

    /// Answer `path` to any peer under [`gate`], matched against the request's
    /// path exactly.
    ///
    /// Never as a prefix: `/healthz/` or `/healthz/x` can reach another handler,
    /// such as a bundle's fallback, that the exemption was not meant for.
    pub fn exempt(mut self, path: impl Into<String>) -> Self {
        self.exempt.push(path.into());
        self
    }

    /// The 403's sentence under [`gate`], replacing "this app answers its ingress
    /// proxy alone".
    pub fn refusal(mut self, sentence: impl Into<String>) -> Self {
        self.refusal = sentence.into();
        self
    }

    fn trust(&self, extensions: &Extensions) -> bool {
        extensions
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|ConnectInfo(peer)| self.trusted.contains(&peer.ip().to_canonical()))
    }
}

/// Proof that a request came from one of the [`Peers`].
#[derive(Clone)]
struct Arrived;

/// Whether `gate` or `recognise` found the request's peer trusted.
pub fn arrived(extensions: &Extensions) -> bool {
    extensions.get::<Arrived>().is_some()
}

/// `router` answering only `peers`, and anyone on an exempt path; for an app
/// whose only way in is the proxy.
pub fn gate<S: Clone + Send + Sync + 'static>(router: Router<S>, peers: &Peers) -> Router<S> {
    checking(router, peers, true)
}

/// `router` answering everyone, with the proxy's headers read for `peers`
/// alone; for an app whose port also serves its own sign-in.
pub fn recognise<S: Clone + Send + Sync + 'static>(router: Router<S>, peers: &Peers) -> Router<S> {
    checking(router, peers, false)
}

fn checking<S: Clone + Send + Sync + 'static>(
    router: Router<S>,
    peers: &Peers,
    refusing: bool,
) -> Router<S> {
    let peers = Arc::new(peers.clone());
    router.layer(axum::middleware::map_request(
        move |mut request: Request| {
            let peers = Arc::clone(&peers);
            async move {
                if peers.trust(request.extensions()) {
                    request.extensions_mut().insert(Arrived);
                } else if refusing && !peers.exempt.iter().any(|path| path == request.uri().path())
                {
                    return Err(ApiError::forbidden(peers.refusal.clone()));
                }
                Ok(request)
            }
        },
    ))
}

/// The Home Assistant user the proxy names, on a request that [`arrived`].
///
/// Extracted as `Option<Caller>`: none for a request that did not arrive or
/// names no id. A header sent twice or not UTF-8 is a 400.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub id: String,
    /// The user name, else the id.
    pub name: String,
    pub display_name: Option<String>,
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, ApiError> {
        caller(parts)
    }
}

/// [`Caller`] read from a request's head, for code that sees `&Parts`.
pub fn caller(parts: &Parts) -> Result<Option<Caller>, ApiError> {
    if !arrived(&parts.extensions) {
        return Ok(None);
    }
    let headers = &parts.headers;
    let Some(id) = header(headers, USER_ID)?.filter(|id| !id.is_empty()) else {
        return Ok(None);
    };
    let name = header(headers, USER_NAME)?
        .filter(|name| !name.is_empty())
        .unwrap_or(id);
    let display_name = header(headers, DISPLAY_NAME)?.filter(|name| !name.is_empty());
    Ok(Some(Caller {
        id: id.to_owned(),
        name: name.to_owned(),
        display_name: display_name.map(str::to_owned),
    }))
}

/// The base path the proxy serves the app under, from `X-Ingress-Path` on a
/// request that [`arrived`]; one that is not a [`BasePath`] is a 400.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressBase(pub Option<BasePath>);

impl<S: Send + Sync> FromRequestParts<S> for IngressBase {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiError> {
        spa_base(parts).map(Self)
    }
}

/// [`IngressBase`] as a `Spa::base_from` hook.
pub fn spa_base(parts: &Parts) -> Result<Option<BasePath>, ApiError> {
    if !arrived(&parts.extensions) {
        return Ok(None);
    }
    header(&parts.headers, INGRESS_PATH)?
        .map(|path| {
            path.parse()
                .map_err(|why| ApiError::bad_request(format!("{INGRESS_PATH}: {why}")))
        })
        .transpose()
}

/// `name`'s one value as UTF-8, or `None` when it is absent.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ApiError> {
    let mut values = headers.get_all(name).iter();
    let value = match (values.next(), values.next()) {
        (None, _) => return Ok(None),
        (Some(value), None) => value,
        (Some(_), Some(_)) => return Err(ApiError::bad_request(format!("{name} is sent twice"))),
    };
    std::str::from_utf8(value.as_bytes())
        .map(Some)
        .map_err(|_| ApiError::bad_request(format!("{name} is not UTF-8")))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{HeaderValue, StatusCode};
    use axum::response::Response;
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use wslib_http_scaffold::Spa;

    use super::*;

    const PROXY: &str = "172.30.32.2:40000";
    const INGRESS: &str = "/api/hassio_ingress/Tk-9_x";
    const BUNDLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/bundle");

    fn app() -> Router {
        Router::new()
            .route(
                "/who",
                get(async |caller: Option<Caller>| match caller {
                    Some(Caller {
                        id,
                        name,
                        display_name,
                    }) => format!("{id}|{name}|{display_name:?}"),
                    None => "nobody".to_owned(),
                }),
            )
            .route(
                "/base",
                get(async |IngressBase(base): IngressBase| format!("{base:?}")),
            )
            .route(
                "/arrived",
                get(async |request: Request| arrived(request.extensions()).to_string()),
            )
            .route("/healthz", get(async || "ok"))
            .fallback_service(Spa::from_dir(BUNDLE).base_from(spa_base))
    }

    async fn send(
        router: Router,
        peer: Option<&str>,
        path: &str,
        headers: &[(&'static str, &[u8])],
    ) -> (StatusCode, String) {
        let mut request = Request::get(path).body(Body::empty()).unwrap();
        if let Some(peer) = peer {
            let peer: SocketAddr = peer.parse().unwrap();
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        for (name, value) in headers {
            request
                .headers_mut()
                .append(*name, HeaderValue::from_bytes(value).unwrap());
        }
        let response: Response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn gated() -> Router {
        gate(app(), &Peers::home_assistant().exempt("/healthz"))
    }

    async fn who(headers: &[(&'static str, &[u8])]) -> (StatusCode, String) {
        send(gated(), Some(PROXY), "/who", headers).await
    }

    #[tokio::test]
    async fn the_gate_answers_another_peer_on_an_exempt_path_alone() {
        for peer in [Some("172.30.32.3:40000"), Some("127.0.0.1:1"), None] {
            for path in [
                "/who",
                "/",
                "/nope",
                "/api/x",
                "/healthz/",
                "/healthzx",
                "/HEALTHZ",
            ] {
                let (status, body) = send(gated(), peer, path, &[(USER_ID, b"a1")]).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{peer:?} {path}");
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
                    "this app answers its ingress proxy alone"
                );
            }
            let (status, body) = send(gated(), peer, "/healthz", &[]).await;
            assert_eq!((status, body.as_str()), (StatusCode::OK, "ok"), "{peer:?}");
        }
        let unexempt = gate(app(), &Peers::home_assistant().refusal("ingress only"));
        let (status, body) = send(unexempt, Some("172.30.32.3:1"), "/healthz", &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
            "ingress only"
        );
    }

    #[tokio::test]
    async fn the_caller_is_the_named_id_with_its_name_and_display_name() {
        let named = [
            (USER_ID, &b"a1"[..]),
            (USER_NAME, b"admin"),
            (DISPLAY_NAME, b"Ad Min"),
        ];
        assert_eq!(
            who(&named).await,
            (StatusCode::OK, "a1|admin|Some(\"Ad Min\")".to_owned())
        );
    }

    #[tokio::test]
    async fn an_empty_id_is_no_caller_and_an_empty_name_is_the_id() {
        assert_eq!(who(&[]).await.1, "nobody");
        assert_eq!(
            who(&[(USER_ID, b""), (USER_NAME, b"admin")]).await.1,
            "nobody"
        );
        assert_eq!(who(&[(USER_ID, b"a1")]).await.1, "a1|a1|None");
        assert_eq!(
            who(&[(USER_ID, b"a1"), (USER_NAME, b""), (DISPLAY_NAME, b"")])
                .await
                .1,
            "a1|a1|None"
        );
    }

    #[tokio::test]
    async fn a_header_sent_twice_or_not_utf8_is_a_bad_request_naming_it() {
        for name in [USER_ID, USER_NAME, DISPLAY_NAME] {
            let (status, body) = who(&[(USER_ID, b"a1"), (name, b"x"), (name, b"y")]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
            assert!(body.contains(&format!("{name} is sent twice")), "{body}");

            let mut headers = vec![(USER_ID, &b"a1"[..])];
            headers.retain(|(header, _)| *header != name);
            headers.push((name, b"caf\xe9"));
            let (status, body) = who(&headers).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
            assert!(body.contains(&format!("{name} is not UTF-8")), "{body}");
        }
    }

    #[tokio::test]
    async fn a_mapped_v4_peer_is_its_v4_address_and_loopback_is_trusted_only_when_asked() {
        let (_, body) = send(
            gated(),
            Some("[::ffff:172.30.32.2]:1"),
            "/who",
            &[(USER_ID, b"a1")],
        )
        .await;
        assert_eq!(body, "a1|a1|None");
        for peer in ["127.0.0.1:1", "[::1]:1", "[::ffff:127.0.0.1]:1"] {
            let (status, _) = send(gated(), Some(peer), "/who", &[]).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{peer}");
            let looped = gate(app(), &Peers::home_assistant().with_loopback());
            let (_, body) = send(looped, Some(peer), "/who", &[(USER_ID, b"a1")]).await;
            assert_eq!(body, "a1|a1|None", "{peer}");
        }
        let elsewhere = gate(app(), &Peers::new(["10.0.0.9".parse().unwrap()]));
        let (status, _) = send(elsewhere.clone(), Some(PROXY), "/who", &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(elsewhere, Some("10.0.0.9:1"), "/who", &[]).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn recognise_answers_everyone_and_reads_the_headers_of_the_proxy_alone() {
        let recognised = || recognise(app(), &Peers::home_assistant());
        let asserting = [(USER_ID, &b"a1"[..]), (INGRESS_PATH, INGRESS.as_bytes())];
        for (peer, arrived, caller, base) in [
            (
                Some(PROXY),
                "true",
                "a1|a1|None",
                format!("Some(BasePath(\"{INGRESS}/\"))"),
            ),
            (Some("192.168.1.20:5"), "false", "nobody", "None".to_owned()),
            (None, "false", "nobody", "None".to_owned()),
        ] {
            let (status, body) = send(recognised(), peer, "/arrived", &[]).await;
            assert_eq!(
                (status, body.as_str()),
                (StatusCode::OK, arrived),
                "{peer:?}"
            );
            assert_eq!(send(recognised(), peer, "/who", &asserting).await.1, caller);
            assert_eq!(send(recognised(), peer, "/base", &asserting).await.1, base);
        }
        let (status, _) = send(app(), Some(PROXY), "/who", &asserting).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(send(app(), Some(PROXY), "/arrived", &[]).await.1, "false");
    }

    #[tokio::test]
    async fn an_ingress_path_that_is_not_a_base_path_is_a_bad_request_naming_why() {
        for value in ["/api/../admin", "/a\"b", "/a b/", "/a//b"] {
            let (status, body) = send(
                gated(),
                Some(PROXY),
                "/base",
                &[(INGRESS_PATH, value.as_bytes())],
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
            assert!(
                body.contains("x-ingress-path: expected a path like /apps/name/"),
                "{body}"
            );
        }
        let (_, body) = send(gated(), Some(PROXY), "/base", &[]).await;
        assert_eq!(body, "None");
    }

    #[tokio::test]
    async fn the_page_carries_the_ingress_path_as_its_base_and_a_file_ignores_it() {
        for path in ["/", "/widgets/1", "/index.html"] {
            let (status, body) = send(
                gated(),
                Some(PROXY),
                path,
                &[(INGRESS_PATH, INGRESS.as_bytes())],
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(
                body,
                format!("<head><base href=\"{INGRESS}/\"></head>\n"),
                "{path}"
            );
        }
        let (_, body) = send(gated(), Some(PROXY), "/", &[]).await;
        assert_eq!(body, "<head></head>\n");

        for (path, status) in [
            ("/", StatusCode::BAD_REQUEST),
            ("/widgets/1", StatusCode::BAD_REQUEST),
            ("/assets/app.js", StatusCode::OK),
        ] {
            let bad = [(INGRESS_PATH, &b"/a b/"[..])];
            assert_eq!(
                send(gated(), Some(PROXY), path, &bad).await.0,
                status,
                "{path}"
            );
        }
    }
}
