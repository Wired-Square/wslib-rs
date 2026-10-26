//! A built single-page app, where every unmatched path is `index.html` but
//! no path under a reserved prefix ever is.

use std::convert::Infallible;
use std::io::Write;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use flate2::Compression;
use flate2::write::GzEncoder;
use percent_encoding::percent_decode_str;
use tower::{Service, ServiceExt};
use tower_http::services::ServeDir;
use wslib_http_error::ApiError;

use crate::BasePath;
use crate::compress;

pub(crate) const INDEX: &str = "index.html";
const ASSETS: &str = "assets";
const IMMUTABLE: HeaderValue = HeaderValue::from_static("public, max-age=31536000, immutable");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const HTML: &str = "text/html; charset=utf-8";

type BaseHook = dyn Fn(&Parts) -> Result<Option<BasePath>, ApiError> + Send + Sync;

/// The app's bundle as a fallback service: mount it with `Router::fallback_service`.
///
/// `assets/` is cached for ever and a missing name there is a 404; everything
/// else is `no-store`, and a missing name is the page. A path under a reserved
/// prefix (`api` unless [`reserving`](Self::reserving) says otherwise) is a 404,
/// judged by [`first_segment_is`].
///
/// `index.html` is read once, as the `Spa` is built, and served from memory
/// with a gzip made then.
#[derive(Clone)]
pub struct Spa {
    files: Arc<Files>,
    reserved: Arc<[String]>,
    page: Option<Page>,
    base_from: Option<Arc<BaseHook>>,
}

pub(crate) enum Files {
    Disk(ServeDir),
    #[cfg(feature = "embed")]
    Embedded(crate::embed::Lookup),
}

impl Files {
    fn disk(dir: &Path) -> Self {
        Self::Disk(
            ServeDir::new(dir)
                .precompressed_gzip()
                .append_index_html_on_directories(false),
        )
    }
}

/// `index.html` as read, and as served without a per-request base: its gzip
/// kept only when smaller.
#[derive(Clone)]
struct Page {
    read: Bytes,
    plain: Bytes,
    gzip: Option<Bytes>,
}

impl Page {
    fn new(read: Bytes, base: Option<&BasePath>) -> Self {
        let plain = match base {
            Some(base) => with_base(&read, base.as_str()),
            None => read.clone(),
        };
        let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
        gzip.write_all(&plain).expect("writing to memory");
        let gzip = Some(gzip.finish().expect("writing to memory"))
            .filter(|gzip| gzip.len() < plain.len())
            .map(Bytes::from);
        Self { read, plain, gzip }
    }

    fn respond(&self, asked: &HeaderMap) -> Response {
        match &self.gzip {
            Some(gzip) if compress::accepts_gzip(asked) => {
                let headers = [
                    (header::CONTENT_TYPE, HTML),
                    (header::CONTENT_ENCODING, "gzip"),
                ];
                (headers, gzip.clone()).into_response()
            }
            _ => ([(header::CONTENT_TYPE, HTML)], self.plain.clone()).into_response(),
        }
    }
}

impl Spa {
    /// The bundle in `dir`, with a `.gz` beside a file sent to a client taking gzip.
    pub fn from_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        let page = std::fs::read(dir.join(INDEX)).ok().map(Bytes::from);
        Self::of(Files::disk(dir), page)
    }

    /// The bundle in `dir` as [`from_dir`](Self::from_dir) serves it, with
    /// `page` as its `index.html` in place of the file there.
    pub fn from_dir_with_page(dir: impl AsRef<Path>, page: impl Into<Bytes>) -> Self {
        Self::of(Files::disk(dir.as_ref()), Some(page.into()))
    }

    pub(crate) fn of(files: Files, page: Option<Bytes>) -> Self {
        Self {
            files: Arc::new(files),
            reserved: Arc::new(["api".to_owned()]),
            page: page.map(|page| Page::new(page, None)),
            base_from: None,
        }
    }

    /// Whether the bundle has an `index.html`; without one the page is a 404.
    pub fn has_page(&self) -> bool {
        self.page.is_some()
    }

    /// The first path segments that belong to routes and never to the bundle,
    /// replacing the default `api`.
    pub fn reserving(mut self, prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.reserved = prefixes.into_iter().map(Into::into).collect();
        self
    }

    /// Serve `index.html` with `<base href>` naming `base`, made once here.
    pub fn base(mut self, base: BasePath) -> Self {
        self.page = self.page.map(|page| Page::new(page.read, Some(&base)));
        self
    }

    /// Serve `index.html` with a `<base href>` for the base `hook` names for
    /// the request, made per request, else as [`base`](Self::base) left it; a
    /// refusal from `hook` answers the page's requests and no file's.
    pub fn base_from(
        mut self,
        hook: impl Fn(&Parts) -> Result<Option<BasePath>, ApiError> + Send + Sync + 'static,
    ) -> Self {
        self.base_from = Some(Arc::new(hook));
        self
    }

    async fn serve(self, mut request: Request) -> Response {
        let path = request.uri().path().to_owned();
        let method = request.method().clone();
        let decoded = percent_decode_str(&path).decode_utf8_lossy();
        let first = first_segment(&decoded);
        if first.is_some_and(|first| self.reserved.iter().any(|r| r == first)) {
            return no_store(
                ApiError::not_found(format!("no such endpoint: {path}")).into_response(),
            );
        }
        let assets = first == Some(ASSETS);
        let page = !assets
            && matches!(first, None | Some(INDEX))
            && matches!(method, Method::GET | Method::HEAD);

        // A range is of the plain file.
        if request.headers().contains_key(header::RANGE) {
            request.headers_mut().remove(header::ACCEPT_ENCODING);
        } else {
            compress::restore_accept_encoding(&mut request);
        }
        let (parts, _) = request.into_parts();
        let served = if page {
            self.page(&parts)
        } else {
            let served = self.file(parts.clone()).await;
            match served.status() {
                StatusCode::NOT_FOUND if !assets => self.page(&parts),
                _ => Ok(served),
            }
        };
        let served = match served {
            Ok(served) => served,
            Err(refused) => return no_store(refused.into_response()),
        };
        let status = served.status();
        if status.is_client_error() || status.is_server_error() {
            return no_store(refusal(served, &method, &path));
        }
        let mut served = compress::mark_stored(served);
        let headers = served.headers_mut();
        headers.insert(
            header::CACHE_CONTROL,
            if assets { IMMUTABLE } else { NO_STORE },
        );
        headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
        served
    }

    async fn file(&self, parts: Parts) -> Response {
        match &*self.files {
            Files::Disk(files) => files
                .clone()
                .oneshot(Request::from_parts(parts, Body::empty()))
                .await
                .into_response(),
            #[cfg(feature = "embed")]
            Files::Embedded(lookup) => {
                let path = percent_decode_str(parts.uri.path()).decode_utf8_lossy();
                crate::embed::serve(*lookup, path.trim_start_matches('/'), &parts)
            }
        }
    }

    fn page(&self, parts: &Parts) -> Result<Response, ApiError> {
        let Some(page) = &self.page else {
            return Err(ApiError::not_found(format!("the bundle has no {INDEX}")));
        };
        let named = match &self.base_from {
            Some(hook) => hook(parts)?,
            None => None,
        };
        Ok(match named {
            Some(base) => based(&page.read, &base),
            None => page.respond(&parts.headers),
        })
    }
}

/// Whether `path`, percent-decoded once and with `.` and `..` resolved, has
/// `segment` as its first segment: the rule [`Spa`] refuses a reserved prefix by.
pub fn first_segment_is(path: &str, segment: &str) -> bool {
    first_segment(&percent_decode_str(path).decode_utf8_lossy()) == Some(segment)
}

fn based(page: &[u8], base: &BasePath) -> Response {
    (
        [(header::CONTENT_TYPE, HTML)],
        with_base(page, base.as_str()),
    )
        .into_response()
}

/// `page` with its `<base>` in the head pointing at `base_path`, else with
/// `<base href="{base_path}">` first in its `<head>`, else after its doctype,
/// else first. `base_path` needs no escaping: see `BasePath`.
fn with_base(page: &[u8], base_path: &str) -> Bytes {
    let href = format!("\"{base_path}\"");
    let head_ends = tag(page, b"</head").map_or(page.len(), |(at, _)| at);
    let (from, to, text) = match tag(page, b"<base").filter(|&(at, _)| at < head_ends) {
        Some((at, end)) => match href_value(&page[at..end]) {
            Some((from, to)) => (at + from, at + to, href),
            None => (at + 5, at + 5, format!(" href={href}")),
        },
        None => {
            let at = tag(page, b"<head")
                .or_else(|| tag(page, b"<!doctype"))
                .map_or(0, |(_, end)| end);
            (at, at, format!("<base href={href}>"))
        }
    };
    [&page[..from], text.as_bytes(), &page[to..]]
        .concat()
        .into()
}

/// Where the first tag named `open`, any case, starts and ends.
fn tag(page: &[u8], open: &[u8]) -> Option<(usize, usize)> {
    (0..page.len()).find_map(|i| {
        let rest = &page[i..];
        let named = rest.len() > open.len()
            && rest[..open.len()].eq_ignore_ascii_case(open)
            && (rest[open.len()] == b'>' || rest[open.len()].is_ascii_whitespace());
        named
            .then(|| {
                rest.iter()
                    .position(|&b| b == b'>')
                    .map(|end| (i, i + end + 1))
            })
            .flatten()
    })
}

/// The span of the `href` attribute's value in `tag`, quotes included.
fn href_value(tag: &[u8]) -> Option<(usize, usize)> {
    let space = |from: usize| {
        from + tag[from..]
            .iter()
            .take_while(|b| b.is_ascii_whitespace())
            .count()
    };
    (1..tag.len()).find_map(|i| {
        let named = tag[i - 1].is_ascii_whitespace()
            && tag.len() > i + 4
            && tag[i..i + 4].eq_ignore_ascii_case(b"href");
        if !named {
            return None;
        }
        let equals = space(i + 4);
        if tag.get(equals) != Some(&b'=') {
            return None;
        }
        let start = space(equals + 1);
        let len = match tag.get(start)? {
            &quote @ (b'"' | b'\'') => tag[start + 1..].iter().position(|&b| b == quote)? + 2,
            _ => tag[start..]
                .iter()
                .position(|&b| b.is_ascii_whitespace() || b == b'>')?,
        };
        Some((start, start + len))
    })
}

impl Service<Request> for Spa {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let spa = self.clone();
        Box::pin(async move { Ok(spa.serve(request).await) })
    }
}

/// The first segment of `path` once `.` and `..` are resolved.
///
/// Stricter than `ServeDir`, which refuses a `..` rather than resolving it and
/// answers that refusal with the page.
fn first_segment(path: &str) -> Option<&str> {
    let mut first = None;
    let mut depth = 0usize;
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    first = None;
                }
            }
            name => {
                if depth == 0 {
                    first = Some(name);
                }
                depth += 1;
            }
        }
    }
    first
}

/// A file server's bare refusal as the error body, keeping `Allow` and `Content-Range`.
fn refusal(served: Response, method: &Method, path: &str) -> Response {
    let status = served.status();
    let sentence = match status {
        StatusCode::NOT_FOUND => format!("no such file: {path}"),
        StatusCode::METHOD_NOT_ALLOWED => format!("the {method} method is not allowed at {path}"),
        _ => status
            .canonical_reason()
            .unwrap_or("refused")
            .to_lowercase(),
    };
    [header::ALLOW, header::CONTENT_RANGE]
        .into_iter()
        .filter_map(|name| Some((served.headers().get(&name)?.clone(), name)))
        .fold(ApiError::new(status, sentence), |error, (value, name)| {
            error.with_header(name, value)
        })
        .into_response()
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, NO_STORE);
    response
}

#[cfg(test)]
pub(crate) mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use http_body_util::BodyExt;

    use super::*;

    pub(crate) const BUNDLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/spa");

    /// Every spelling of an `/api` path the bundle must not answer.
    const API_SHAPES: [&str; 12] = [
        "/api",
        "/api/",
        "/api/nonsense",
        "//api/nonsense",
        "/api%2Fnonsense",
        "/%61pi/nonsense",
        "/%2Fapi/nonsense",
        "/./api/nonsense",
        "/x/../api/nonsense",
        "/ui/../api/branding",
        "/x/%2e%2e/api/nonsense",
        "/apiary/../api/nonsense",
    ];

    pub(crate) async fn get_from(
        spa: Spa,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (Response, Vec<u8>) {
        send(spa, Method::GET, path, headers).await
    }

    async fn send(
        spa: Spa,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (Response, Vec<u8>) {
        let app = Router::new()
            .route("/api/real", get(async || "real"))
            .fallback_service(spa);
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes().to_vec();
        (Response::from_parts(parts, Body::empty()), bytes)
    }

    pub(crate) async fn rules_hold(spa: Spa) {
        let page = std::fs::read(format!("{BUNDLE}/index.html")).unwrap();
        let header = |response: &Response, name| {
            response
                .headers()
                .get(name)
                .map(|v| v.to_str().unwrap().to_owned())
        };

        for path in API_SHAPES {
            let (response, body) = get_from(spa.clone(), path, &[]).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert_eq!(
                header(&response, header::CACHE_CONTROL).as_deref(),
                Some("no-store"),
                "{path}"
            );
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                body["error"].as_str().unwrap().contains(path),
                "{path}: {body}"
            );
        }
        assert_eq!(get_from(spa.clone(), "/api/real", &[]).await.1, b"real");

        for path in [
            "/",
            "/settings",
            "/users/abc",
            "/index.html",
            "/API/branding",
            "/apiary",
        ] {
            let (response, body) = get_from(spa.clone(), path, &[]).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(body, page, "{path}");
            assert_eq!(
                header(&response, header::CACHE_CONTROL).as_deref(),
                Some("no-store"),
                "{path}"
            );
        }

        let (response, body) = get_from(spa.clone(), "/robots.txt", &[]).await;
        assert_eq!(body, b"User-agent: *\n");
        assert_eq!(
            header(&response, header::CACHE_CONTROL).as_deref(),
            Some("no-store")
        );

        let (response, body) = get_from(spa.clone(), "/assets/app-abc123.js", &[]).await;
        assert_eq!(body, b"console.log(\"app\");\n");
        assert_eq!(
            header(&response, header::CACHE_CONTROL).as_deref(),
            Some("public, max-age=31536000, immutable")
        );
        assert!(
            header(&response, header::CONTENT_TYPE)
                .unwrap()
                .contains("javascript")
        );

        let (response, body) = get_from(spa.clone(), "/assets/app-old.js", &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            header(&response, header::CACHE_CONTROL).as_deref(),
            Some("no-store")
        );
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "no such file: /assets/app-old.js");

        for path in ["/assets/app-abc123.js", "/settings"] {
            let (response, body) =
                get_from(spa.clone(), path, &[("accept-encoding", "br, gzip")]).await;
            assert_eq!(
                header(&response, header::CONTENT_ENCODING).as_deref(),
                Some("gzip"),
                "{path}"
            );
            assert!(
                header(&response, header::VARY)
                    .unwrap()
                    .contains("accept-encoding"),
                "{path}"
            );
            assert_eq!(&body[..2], [0x1f, 0x8b], "{path}");
        }
        let (response, _) =
            get_from(spa.clone(), "/settings", &[("accept-encoding", "gzip;q=0")]).await;
        assert!(header(&response, header::CONTENT_ENCODING).is_none());

        let (response, body) = send(spa.clone(), Method::POST, "/settings", &[]).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(header(&response, header::ALLOW).unwrap().contains("GET"));
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "the POST method is not allowed at /settings");
    }

    #[tokio::test]
    async fn a_bundle_on_disk_keeps_every_rule() {
        rules_hold(Spa::from_dir(BUNDLE)).await;
    }

    /// The base named in `x-base`, a 400 when it is not one.
    pub(crate) fn based_on_header(spa: Spa) -> Spa {
        spa.base_from(|parts| {
            parts
                .headers
                .get("x-base")
                .map(|base| {
                    base.to_str()
                        .unwrap()
                        .parse()
                        .map_err(|why: String| ApiError::bad_request(format!("x-base: {why}")))
                })
                .transpose()
        })
    }

    pub(crate) async fn the_base_is_the_hooks(spa: Spa) {
        let page = String::from_utf8(std::fs::read(format!("{BUNDLE}/index.html")).unwrap())
            .unwrap()
            .replace("<head>", "<head><base href=\"/apps/x/\">");
        let spa = based_on_header(spa);
        for path in ["/", "/settings", "/index.html"] {
            let (response, body) = get_from(
                spa.clone(),
                path,
                &[("x-base", "apps/x"), ("accept-encoding", "gzip")],
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(String::from_utf8(body).unwrap(), page, "{path}");
            assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(
                response.headers()[header::CONTENT_TYPE]
                    .to_str()
                    .unwrap()
                    .starts_with("text/html")
            );
        }

        let unnamed = get_from(spa.clone(), "/settings", &[]).await.1;
        assert_eq!(
            unnamed,
            std::fs::read(format!("{BUNDLE}/index.html")).unwrap()
        );

        for (path, status) in [
            ("/", StatusCode::BAD_REQUEST),
            ("/settings", StatusCode::BAD_REQUEST),
            ("/assets/app-abc123.js", StatusCode::OK),
            ("/robots.txt", StatusCode::OK),
            ("/assets/app-old.js", StatusCode::NOT_FOUND),
            ("/api/x", StatusCode::NOT_FOUND),
        ] {
            let (response, body) = get_from(spa.clone(), path, &[("x-base", "/a b/")]).await;
            assert_eq!(response.status(), status, "{path}");
            if status == StatusCode::BAD_REQUEST {
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert!(
                    body["error"]
                        .as_str()
                        .unwrap()
                        .starts_with("x-base: expected")
                );
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            }
        }
    }

    fn gunzip(body: &[u8]) -> String {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(body), &mut text).unwrap();
        text
    }

    /// A static base, its stored gzip past the encoder cap, and a hook over it.
    pub(crate) async fn the_static_base_is_made_once_and_the_hook_overrides_it(spa: Spa) {
        let read =
            String::from_utf8(std::fs::read(format!("{BUNDLE}/index.html")).unwrap()).unwrap();
        let under = |base: &str| read.replace("<head>", &format!("<head><base href=\"{base}\">"));
        let spa = spa.base("/static/".parse().unwrap());

        let (response, body) = get_from(spa.clone(), "/settings", &[]).await;
        assert_eq!(String::from_utf8(body).unwrap(), under("/static/"));
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));

        let app = crate::standard_layers(
            Router::new()
                .route("/big", get(async || "x".repeat(4096)))
                .fallback_service(spa.clone()),
        );
        let gzipped = |path: &str| {
            app.clone().oneshot(
                Request::get(path)
                    .header(header::ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        let mut held = Vec::new();
        for _ in 0..crate::EncoderCap::DEFAULT {
            held.push(gzipped("/big").await.unwrap());
        }
        for path in ["/", "/settings"] {
            let page = gzipped(path).await.unwrap();
            assert_eq!(page.headers()[header::CONTENT_ENCODING], "gzip", "{path}");
            let body = page.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(gunzip(&body), under("/static/"), "{path}");
        }

        let hooked = based_on_header(spa);
        let (response, body) = get_from(
            hooked.clone(),
            "/settings",
            &[("x-base", "/named/"), ("accept-encoding", "gzip")],
        )
        .await;
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(String::from_utf8(body).unwrap(), under("/named/"));
        let (_, body) = get_from(hooked, "/settings", &[]).await;
        assert_eq!(String::from_utf8(body).unwrap(), under("/static/"));
    }

    #[tokio::test]
    async fn a_bundle_on_disk_makes_its_static_base_once_under_the_hook() {
        the_static_base_is_made_once_and_the_hook_overrides_it(Spa::from_dir(BUNDLE)).await;
    }

    #[tokio::test]
    async fn a_bundle_on_disk_serves_the_page_it_read_when_built() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(INDEX), "<head></head>").unwrap();
        let spa = Spa::from_dir(dir.path());
        std::fs::write(dir.path().join(INDEX), "<head>changed</head>").unwrap();
        assert_eq!(get_from(spa.clone(), "/", &[]).await.1, b"<head></head>");
        std::fs::remove_file(dir.path().join(INDEX)).unwrap();
        assert_eq!(get_from(spa, "/x", &[]).await.1, b"<head></head>");
    }

    #[tokio::test]
    async fn a_page_given_is_served_in_place_of_the_one_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(INDEX), "<head>on disk</head>").unwrap();
        let spa = Spa::from_dir_with_page(dir.path(), "<head>given</head>");
        for path in ["/", "/index.html", "/settings"] {
            assert_eq!(
                get_from(spa.clone(), path, &[]).await.1,
                b"<head>given</head>"
            );
        }
    }

    #[tokio::test]
    async fn a_page_its_gzip_would_not_shrink_is_sent_plain_for_the_compression_layer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(INDEX), "<p>").unwrap();
        for spa in [
            Spa::from_dir(dir.path()),
            Spa::from_dir(dir.path()).base("/x/".parse().unwrap()),
        ] {
            let (response, _) = get_from(spa, "/", &[("accept-encoding", "gzip")]).await;
            assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        }
    }

    #[test]
    fn the_reserved_rule_judges_the_resolved_first_segment() {
        for path in API_SHAPES {
            assert!(first_segment_is(path, "api"), "{path}");
        }
        for path in ["/", "/apiary", "/API/x", "/x/api", "/assets/api"] {
            assert!(!first_segment_is(path, "api"), "{path}");
        }
    }

    #[tokio::test]
    async fn a_bundle_on_disk_serves_its_page_under_the_hooks_base() {
        the_base_is_the_hooks(Spa::from_dir(BUNDLE)).await;
    }

    pub(crate) async fn a_bundle_without_its_page_answers_it_404(spa: Spa) {
        assert!(!spa.has_page());
        for spa in [spa.clone(), based_on_header(spa)] {
            for path in ["/", "/settings"] {
                let (response, body) = get_from(spa.clone(), path, &[("x-base", "/x/")]).await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["error"], "the bundle has no index.html");
            }
        }
    }

    #[tokio::test]
    async fn a_bundle_on_disk_without_its_page_answers_it_404() {
        a_bundle_without_its_page_answers_it_404(Spa::from_dir(format!("{BUNDLE}/assets"))).await;
        assert!(Spa::from_dir(BUNDLE).has_page());
    }

    /// Every encoder held by a route, then every stored copy out at once.
    pub(crate) async fn a_stored_copy_passes_the_cap(spa: Spa) {
        let app = crate::standard_layers(
            Router::new()
                .route("/big", get(async || "x".repeat(4096)))
                .fallback_service(spa),
        );
        let gzipped = |path: &str| {
            app.clone().oneshot(
                Request::get(path)
                    .header(header::ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        let encoding =
            |response: &Response| response.headers().get(header::CONTENT_ENCODING).cloned();

        let mut held = Vec::new();
        for _ in 0..crate::EncoderCap::DEFAULT {
            held.push(gzipped("/big").await.unwrap());
        }
        assert_eq!(
            encoding(&gzipped("/big").await.unwrap()),
            None,
            "every encoder is held"
        );
        for path in ["/assets/app-abc123.js", "/settings"] {
            let stored = gzipped(path).await.unwrap();
            assert_eq!(
                encoding(&stored).unwrap(),
                "gzip",
                "{path}: a stored copy needs none"
            );
        }
        drop(held);

        let mut stored = Vec::new();
        for _ in 0..=crate::EncoderCap::DEFAULT {
            stored.push(gzipped("/assets/app-abc123.js").await.unwrap());
        }
        assert_eq!(
            encoding(&gzipped("/big").await.unwrap()).unwrap(),
            "gzip",
            "past the cap in stored copies, an encoder is still free"
        );
    }

    #[tokio::test]
    async fn a_stored_copy_on_disk_passes_the_cap() {
        a_stored_copy_passes_the_cap(Spa::from_dir(BUNDLE)).await;
    }

    #[test]
    fn the_base_goes_first_in_the_head_else_after_the_doctype_else_first() {
        let based = |page: &str| {
            String::from_utf8(with_base(page.as_bytes(), "/apps/x/").to_vec()).unwrap()
        };
        assert_eq!(
            based("<!doctype html><html><HEAD lang=en><title>t</title></head><header>"),
            "<!doctype html><html><HEAD lang=en><base href=\"/apps/x/\"><title>t</title></head><header>"
        );
        assert_eq!(
            based("<!DOCTYPE html><header></header>"),
            "<!DOCTYPE html><base href=\"/apps/x/\"><header></header>"
        );
        assert_eq!(based("<p>bare</p>"), "<base href=\"/apps/x/\"><p>bare</p>");
    }

    #[test]
    fn a_base_already_in_the_head_is_pointed_at_the_path_keeping_its_other_attributes() {
        let based = |page: &str| {
            String::from_utf8(with_base(page.as_bytes(), "/apps/x/").to_vec()).unwrap()
        };
        assert_eq!(
            based("<head><base href=\"/\"><title>t</title></head>"),
            "<head><base href=\"/apps/x/\"><title>t</title></head>"
        );
        assert_eq!(
            based("<head><BASE target=\"_top\" HREF = './' /></head>"),
            "<head><BASE target=\"_top\" HREF = \"/apps/x/\" /></head>"
        );
        assert_eq!(
            based("<head><base href=/ui/></head>"),
            "<head><base href=\"/apps/x/\"></head>"
        );
        assert_eq!(
            based("<head><base target=\"_top\"></head>"),
            "<head><base href=\"/apps/x/\" target=\"_top\"></head>"
        );
        assert_eq!(
            based("<head></head><body><base href=\"/\"></body>"),
            "<head><base href=\"/apps/x/\"></head><body><base href=\"/\"></body>"
        );
    }

    #[tokio::test]
    async fn a_hashed_asset_answered_304_keeps_its_cache_control() {
        let spa = Spa::from_dir(BUNDLE);
        let (response, _) = get_from(spa.clone(), "/assets/app-abc123.js", &[]).await;
        let modified = response.headers()[header::LAST_MODIFIED]
            .to_str()
            .unwrap()
            .to_owned();
        let (unchanged, _) = get_from(
            spa,
            "/assets/app-abc123.js",
            &[("if-modified-since", &modified)],
        )
        .await;
        assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            unchanged.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
    }

    #[tokio::test]
    async fn a_range_is_of_the_plain_file() {
        let (response, body) = get_from(
            Spa::from_dir(BUNDLE),
            "/assets/app-abc123.js",
            &[("accept-encoding", "gzip"), ("range", "bytes=0-6")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(body, b"console");
    }

    #[tokio::test]
    async fn reserving_replaces_the_default_prefixes() {
        let spa = Spa::from_dir(BUNDLE).reserving(["auth", "metrics"]);
        assert_eq!(
            get_from(spa.clone(), "/auth/x", &[]).await.0.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_from(spa.clone(), "/%6detrics", &[]).await.0.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_from(spa, "/api/x", &[]).await.0.status(),
            StatusCode::OK
        );
    }

    #[test]
    fn the_first_segment_is_the_resolved_one() {
        for (path, first) in [
            ("/", None),
            ("//api/x", Some("api")),
            ("/./api", Some("api")),
            ("/x/../api/y", Some("api")),
            ("/x/y/../../api", Some("api")),
            ("/../../api", Some("api")),
            ("/x/..", None),
            ("/ui/./a/../b", Some("ui")),
        ] {
            assert_eq!(first_segment(path), first, "{path}");
        }
    }
}
