//! A built single-page app, where every unmatched path is `index.html` but
//! no path under a reserved prefix ever is.

use std::convert::Infallible;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use percent_encoding::percent_decode_str;
use tower::{Service, ServiceExt};
use tower_http::services::{ServeDir, ServeFile};
use wslib_http_error::ApiError;

pub(crate) const INDEX: &str = "index.html";
const ASSETS: &str = "assets";
const IMMUTABLE: HeaderValue = HeaderValue::from_static("public, max-age=31536000, immutable");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");

/// The app's bundle as a fallback service: mount it with `Router::fallback_service`.
///
/// `assets/` is cached for ever and a missing name there is a 404; everything
/// else is `no-store`, and a missing name is the page. A path under a reserved
/// prefix (`api` unless [`reserving`](Self::reserving) says otherwise) is a 404,
/// judged on the path after percent-decoding and dot segments.
#[derive(Clone)]
pub struct Spa {
    files: Arc<Files>,
    reserved: Arc<[String]>,
}

#[allow(clippy::large_enum_variant, reason = "built once, behind an Arc")]
pub(crate) enum Files {
    Disk {
        assets: ServeDir,
        files: ServeDir<ServeFile>,
    },
    #[cfg(feature = "embed")]
    Embedded(crate::embed::Lookup),
}

impl Spa {
    /// The bundle in `dir`, with a `.gz` beside a file sent to a client taking gzip.
    pub fn from_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        let serve = || {
            ServeDir::new(dir)
                .precompressed_gzip()
                .append_index_html_on_directories(false)
        };
        Self::of(Files::Disk {
            assets: serve(),
            files: serve().fallback(ServeFile::new(dir.join(INDEX)).precompressed_gzip()),
        })
    }

    pub(crate) fn of(files: Files) -> Self {
        Self {
            files: Arc::new(files),
            reserved: Arc::new(["api".to_owned()]),
        }
    }

    /// The first path segments that belong to routes and never to the bundle,
    /// replacing the default `api`.
    pub fn reserving(mut self, prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.reserved = prefixes.into_iter().map(Into::into).collect();
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

        // A range is of the plain file.
        if request.headers().contains_key(header::RANGE) {
            request.headers_mut().remove(header::ACCEPT_ENCODING);
        }
        let mut served = match &*self.files {
            Files::Disk { assets: dir, .. } if assets => {
                dir.clone().oneshot(request).await.into_response()
            }
            Files::Disk { files, .. } => files.clone().oneshot(request).await.into_response(),
            #[cfg(feature = "embed")]
            Files::Embedded(lookup) => crate::embed::serve(*lookup, &decoded, assets, &request),
        };
        let status = served.status();
        if status.is_client_error() || status.is_server_error() {
            return no_store(refusal(served, &method, &path));
        }
        let headers = served.headers_mut();
        headers.insert(
            header::CACHE_CONTROL,
            if assets { IMMUTABLE } else { NO_STORE },
        );
        headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
        served
    }
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

    #[tokio::test]
    async fn a_missing_page_is_the_error_body_not_an_empty_404() {
        let (response, body) =
            get_from(Spa::from_dir(format!("{BUNDLE}/assets")), "/settings", &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "no such file: /settings");
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
