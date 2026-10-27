//! The built browser bundle, and the last word on a request when there is none.
//!
//! **Neither ever answers `/api/…`** (judged on the normalised path), so a
//! mistyped endpoint is a JSON 404, never `index.html`; nor does the bundle
//! answer `apps/…` or a route prefix.

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use tower::ServiceExt;
use wslib_http_scaffold::Spa;

use wslib_appliance_config::BasePath;

use crate::ApiError;

pub(crate) const INDEX: &str = "index.html";

/// The first path segment a console proxies its apps under.
const APPS: &str = "apps";

pub(crate) fn bundle(
    dir: &Path,
    page: Option<Vec<u8>>,
    base_path: BasePath,
    prefixes: Vec<String>,
) -> Spa {
    match page {
        Some(page) => Spa::from_dir_with_page(dir, page),
        None => Spa::from_dir(dir),
    }
    .reserving(["api", APPS].map(String::from).into_iter().chain(prefixes))
    .base(base_path)
    .base_from(wslib_homeassistant::ingress::spa_base)
}

/// A rewrite rather than `Router::nest`, whose wildcard never matches `<prefix>/` itself.
pub(crate) fn under(prefix: &str, routes: Router) -> Router {
    if prefix.is_empty() {
        return routes;
    }
    let prefix: Arc<str> = prefix.into();
    Router::new().fallback_service(tower::service_fn(move |mut request: Request| {
        let (prefix, routes) = (prefix.clone(), routes.clone());
        async move {
            let Some(uri) = without(request.uri(), &prefix) else {
                return Ok::<_, std::convert::Infallible>(fallback(request).await);
            };
            *request.uri_mut() = uri;
            routes.oneshot(request).await
        }
    }))
}

fn without(uri: &Uri, prefix: &str) -> Option<Uri> {
    let rest = uri.path().strip_prefix(prefix)?;
    let rest = match rest {
        "" => "/",
        rest if rest.starts_with('/') => rest,
        _ => return None,
    };
    let path_and_query = match uri.query() {
        Some(query) => format!("{rest}?{query}"),
        None => rest.to_string(),
    };
    path_and_query.parse().ok()
}

pub(crate) async fn fallback(request: Request) -> Response {
    let path = request.uri().path();
    let what = if wslib_http_scaffold::first_segment_is(path, "api") {
        "endpoint"
    } else {
        "path"
    };
    ApiError::NotFound(format!("no such {what}: {path}")).into_response()
}
