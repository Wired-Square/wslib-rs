use axum::body::Bytes;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::{EmbeddedFile, RustEmbed};

use crate::Spa;
use crate::compress::{accepts_gzip, listed};
use crate::spa::{Files, INDEX};

pub(crate) type Lookup = fn(&str) -> Option<EmbeddedFile>;

impl Spa {
    /// The bundle compiled in by `#[derive(rust_embed::Embed)]`, under the same rules.
    pub fn embedded<E: RustEmbed>() -> Self {
        let page = E::get(INDEX).map(|page| Bytes::from(page.data.into_owned()));
        Self::of(Files::Embedded(E::get), page)
    }
}

/// The file `name`, or a bare 404.
pub(crate) fn serve(lookup: Lookup, name: &str, request: &Parts) -> Response {
    let method = &request.method;
    if method != Method::GET && method != Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET,HEAD")],
        )
            .into_response();
    }
    let Some(file) = lookup(name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let gzipped = accepts_gzip(&request.headers)
        .then(|| lookup(&format!("{name}.gz")))
        .flatten();
    let mime = HeaderValue::from_str(file.metadata.mimetype()).ok();
    let encoded = gzipped.is_some();
    let file = gzipped.unwrap_or(file);
    let tag = etag(&file);

    let mut response = if if_none_match(&request.headers, &tag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else if method == Method::HEAD {
        ().into_response()
    } else {
        file.data.into_owned().into_response()
    };
    let headers = response.headers_mut();
    headers.remove(header::CONTENT_TYPE);
    headers.extend(mime.map(|mime| (header::CONTENT_TYPE, mime)));
    if encoded {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    headers.insert(header::ETAG, tag);
    response
}

fn etag(file: &EmbeddedFile) -> HeaderValue {
    let hex: String = file.metadata.sha256_hash()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    HeaderValue::from_str(&format!("\"{hex}\"")).expect("hex is a valid header value")
}

fn if_none_match(headers: &HeaderMap, tag: &HeaderValue) -> bool {
    let tag = tag.to_str().unwrap_or_default();
    listed(headers, header::IF_NONE_MATCH)
        .any(|asked| asked == "*" || asked.trim_start_matches("W/") == tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spa::tests::{
        a_bundle_without_its_page_answers_it_404, a_stored_copy_passes_the_cap, get_from,
        rules_hold, the_base_is_the_hooks, the_static_base_is_made_once_and_the_hook_overrides_it,
    };

    #[derive(rust_embed::Embed)]
    #[folder = "tests/spa"]
    struct Bundle;

    #[tokio::test]
    async fn an_embedded_bundle_keeps_every_rule() {
        rules_hold(Spa::embedded::<Bundle>()).await;
    }

    #[derive(rust_embed::Embed)]
    #[folder = "tests/spa/assets"]
    struct Pageless;

    #[tokio::test]
    async fn an_embedded_bundle_without_its_page_answers_it_404() {
        a_bundle_without_its_page_answers_it_404(Spa::embedded::<Pageless>()).await;
    }

    #[tokio::test]
    async fn an_embedded_bundle_serves_its_page_under_the_hooks_base() {
        the_base_is_the_hooks(Spa::embedded::<Bundle>()).await;
    }

    #[tokio::test]
    async fn an_embedded_bundle_makes_its_static_base_once_under_the_hook() {
        the_static_base_is_made_once_and_the_hook_overrides_it(Spa::embedded::<Bundle>()).await;
    }

    #[tokio::test]
    async fn a_stored_copy_embedded_passes_the_cap() {
        a_stored_copy_passes_the_cap(Spa::embedded::<Bundle>()).await;
    }

    #[tokio::test]
    async fn a_matching_etag_is_answered_304_with_its_cache_control() {
        let spa = Spa::embedded::<Bundle>();
        let (response, _) = get_from(spa.clone(), "/assets/app-abc123.js", &[]).await;
        let tag = response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let (unchanged, body) =
            get_from(spa, "/assets/app-abc123.js", &[("if-none-match", &tag)]).await;
        assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
        assert!(body.is_empty());
        assert_eq!(
            unchanged.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
    }
}
