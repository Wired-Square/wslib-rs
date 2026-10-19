use std::any::Any;

use axum::Router;
use axum::response::{IntoResponse, Response};
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;
use wslib_http_error::ApiError;

/// `router` traced, gzipped, and answering a panic as a 500 error body.
///
/// Wraps only what `router` already holds, so call it after the last route
/// and the fallback.
pub fn standard_layers<S: Clone + Send + Sync + 'static>(router: Router<S>) -> Router<S> {
    router.layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CompressionLayer::new())
            .layer(CatchPanicLayer::custom(panicked)),
    )
}

fn panicked(payload: Box<dyn Any + Send>) -> Response {
    let cause = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a panic");
    ApiError::internal("answer the request", cause).into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::{StatusCode, header};
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn a_panic_is_answered_the_error_body() {
        let app = standard_layers(
            Router::new().route("/boom", get(async || -> &'static str { panic!("sekrit") })),
        );
        let response = app
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({ "error": "could not answer the request" })
        );
    }

    #[tokio::test]
    async fn a_large_body_is_gzipped_for_a_client_that_takes_it() {
        let app = standard_layers(Router::new().route("/big", get(async || "x".repeat(4096))));
        let response = app
            .oneshot(
                Request::get("/big")
                    .header(header::ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
    }
}
