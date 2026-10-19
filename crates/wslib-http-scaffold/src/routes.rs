use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderValue, header};
use axum::response::IntoResponse;
use axum::routing::get;
use wslib_api_error::ApiError;

pub const HEALTH: &str = "/healthz";
pub const VERSION: &str = "/version";

const JSON: [(header::HeaderName, HeaderValue); 1] = [(
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json"),
)];

/// `GET /healthz` answering `{"status":"ok"}` whenever the process can answer.
pub fn health<S: Clone + Send + Sync + 'static>() -> Router<S> {
    health_with(|| std::future::ready(Ok(())))
}

/// `GET /healthz` answering `{"status":"ok"}` while `ready` succeeds, else its error.
pub fn health_with<S, F, Fut>(ready: F) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    F: Fn() -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<(), ApiError>> + Send + 'static,
{
    Router::new().route(
        HEALTH,
        get(move || {
            let ready = ready();
            async move { ready.await.map(|()| (JSON, r#"{"status":"ok"}"#)) }
        }),
    )
}

/// `GET /version` answering `{"version": version, "build": build}`.
///
/// `build` is typically `env!("WSLIB_BUILD_ID")` from wslib-build-id's `emit`.
pub fn version<S: Clone + Send + Sync + 'static>(version: &str, build: &str) -> Router<S> {
    let body = Bytes::from(serde_json::json!({ "version": version, "build": build }).to_string());
    Router::new().route(
        VERSION,
        get(move || std::future::ready((JSON, body.clone()).into_response())),
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    async fn get_body(app: Router, path: &str) -> (StatusCode, serde_json::Value) {
        let response = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn health_is_ok_until_the_check_fails() {
        let ok = serde_json::json!({ "status": "ok" });
        assert_eq!(get_body(health(), HEALTH).await, (StatusCode::OK, ok));
        let down = health_with(|| async {
            Err(ApiError::unavailable(
                "reach the database",
                "connection refused",
            ))
        });
        assert_eq!(
            get_body(down, HEALTH).await,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({ "error": "could not reach the database" })
            )
        );
    }

    #[tokio::test]
    async fn version_names_the_release_and_the_build() {
        assert_eq!(
            get_body(version("0.1.0", "g4bf526d44891"), VERSION).await,
            (
                StatusCode::OK,
                serde_json::json!({ "version": "0.1.0", "build": "g4bf526d44891" })
            )
        );
    }
}
