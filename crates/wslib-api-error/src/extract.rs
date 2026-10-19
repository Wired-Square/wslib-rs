//! axum's `Json`, `Query` and `Path`, refusing with an [`ApiError`] at the
//! status axum chose.

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{Method, Uri};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::ApiError;

macro_rules! from_rejection {
    ($($rejection:ty),+) => {$(
        impl From<$rejection> for ApiError {
            fn from(rejection: $rejection) -> Self {
                Self::new(rejection.status(), rejection.body_text())
            }
        }
    )+};
}

from_rejection!(JsonRejection, QueryRejection, PathRejection);

/// A JSON body in, refused as 400, 413, 415 or 422; a JSON body out.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for Json<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        let axum::Json(value) = axum::Json::from_request(request, state).await?;
        Ok(Self(value))
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Query<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequestParts<S> for Query<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let axum::extract::Query(value) =
            axum::extract::Query::from_request_parts(parts, state).await?;
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Path<T>(pub T);

impl<T: DeserializeOwned + Send, S: Send + Sync> FromRequestParts<S> for Path<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let axum::extract::Path(value) =
            axum::extract::Path::from_request_parts(parts, state).await?;
        Ok(Self(value))
    }
}

/// For `Router::method_not_allowed_fallback`; axum still sets `Allow`.
///
/// It covers routes added with `route` and `nest`, not `route_service`,
/// `nest_service` or `any`.
pub async fn method_not_allowed(method: Method, uri: Uri) -> ApiError {
    ApiError::method_not_allowed(format!(
        "the {method} method is not allowed at {}",
        uri.path()
    ))
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{StatusCode, header};
    use axum::routing::{get, post};
    use http_body_util::BodyExt;
    use serde::Deserialize;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    #[derive(Deserialize, Serialize)]
    struct Thing {
        n: u8,
    }

    fn app() -> Router {
        Router::new()
            .route("/json", post(async |Json(thing): Json<Thing>| Json(thing)))
            .route(
                "/query",
                get(async |Query(thing): Query<Thing>| thing.n.to_string()),
            )
            .route("/path/{n}", get(async |Path(n): Path<u8>| n.to_string()))
            .layer(axum::extract::DefaultBodyLimit::max(64))
            .method_not_allowed_fallback(method_not_allowed)
    }

    async fn send(
        method: &str,
        uri: &str,
        content_type: Option<&str>,
        body: &str,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let response = app()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    const JSON: Option<&str> = Some("application/json");

    #[tokio::test]
    async fn each_rejection_answers_the_body_at_axums_status() {
        let long = format!("{{\"n\":1,\"pad\":\"{}\"}}", "x".repeat(100));
        for (method, uri, content_type, body, status) in [
            ("POST", "/json", JSON, "{", StatusCode::BAD_REQUEST),
            (
                "POST",
                "/json",
                JSON,
                "{\"n\":\"x\"}",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "POST",
                "/json",
                None,
                "{\"n\":1}",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                "POST",
                "/json",
                JSON,
                long.as_str(),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            ("GET", "/query?n=abc", None, "", StatusCode::BAD_REQUEST),
            ("GET", "/path/300", None, "", StatusCode::BAD_REQUEST),
        ] {
            let (answered, body) = send(method, uri, content_type, body).await;
            assert_eq!(answered, status, "{method} {uri} {body}");
            assert!(
                body["error"].as_str().is_some_and(|e| !e.is_empty()),
                "{uri} {body}"
            );
        }
    }

    #[tokio::test]
    async fn accepted_input_reaches_the_handler() {
        assert_eq!(
            send("POST", "/json", JSON, "{\"n\":7}").await,
            (StatusCode::OK, serde_json::json!({ "n": 7 }))
        );
        assert_eq!(send("GET", "/path/9", None, "").await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_wrong_method_names_itself_and_the_path_and_keeps_allow() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(response.headers().contains_key(header::ALLOW));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "the PATCH method is not allowed at /json");
    }
}
