use std::fmt;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use serde_json::Value;

use crate::ApiErrorBody;

/// A refused request: its status, its [`ApiErrorBody`] and any headers it
/// answers with.
#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    body: ApiErrorBody,
    headers: HeaderMap,
}

impl ApiError {
    pub fn new(status: StatusCode, sentence: impl Into<String>) -> Self {
        Self {
            status,
            body: ApiErrorBody::new(sentence),
            headers: HeaderMap::new(),
        }
    }

    pub fn bad_request(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, sentence)
    }

    pub fn unauthorised(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, sentence)
    }

    pub fn forbidden(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, sentence)
    }

    pub fn not_found(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, sentence)
    }

    pub fn method_not_allowed(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, sentence)
    }

    pub fn conflict(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, sentence)
    }

    pub fn payload_too_large(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, sentence)
    }

    pub fn unsupported_media_type(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, sentence)
    }

    pub fn unprocessable(sentence: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, sentence)
    }

    /// A 429 with `Retry-After` in whole seconds, rounded up.
    pub fn too_many_requests(sentence: impl Into<String>, retry_after: Duration) -> Self {
        let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
        Self::new(StatusCode::TOO_MANY_REQUESTS, sentence)
            .with_header(header::RETRY_AFTER, HeaderValue::from(seconds))
    }

    /// A 500 answering "could not {what}"; `cause` goes to the log, never the client.
    pub fn internal(what: &'static str, cause: impl fmt::Display) -> Self {
        Self::failed(StatusCode::INTERNAL_SERVER_ERROR, what, cause)
    }

    /// A 503 phrased and logged as [`internal`](Self::internal) is.
    pub fn unavailable(what: &'static str, cause: impl fmt::Display) -> Self {
        Self::failed(StatusCode::SERVICE_UNAVAILABLE, what, cause)
    }

    fn failed(status: StatusCode, what: &'static str, cause: impl fmt::Display) -> Self {
        tracing::error!(status = status.as_u16(), what, cause = %cause, "request failed");
        Self::new(status, format!("could not {what}"))
    }

    /// The app's own `snake_case` code for this refusal.
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.body.code = Some(code.into());
        self
    }

    /// A field of the app's own, beside `error` and `code` in the body.
    pub fn with_field(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.body.extra.insert(name.into(), value.into());
        self
    }

    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn body(&self) -> &ApiErrorBody {
        &self.body
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.body.error)
    }
}

impl std::error::Error for ApiError {}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, self.headers, axum::Json(self.body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_constructor_answers_its_status() {
        for (error, status) in [
            (ApiError::bad_request("x"), StatusCode::BAD_REQUEST),
            (ApiError::unauthorised("x"), StatusCode::UNAUTHORIZED),
            (ApiError::forbidden("x"), StatusCode::FORBIDDEN),
            (ApiError::not_found("x"), StatusCode::NOT_FOUND),
            (
                ApiError::method_not_allowed("x"),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (ApiError::conflict("x"), StatusCode::CONFLICT),
            (
                ApiError::payload_too_large("x"),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                ApiError::unsupported_media_type("x"),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                ApiError::unprocessable("x"),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                ApiError::too_many_requests("x", Duration::ZERO),
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                ApiError::internal("x", "y"),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ApiError::unavailable("x", "y"),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            assert_eq!(error.status(), status);
        }
    }

    #[test]
    fn an_internal_failure_names_the_attempt_and_not_the_cause() {
        let error = ApiError::internal("read the audit log", "no such column: sekrit in /var/x.db");
        assert_eq!(error.to_string(), "could not read the audit log");
        assert!(error.body().extra.is_empty());
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        let error = ApiError::too_many_requests("wait", Duration::from_millis(89_001));
        assert_eq!(error.headers()[header::RETRY_AFTER], "90");
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn the_response_carries_status_headers_and_body() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt;

        let response = ApiError::too_many_requests("slow down", Duration::from_secs(5))
            .with_code("rate_limited")
            .with_field("attempts", 6)
            .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "5");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            serde_json::json!({ "error": "slow down", "code": "rate_limited", "attempts": 6 })
        );
    }
}
