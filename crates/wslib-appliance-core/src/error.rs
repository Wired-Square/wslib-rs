//! One error body ([`ApiErrorBody`]), and one place a failure becomes a status code: the
//! `From` impls, never a handler. Axum's extractor rejections (`Json`, `Query`, `Path`)
//! fire before a handler and stay `text/plain`. [`ApiError::Internal`] renders only what
//! was being attempted; its cause goes to the journal through [`redact::foreign`].

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use wslib_appliance_auth::{AuthError, Ceremony};
use wslib_appliance_store::StoreError;
use wslib_appliance_types::ApiErrorBody;
use wslib_appliance_types::totp::ClockSkew;

use crate::redact;

/// Why a request was refused; it grows, so a `match` on it needs a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    /// The request was understood and is not usable. 400.
    #[error("{0}")]
    BadRequest(String),

    /// No usable session. 401, outwardly indistinguishable from [`ApiError::Refused`].
    #[error("not signed in")]
    Unauthenticated,

    /// A sign-in that did not produce an identity, whatever the cause: one answer. 401.
    #[error("the username or password is incorrect")]
    Refused,

    /// A wrong second-factor code. 403, since a browser takes 401 as a lost session.
    #[error("the code is incorrect")]
    WrongCode,

    /// A code refused for clock disagreement. 400, with the [`ClockSkew`] in the body.
    #[error("{0}")]
    ClockSkew(ClockSkew),

    /// A refused passkey sign-in. 401; a signed-in caller's refused passkey is a 403.
    #[error("the passkey was not accepted")]
    PasskeyRefused,

    /// Signed in, and not enough. 403.
    #[error("{0}")]
    Forbidden(String),

    /// A signed-in caller's proof was refused. 403, with `"proof": "refused"` in the
    /// body, as [`WrongCode`](ApiError::WrongCode) carries too.
    #[error("{0}")]
    ProofRefused(String),

    /// 404, including the JSON one `/api/*` gets instead of the SPA.
    #[error("{0}")]
    NotFound(String),

    /// 405, answered once for the surface. A `route_service`, `nest_service` or
    /// `any(…)` mount bypasses it and keeps axum's bare 405.
    #[error("{0}")]
    MethodNotAllowed(String),

    /// A write that conflicts with what is already there. 409.
    #[error("{0}")]
    Conflict(String),

    /// More than a parser will read. 413; an oversized body meets `DefaultBodyLimit` first.
    #[error("{0}")]
    PayloadTooLarge(String),

    /// Too many tries lately. 429, with `Retry-After` in whole seconds.
    #[error("{message}")]
    TooManyRequests {
        message: String,
        retry_after: std::time::Duration,
    },

    /// Something below the handler failed. 500. Build it with [`ApiError::internal`]:
    /// `#[non_exhaustive]` stops a struct literal outside this crate skipping the redaction.
    #[error("could not {context}")]
    #[non_exhaustive]
    Internal {
        /// A phrase this crate wrote, rendered outward.
        context: &'static str,
        /// Already sanitised; logged, never rendered.
        because: String,
    },

    /// Something the appliance depends on is not there: 503, "come back". Build it
    /// with [`ApiError::unavailable`], as [`Internal`](ApiError::Internal) is built.
    #[error("could not {context}")]
    #[non_exhaustive]
    Unavailable {
        context: &'static str,
        because: String,
    },

    /// A host the caller named did not answer as one. 502; the sentence is rendered.
    #[error("{0}")]
    BadGateway(String),

    /// This box has no way to do it, and the reason is the answer. 503. The sentence is
    /// rendered: write it by hand, never from a foreign `Display`.
    #[error("{0}")]
    Unsupported(String),
}

impl ApiError {
    /// A 500 whose cause reaches the journal, not the client. `context` completes
    /// "could not …" and is rendered, so it is a literal.
    pub fn internal(context: &'static str, because: &dyn std::fmt::Display) -> Self {
        Self::Internal {
            context,
            because: redact::foreign(because),
        }
    }

    /// A 503, with the same redaction and the same "could not …" phrasing.
    pub fn unavailable(context: &'static str, because: &dyn std::fmt::Display) -> Self {
        Self::Unavailable {
            context,
            because: redact::foreign(because),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::ClockSkew(_) => StatusCode::BAD_REQUEST,
            Self::Unauthenticated | Self::Refused | Self::PasskeyRefused => {
                StatusCode::UNAUTHORIZED
            }
            Self::Forbidden(_) | Self::WrongCode | Self::ProofRefused(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed(_) => StatusCode::METHOD_NOT_ALLOWED,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::Unavailable { .. } | Self::Unsupported(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// The one place an internal failure is logged, so it is logged exactly once.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal { context, because } | Self::Unavailable { context, because } = &self
        {
            tracing::error!(context, because, "request failed");
        }
        let sentence = self.to_string();
        match self {
            Self::ClockSkew(skew) => wslib_http_error::ApiError::bad_request(sentence)
                .with_field("clock_skew", serde_json::json!(skew)),
            Self::TooManyRequests { retry_after, .. } => {
                wslib_http_error::ApiError::too_many_requests(sentence, retry_after)
            }
            Self::WrongCode | Self::ProofRefused(_) => {
                wslib_http_error::ApiError::new(StatusCode::FORBIDDEN, sentence)
                    .with_field("proof", "refused")
            }
            other => wslib_http_error::ApiError::new(other.status(), sentence),
        }
        .into_response()
    }
}

/// Answers a response carrying an [`ApiErrorBody`] extension as an HTML page when
/// `Accept` names `text/html` without `q=0`. It marks such responses `Vary: Accept`
/// and removes the marker, so a second layer leaves them alone.
pub(crate) async fn as_page(request: Request, next: Next) -> Response {
    let navigation = names_html(request.headers());
    let mut response = next.run(request).await;
    let Some(ApiErrorBody { error: message, .. }) = response.extensions_mut().remove() else {
        return response;
    };
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("accept"));
    if !navigation {
        return response;
    }
    let (mut parts, _) = response.into_parts();
    parts.headers.remove(header::CONTENT_ENCODING);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    let page = format!(
        "<!doctype html>\n<html lang=\"en\">\n<meta charset=\"utf-8\">\n<title>{status}</title>\n\
         <h1>{status}</h1>\n<p>{message}</p>\n</html>\n",
        status = parts.status,
        message = escaped(&message),
    );
    Response::from_parts(parts, Body::from(page))
}

fn names_html(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|range| {
            let mut parts = range.split(';');
            let html = parts
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/html"));
            html && !parts.any(refuses)
        })
}

fn refuses(parameter: &str) -> bool {
    parameter.split_once('=').is_some_and(|(name, value)| {
        name.trim().eq_ignore_ascii_case("q") && value.trim().parse::<f32>() == Ok(0.0)
    })
}

fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NoSuchUser(id) => Self::NotFound(format!("no such user: {id}")),
            StoreError::UsernameTaken(name) => {
                Self::Conflict(format!("the username {name:?} is already taken"))
            }
            StoreError::LastHostAdmin | StoreError::PasskeyTaken => Self::Conflict(e.to_string()),
            StoreError::HostAdminsOnly => Self::Forbidden(e.to_string()),
            StoreError::NotAnAppRole => Self::BadRequest(e.to_string()),
            // A cursor arrives from a query string: the caller's mistake.
            StoreError::BadCursor(_) => {
                Self::BadRequest("that cursor did not come from this appliance".to_string())
            }
            other => Self::internal("reach the database", &other),
        }
    }
}

/// Certificate refusals only: a warning installs, and its report carries the sentence.
impl From<crate::tls::TlsError> for ApiError {
    fn from(e: crate::tls::TlsError) -> Self {
        use crate::tls::TlsError::*;
        match e {
            Pem(_) | Mismatched | Unloadable(_) | Target(_) => Self::BadRequest(e.to_string()),

            TooLong { .. } => Self::PayloadTooLarge(e.to_string()),

            // 503 rather than 403: nothing about the caller is wrong.
            Unsupported(_) => Self::Unsupported(e.to_string()),

            Unreachable(_) => Self::BadGateway(e.to_string()),

            Unwritable { .. } => Self::internal("write the certificate", &e),

            // Transient: installing again serves it now.
            Unfinished { .. } => Self::unavailable("finish installing the certificate", &e),
            Internal(_) => Self::internal("read or write the certificate", &e),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Refused => Self::Refused,
            AuthError::NoSession => Self::Unauthenticated,
            AuthError::PasswordTooShort(n) => {
                Self::BadRequest(format!("the password must be at least {n} characters"))
            }
            AuthError::PasswordTooLong(n) => {
                Self::BadRequest(format!("the password must be at most {n} bytes"))
            }
            AuthError::CodeRefused => Self::WrongCode,
            AuthError::ClockSkew(skew) => Self::ClockSkew(skew),
            AuthError::TooManyCodes(retry_after) => Self::TooManyRequests {
                message: e.to_string(),
                retry_after,
            },
            AuthError::TotpAlreadyOn
            | AuthError::TotpNotEnrolled
            | AuthError::NoPasskeysHere(_) => Self::Conflict(e.to_string()),
            AuthError::PasskeyRefused(Ceremony::SignIn)
            | AuthError::PasskeyCounterDidNotMove(Ceremony::SignIn) => Self::PasskeyRefused,
            AuthError::PasskeyRefused(Ceremony::Registration)
            | AuthError::PasskeyCounterDidNotMove(Ceremony::Registration) => {
                Self::Forbidden(e.to_string())
            }
            AuthError::CodeUsed
            | AuthError::PasskeyRefused(_)
            | AuthError::PasskeyCounterDidNotMove(_) => Self::ProofRefused(e.to_string()),
            AuthError::NotOnAnIpAddress | AuthError::BadHost | AuthError::PasskeyName => {
                Self::BadRequest(e.to_string())
            }
            AuthError::Store(e) => e.into(),
            other => Self::internal("complete the sign-in", &other),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::routing::get;
    use axum::{Json, Router};

    use super::*;
    use crate::testing::{Req, body_json, body_text, varies};

    #[tokio::test]
    async fn every_refusal_answers_in_the_one_body_a_client_parses() {
        for (error, expected) in [
            (ApiError::BadRequest("bad".into()), StatusCode::BAD_REQUEST),
            (ApiError::Unauthenticated, StatusCode::UNAUTHORIZED),
            (ApiError::Refused, StatusCode::UNAUTHORIZED),
            (ApiError::WrongCode, StatusCode::FORBIDDEN),
            (ApiError::PasskeyRefused, StatusCode::UNAUTHORIZED),
            (ApiError::Forbidden("no".into()), StatusCode::FORBIDDEN),
            (ApiError::ProofRefused("no".into()), StatusCode::FORBIDDEN),
            (ApiError::NotFound("gone".into()), StatusCode::NOT_FOUND),
            (
                ApiError::MethodNotAllowed("the PATCH method is not allowed here".into()),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (ApiError::Conflict("taken".into()), StatusCode::CONFLICT),
            (
                ApiError::PayloadTooLarge("that file is larger than 8 MiB".into()),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                ApiError::TooManyRequests {
                    message: "slow down".into(),
                    retry_after: std::time::Duration::from_secs(5),
                },
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                ApiError::Unsupported("there is no system D-Bus here".into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let rendered = error.to_string();
            let response = error.into_response();
            assert_eq!(response.status(), expected);

            let body = body_json(response).await;
            assert_eq!(
                body["error"], rendered,
                "the body must carry the same sentence the error renders"
            );
        }
    }

    #[tokio::test]
    async fn an_internal_failure_names_the_attempt_and_nothing_underneath_it() {
        let error = ApiError::internal(
            "reach the database",
            &"no such column: sekrit_value in /var/lib/x.db",
        );
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = body_json(response).await;
        assert_eq!(body["error"], "could not reach the database");
        assert!(
            !body["error"].as_str().unwrap().contains("sekrit_value"),
            "{body}"
        );
    }

    #[test]
    fn an_internal_cause_is_sanitised_as_it_is_built_not_as_it_is_logged() {
        let ApiError::Internal { because, .. } = ApiError::internal(
            "notify",
            &"error sending request for url (https://hook:s3cr3t@example.invalid/x)",
        ) else {
            panic!("internal builds an Internal")
        };
        assert!(!because.contains("s3cr3t"), "{because}");
    }

    #[test]
    fn a_store_failure_keeps_the_distinctions_a_client_can_act_on() {
        assert!(matches!(
            ApiError::from(StoreError::NoSuchUser("x".into())),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            ApiError::from(StoreError::UsernameTaken("admin".into())),
            ApiError::Conflict(_)
        ));
        assert!(matches!(
            ApiError::from(StoreError::Unreadable {
                table: "users",
                what: "role",
                because: "superuser".into(),
            }),
            ApiError::Internal { .. }
        ));
    }

    #[test]
    fn the_three_sign_in_refusals_stay_one_answer_through_the_mapping() {
        let e = ApiError::from(AuthError::Refused);
        assert!(matches!(e, ApiError::Refused));
        assert_eq!(e.to_string(), "the username or password is incorrect");
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            ApiError::from(AuthError::NoSession).status(),
            StatusCode::UNAUTHORIZED,
            "and a missing session is indistinguishable from a bad password"
        );
    }

    #[test]
    fn a_second_factor_refusal_answers_its_own_status_and_sentence() {
        use wslib_appliance_types::totp::ClockSkew;
        for (error, status) in [
            (AuthError::CodeRefused, StatusCode::FORBIDDEN),
            (AuthError::CodeUsed, StatusCode::FORBIDDEN),
            (
                AuthError::ClockSkew(ClockSkew { minutes: -7 }),
                StatusCode::BAD_REQUEST,
            ),
            (AuthError::TotpAlreadyOn, StatusCode::CONFLICT),
            (AuthError::TotpNotEnrolled, StatusCode::CONFLICT),
            (
                AuthError::TooManyCodes(std::time::Duration::from_secs(90)),
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                AuthError::PasskeyRefused(Ceremony::SignIn),
                StatusCode::UNAUTHORIZED,
            ),
            (
                AuthError::PasskeyCounterDidNotMove(Ceremony::SignIn),
                StatusCode::UNAUTHORIZED,
            ),
            (
                AuthError::PasskeyRefused(Ceremony::Reauthentication),
                StatusCode::FORBIDDEN,
            ),
            (
                AuthError::PasskeyCounterDidNotMove(Ceremony::Reauthentication),
                StatusCode::FORBIDDEN,
            ),
            (
                AuthError::PasskeyRefused(Ceremony::Registration),
                StatusCode::FORBIDDEN,
            ),
            (AuthError::NotOnAnIpAddress, StatusCode::BAD_REQUEST),
            (AuthError::BadHost, StatusCode::BAD_REQUEST),
            (AuthError::PasskeyName, StatusCode::BAD_REQUEST),
            (
                AuthError::NoPasskeysHere("box.local".into()),
                StatusCode::CONFLICT,
            ),
        ] {
            let sentence = error.to_string();
            let e = ApiError::from(error);
            assert_eq!(e.status(), status, "{sentence}");
            assert_eq!(e.to_string(), sentence);
        }
        assert!(matches!(
            ApiError::from(AuthError::Random),
            ApiError::Internal { .. }
        ));
    }

    #[tokio::test]
    async fn a_clock_skew_carries_its_minutes_beside_its_sentence() {
        use wslib_appliance_types::totp::ClockSkew;
        let skew = ClockSkew { minutes: -7 };
        let response = ApiError::from(AuthError::ClockSkew(skew)).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ApiErrorBody = serde_json::from_value(body_json(response).await).unwrap();
        assert_eq!(
            body.extra["clock_skew"],
            serde_json::json!({ "minutes": -7 })
        );
        assert_eq!(body.error, skew.to_string());

        let plain = body_json(ApiError::BadRequest("bad".into()).into_response()).await;
        assert!(plain.get("clock_skew").is_none(), "{plain}");
    }

    #[test]
    fn too_many_codes_says_when_to_come_back_in_whole_seconds() {
        let response = ApiError::from(AuthError::TooManyCodes(std::time::Duration::from_millis(
            89_001,
        )))
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "90");
    }

    const NAVIGATION: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    fn app() -> Router {
        Router::new()
            .route(
                "/refused",
                get(async || ApiError::Forbidden("<script>alert('x')</script> & \"so\"".into())),
            )
            .route(
                "/slow",
                get(async || ApiError::TooManyRequests {
                    message: "wait".into(),
                    retry_after: std::time::Duration::from_secs(3),
                }),
            )
            .route(
                "/fine",
                get(async || Json(serde_json::json!({ "error": "<b>" }))),
            )
            .layer(axum::middleware::from_fn(as_page))
    }

    async fn asking(path: &str, accept: &str) -> Response {
        Req::new(app(), "GET", path)
            .header("accept", accept)
            .send()
            .await
    }

    #[tokio::test]
    async fn a_navigation_is_answered_a_page_with_the_sentence_escaped() {
        let response = asking("/refused", NAVIGATION).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(varies(&response), [b"accept"]);
        let page = body_text(response).await;
        assert!(
            page.contains(
                "<p>&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;so&quot;</p>"
            ),
            "{page}"
        );
        assert!(!page.contains("<script>"), "{page}");
        assert!(page.contains("<meta charset=\"utf-8\">"), "{page}");
    }

    #[tokio::test]
    async fn text_html_at_q_zero_is_a_refusal_and_keeps_the_json_body() {
        for accept in [
            "text/html;q=0, application/json",
            "text/html; Q=0.0",
            "TEXT/HTML ; q = 0.000",
            "text/html;q=0.",
        ] {
            let response = asking("/refused", accept).await;
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "application/json",
                "{accept}"
            );
        }
        let response = asking("/refused", "text/html;q=0.1").await;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn fetch_and_a_json_client_keep_the_json_body() {
        for accept in ["*/*", "application/json"] {
            let response = asking("/refused", accept).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(varies(&response), [b"accept"]);
            assert_eq!(
                body_json(response).await["error"],
                "<script>alert('x')</script> & \"so\"",
                "{accept}"
            );
        }
    }

    #[tokio::test]
    async fn a_page_keeps_the_headers_the_error_set() {
        let response = asking("/slow", NAVIGATION).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "3");
        assert!(body_text(response).await.contains("<p>wait</p>"));
    }

    #[tokio::test]
    async fn a_second_layer_leaves_the_page_and_its_vary_alone() {
        let twice = app().layer(axum::middleware::from_fn(as_page));
        let response = Req::new(twice, "GET", "/refused")
            .header("accept", NAVIGATION)
            .send()
            .await;
        assert_eq!(varies(&response), [b"accept"]);
        let page = body_text(response).await;
        assert_eq!(page.matches("<!doctype html>").count(), 1, "{page}");
        assert!(page.contains("&lt;script&gt;"), "escaped once: {page}");
    }

    #[tokio::test]
    async fn a_response_that_is_not_an_api_error_is_left_alone() {
        let response = asking("/fine", NAVIGATION).await;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert!(varies(&response).is_empty());
        assert_eq!(body_json(response).await["error"], "<b>");
    }
}
