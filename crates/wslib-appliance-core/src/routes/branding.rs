//! What the appliance calls itself, served before anybody has signed in.

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::state::ApplianceState;
use crate::{ApiError, compress};

pub(crate) fn routes() -> Router<ApplianceState> {
    Router::new()
        .route("/branding", get(branding))
        .route("/branding/logo", get(logo))
}

/// **Public, deliberately**: the sign-in screen is branded. Nothing here may
/// read the database or carry more than the compiled-in branding, a build id
/// and, where the backend names the box, the hostname it already gives its
/// network. A matching `If-None-Match` is answered 304.
async fn branding(State(app): State<ApplianceState>, headers: HeaderMap) -> Response {
    let hostname = app.assets.names_the_box.then(crate::hostname).flatten();
    let branding = app.assets.branding.naming(hostname);
    let caching = [
        (header::ETAG, branding.etag.clone()),
        (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
    ];
    let response = if names(&headers, &branding.etag) {
        (StatusCode::NOT_MODIFIED, caching).into_response()
    } else {
        (
            caching,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            branding.body.clone(),
        )
            .into_response()
    };
    compress::negotiated(response)
}

/// The weak comparison RFC 9110 §13.1.2 prescribes for `If-None-Match`.
fn names(headers: &HeaderMap, etag: &HeaderValue) -> bool {
    fn opaque(tag: &str) -> &str {
        tag.strip_prefix("W/").unwrap_or(tag)
    }
    let Ok(current) = etag.to_str() else {
        return false;
    };
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|tag| tag == "*" || opaque(tag) == opaque(current))
}

/// **Public**, for the same reason: the logo is on the sign-in screen.
async fn logo(
    State(app): State<ApplianceState>,
    mut request: Request,
) -> Result<Response, ApiError> {
    let logo = app
        .assets
        .logo
        .as_ref()
        .ok_or_else(|| ApiError::NotFound("this appliance has no logo".to_string()))?;
    wslib_http_scaffold::restore_accept_encoding(&mut request);
    Ok(logo.respond(request.headers()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::backend::{Callers, LogsRung};
    use crate::testing::{Req, body_json};
    use crate::{AboveAdmin, Backend, Chassis, tls::Tls};

    #[tokio::test]
    async fn the_hostname_is_served_only_where_the_backend_names_the_box() {
        let dir = tempfile::tempdir().unwrap();
        for names_the_box in [true, false] {
            let store = wslib_appliance_store::Store::open(
                dir.path().join(format!("{names_the_box}.db")),
                None,
            )
            .await
            .expect("store");
            let built = Chassis::new(
                store,
                wslib_appliance_types::Branding::unbranded(),
                "0.0.0",
                crate::logs(&[]),
            )
            .build(Backend {
                callers: Callers::nobody(),
                logs: LogsRung::Admin,
                tls: Arc::new(Tls::none()),
                listening: None,
                onboarding: false,
                names_the_box,
                above_admin: AboveAdmin::Absent,
                routes: Vec::new(),
                control_routes: Vec::new(),
            })
            .await
            .expect("builds");
            let body = body_json(Req::new(built.https, "GET", "/api/branding").send().await).await;
            let expected = names_the_box.then(crate::hostname).flatten();
            assert_eq!(body["hostname"].as_str(), expected.as_deref());
        }
    }
}
