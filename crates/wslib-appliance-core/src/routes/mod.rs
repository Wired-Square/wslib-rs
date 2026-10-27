//! The `/api` surface this crate owns. Every route names its access, or says at the
//! handler why it takes none.

use axum::Router;
use axum::http::{Method, Uri};

use crate::ApiError;
use crate::state::ApplianceState;

pub(crate) mod about;
pub(crate) mod audit;
pub(crate) mod branding;
pub(crate) mod logs;
pub(crate) mod session;
pub(crate) mod tls;

/// `app` is merged before the fallback is set: two routers each carrying one panic.
pub(crate) fn api(app: Router<ApplianceState>, logs: logs::LogsRung) -> Router<ApplianceState> {
    Router::new()
        .merge(branding::routes())
        .merge(audit::routes())
        .merge(logs::routes(logs))
        .merge(about::routes())
        .merge(session::routes())
        .merge(app)
        .fallback(unknown_endpoint)
}

/// Trim a name; refuse one empty, over `max` characters, or forging an audit line.
pub fn clean_name(raw: &str, what: &str, max: usize) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest(format!("a {what} is required")));
    }
    if name.chars().count() > max {
        return Err(ApiError::BadRequest(format!(
            "a {what} may be at most {max} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "a {what} may not contain control characters"
        )));
    }
    Ok(name.to_string())
}

/// Without this the SPA fallback answers `/api/typo` with `index.html` and a 200.
async fn unknown_endpoint(uri: Uri) -> ApiError {
    ApiError::NotFound(format!("no such endpoint: /api{}", uri.path()))
}

/// Installed by `Chassis`'s assembly; unlike the 404 it sees the unstripped path.
pub(crate) async fn method_not_allowed(method: Method, uri: Uri) -> ApiError {
    ApiError::MethodNotAllowed(format!(
        "the {method} method is not allowed at {}",
        uri.path()
    ))
}
