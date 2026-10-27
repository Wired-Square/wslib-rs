//! Reading the durable record of what was done to this box.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use wslib_appliance_types::{AuditRecord, Page};

use crate::ApiError;
use crate::extract::Admin;
use crate::state::ApplianceState;

/// Not `MAX_AUDIT_PAGE`, the ceiling the store clamps to: the default request stays cheap.
const DEFAULT_PAGE: u32 = 100;

pub(crate) fn routes() -> Router<ApplianceState> {
    Router::new().route("/audit", get(list))
}

#[derive(Debug, Deserialize)]
struct Paging {
    limit: Option<u32>,
    cursor: Option<String>,
}

/// **Admin**: reading who did what is a different privilege from acting on the box.
async fn list(
    Admin(_): Admin,
    State(app): State<ApplianceState>,
    Query(paging): Query<Paging>,
) -> Result<Json<Page<AuditRecord>>, ApiError> {
    let limit = paging.limit.unwrap_or(DEFAULT_PAGE);
    Ok(Json(
        app.store.audit(limit, paging.cursor.as_deref()).await?,
    ))
}
