//! A proxied app's backup, as its console calls it over the hooks socket:
//! capture, inspect and restore of the application half.
//!
//! The half crosses the socket unsealed, for the console to seal: the outbound
//! trust and the product's sections, never an account, an app role or a
//! setting. What comes back is caller input, checked as [`Bundle::open`] checks
//! a file. One capture or restore runs at a time, counting the proxied routes',
//! and one inspect; another is refused before its body is read.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, FromRef, FromRequestParts, State};
use axum::http::header;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use wslib_appliance_core::{ApiError, ApplianceState, BackupHooks, HookCaller, audit};
use wslib_appliance_types::backup::{MAX_BUNDLE_LEN, RestoreReport};
use wslib_appliance_types::hooks::{AppInspection, AppRestore};
use wslib_appliance_types::{TrustedCa, TrustedCert};

use crate::routes::{Engine, Restorer, Turn, bundle_sized, check_chosen, to_completion, try_take};
use crate::{BackupError, Bundle, Sections, Snapshot};

pub(crate) const APP_SECTIONS: &str = "appliance-app-sections";
pub(crate) const APP_SECTIONS_VERSION: u32 = 1;

/// The application half, as a capture answers it and a console hands it back.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppSections {
    pub(crate) format: String,
    pub(crate) version: u32,
    /// The product's system name.
    pub(crate) product: String,
    pub(crate) app_version: String,
    pub(crate) app_schema_version: u32,
    pub(crate) taken_at: DateTime<Utc>,
    pub(crate) trusted_certs: Vec<TrustedCert>,
    pub(crate) trusted_cas: Vec<TrustedCa>,
    pub(crate) app: BTreeMap<String, Value>,
}

impl AppSections {
    /// The format and version first, so a newer blob is refused as one. serde's
    /// message is never carried outward: it embeds the value.
    fn read(blob: Value) -> Result<Self, BackupError> {
        #[derive(Deserialize)]
        struct Tag {
            format: String,
            version: u32,
        }
        let tag = Tag::deserialize(&blob).map_err(|_| BackupError::NotABundle)?;
        if tag.format != APP_SECTIONS || tag.version == 0 {
            return Err(BackupError::NotABundle);
        }
        if tag.version > APP_SECTIONS_VERSION {
            return Err(BackupError::FormatTooNew {
                theirs: tag.version,
                ours: APP_SECTIONS_VERSION,
            });
        }
        Self::deserialize(blob).map_err(|_| BackupError::malformed("its sections did not parse"))
    }
}

/// Counts, as a bundle's is: nothing inside a section reaches a log line.
impl std::fmt::Debug for AppSections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let app: BTreeMap<&str, usize> = self
            .app
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_array().map_or(1, Vec::len)))
            .collect();
        f.debug_struct("AppSections")
            .field("product", &self.product)
            .field("app_version", &self.app_version)
            .field("trusted_certs", &self.trusted_certs.len())
            .field("trusted_cas", &self.trusted_cas.len())
            .field("app", &app)
            .finish()
    }
}

#[derive(Clone)]
struct Hooked<S> {
    app: ApplianceState,
    engine: Engine<S, ()>,
    inspecting: Arc<Semaphore>,
}

impl<S> FromRef<Hooked<S>> for ApplianceState {
    fn from_ref(state: &Hooked<S>) -> Self {
        state.app.clone()
    }
}

impl<S: Sections> Hooked<S> {
    fn opened(&self, blob: Value) -> Result<Bundle, BackupError> {
        let ours = self.app.store.app_schema_version();
        Bundle::from_console(AppSections::read(blob)?, &self.engine.name, ours)
    }
}

/// The inspect permit, taken before the body is read.
struct Inspecting {
    _held: OwnedSemaphorePermit,
}

impl<S: Sections> FromRequestParts<Hooked<S>> for Turn {
    type Rejection = ApiError;

    async fn from_request_parts(_: &mut Parts, hooked: &Hooked<S>) -> Result<Self, ApiError> {
        Self::take(&hooked.engine)
    }
}

impl<S: Sections> FromRequestParts<Hooked<S>> for Inspecting {
    type Rejection = ApiError;

    async fn from_request_parts(_: &mut Parts, hooked: &Hooked<S>) -> Result<Self, ApiError> {
        let _held = try_take(&hooked.inspecting, "inspecting a capture")?;
        Ok(Self { _held })
    }
}

pub(crate) fn mount<S: Sections>(engine: Engine<S, ()>) -> BackupHooks {
    let inspecting = Arc::new(Semaphore::new(1));
    let routes = Router::new()
        .route("/capture", post(capture::<S>))
        .route(
            "/inspect",
            post(inspect::<S>).layer(DefaultBodyLimit::max(MAX_BUNDLE_LEN)),
        )
        .route("/restore", post(restore::<S>).layer(bundle_sized()));
    BackupHooks::routes(routes, move |app| Hooked {
        app,
        engine: engine.clone(),
        inspecting: inspecting.clone(),
    })
}

async fn capture<S: Sections>(
    State(hooked): State<Hooked<S>>,
    _turn: Turn,
    who: HookCaller,
) -> Result<Response, ApiError> {
    let store = &hooked.app.store;
    let mut snapshot = Snapshot::capture_application(store).await?;
    snapshot
        .capture_sections(&hooked.engine.sections, store)
        .await?;
    let sections = snapshot.for_console(
        &hooked.engine.name,
        &hooked.engine.version,
        store.app_schema_version(),
    );
    let body = serde_json::to_vec(&sections)
        .map_err(|e| ApiError::internal("capture this app's sections", &e))?;
    if body.len() > MAX_BUNDLE_LEN {
        return Err(BackupError::TooLarge {
            limit: MAX_BUNDLE_LEN,
            actual: body.len(),
        }
        .into());
    }
    audit!(
        &hooked.app,
        &who,
        "captured this app's sections for the console"
    )
    .await;
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

async fn inspect<S: Sections>(
    State(hooked): State<Hooked<S>>,
    _turn: Inspecting,
    Json(blob): Json<Value>,
) -> Result<Json<AppInspection>, ApiError> {
    let bundle = hooked.opened(blob)?;
    let mut inspection = AppInspection::default();
    inspection.contains = bundle.header().contains.clone();
    let ours = hooked.engine.sections.names().await?;
    inspection.warnings = hooked.engine.warnings(&bundle, &ours);
    inspection.items = hooked.engine.items(&bundle, &ours);
    inspection.blocked = hooked
        .engine
        .blocked(&hooked.app.store, inspection.contains.app.keys())
        .await;
    Ok(Json(inspection))
}

async fn restore<S: Sections>(
    State(hooked): State<Hooked<S>>,
    turn: Turn,
    who: HookCaller,
    Json(body): Json<AppRestore<Value>>,
) -> Result<Json<RestoreReport>, ApiError> {
    if body.chosen != body.chosen.application_half() {
        return Err(ApiError::BadRequest(
            "a console restores an app's application half alone: its own sections and what \
             it trusts outbound"
                .to_string(),
        ));
    }
    check_chosen(&body.chosen)?;
    let bundle = hooked.opened(body.sections)?;
    let ours = hooked.engine.sections.names().await?;
    let carried = body.chosen.carried_by(&bundle.header().contains).app;
    hooked
        .engine
        .refuse_blocked(&hooked.app.store, &carried)
        .await?;
    let report = to_completion(&hooked.app.clone(), async move {
        let _turn = turn;
        hooked
            .engine
            .apply(
                &hooked.app,
                bundle,
                &body.chosen,
                &ours,
                Restorer::Console(&who),
            )
            .await
    })
    .await?;
    Ok(Json(report))
}

#[cfg(test)]
mod tests;
