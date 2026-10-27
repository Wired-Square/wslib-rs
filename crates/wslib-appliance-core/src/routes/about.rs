//! Settings › About: the build, the box, and whether each optional part came up.
//! `Admin`: versions are inventory an attacker reads to pick an exploit.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use wslib_appliance_types::about::AboutView;

use crate::extract::Admin;
use crate::procfs;
use crate::state::ApplianceState;

/// `now − uptime`, to the second, as the log ring's own `started_at` is.
fn started_at(uptime: std::time::Duration) -> chrono::DateTime<chrono::Utc> {
    use chrono::SubsecRound;
    (wslib_appliance_store::now() - chrono::Duration::from_std(uptime).unwrap_or_default())
        .trunc_subsecs(0)
}

pub(crate) fn routes() -> Router<ApplianceState> {
    Router::new().route("/about", get(view))
}

async fn view(Admin(_): Admin, State(app): State<ApplianceState>) -> Json<AboutView> {
    let product = app.about.rows(&app.store).await;

    // Read once, so the two fields derived from it cannot disagree.
    let uptime = app.logs.ring().uptime();
    let mut view = AboutView::default();
    view.product = app.about.product.clone();
    view.version = app.about.version.clone();
    view.daemon_uptime_s = uptime.as_secs();
    view.daemon_started_at = started_at(uptime);
    view.host_uptime_s = procfs::boottime().map(|up| up.as_secs());
    view.hostname = procfs::hostname();
    view.box_id = procfs::box_id();
    view.os = procfs::os_pretty_name();
    view.kernel = procfs::kernel_release();
    view.architecture = std::env::consts::ARCH.to_string();
    view.facts = product.facts;
    view.subsystems = product.subsystems;
    Json(view)
}
