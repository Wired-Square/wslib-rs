//! A session cookie this crate signs is nobody to a backend that does not
//! sign accounts in, even in a build where the `sessions` feature is on.

use std::sync::Arc;

use axum::http::StatusCode;
use wslib_appliance_core::backend::{self, Callers, LogsRung};
use wslib_appliance_core::testing::Req;
use wslib_appliance_core::{AboveAdmin, Backend, Chassis};
use wslib_appliance_types::Branding;

use crate::testing::{Harness, body_bytes};
use crate::tests::rungs;

const RUNGS: [&str; 6] = [
    "/api/rung/viewer",
    "/api/rung/operator",
    "/api/rung/admin",
    "/api/rung/hostadmin",
    "/api/rung/session-admin",
    "/api/session",
];

/// `request` is a 401 with `cookie` as it is without.
async fn refused_as_with_no_cookie(request: impl Fn() -> Req, cookie: &str, path: &str) {
    let signed_out = request().send().await;
    let named = request().cookie(cookie).send().await;
    assert_eq!(signed_out.status(), StatusCode::UNAUTHORIZED, "{path}");
    assert_eq!(named.status(), signed_out.status(), "{path}");
    assert_eq!(
        body_bytes(named).await,
        body_bytes(signed_out).await,
        "{path}"
    );
}

#[tokio::test]
async fn a_genuine_session_cookie_is_refused_by_every_rung_where_nobody_signs_in() {
    let signing = Harness::new().await;
    let cookie = signing.admin("admin").await;
    let store = signing.store().clone();
    let same_keys = Harness::builder().store(store.clone()).build().await;
    assert_eq!(
        same_keys
            .get("/api/session")
            .cookie(&cookie)
            .send()
            .await
            .status(),
        StatusCode::OK,
        "the cookie is genuine wherever this store's keys are read"
    );

    let callerless = Chassis::new(
        store.clone(),
        Branding::unbranded(),
        "0.0.0",
        crate::logs(&[]),
    )
    .api(rungs())
    .build(Backend {
        callers: Callers::nobody(),
        logs: LogsRung::SessionAdmin,
        tls: Arc::new(backend::no_tls()),
        listening: None,
        onboarding: false,
        names_the_box: false,
        above_admin: AboveAdmin::Present,
        routes: Vec::new(),
        control_routes: Vec::new(),
    })
    .await
    .expect("the backend builds")
    .https;
    let console = wslib_appliance_server::testing::Harness::builder()
        .store(store)
        .api(rungs())
        .build()
        .await;

    for path in RUNGS {
        refused_as_with_no_cookie(|| Req::new(callerless.clone(), "GET", path), &cookie, path)
            .await;
        refused_as_with_no_cookie(|| console.get(path), &cookie, path).await;
    }
}
