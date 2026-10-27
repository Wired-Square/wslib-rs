//! An assembled appliance with a route behind every rung and behind [`Unclaimed`],
//! for this crate's own tests: `wslib-appliance-server`'s harness would link a second
//! copy of this crate.

use std::convert::identity;
use std::sync::Arc;

use axum::Router;
use axum::extract::Path;
use axum::http::request::Parts;
use axum::response::Response;
use axum::routing::get;
use tempfile::TempDir;
use wslib_appliance_store::Store;
use wslib_appliance_types::{Branding, Role};

use crate::backend::{Callers, LogsRung};
use crate::testing::Req;
use crate::tls::Tls;
use crate::{
    AboveAdmin, Admin, ApiError, Backend, Chassis, ControlRouter, HostAdmin, Mount, Operator,
    Principal, RequestBase, ResolveCaller, SessionAdmin, Unclaimed, Viewer, host_admin_only,
};

/// The header [`StoreAccounts`] reads an account id from.
pub(crate) const ACCOUNT: &str = "x-probe-account";

/// Vouches for the enabled store account named in [`ACCOUNT`], re-authenticated just now.
struct StoreAccounts(Store);

impl ResolveCaller for StoreAccounts {
    async fn resolve(&self, request: &Parts) -> Result<Option<Principal>, ApiError> {
        let Some(id) = request.headers.get(ACCOUNT).and_then(|v| v.to_str().ok()) else {
            return Ok(None);
        };
        Ok(self
            .0
            .user_by_id(id)
            .await?
            .map(|account| account.user)
            .filter(|user| user.enabled)
            .map(|user| Principal {
                id: user.id,
                username: user.username,
                role: user.role,
                reauthenticated_at: Some(chrono::Utc::now()),
            }))
    }
}

/// The [`ServingPort`](crate::ServingPort) the probe marks every request with.
pub(crate) const PORT: u16 = 8443;

pub(crate) const SESSION_ADMIN: &str = "/api/probe/session-admin";
/// A Viewer route behind [`host_admin_only`].
pub(crate) const RAISED: &str = "/api/probe/raised";
pub(crate) const UNCLAIMED: &str = "/api/probe/unclaimed";
/// Answers the Viewer rung's [`Identity::actor`](crate::Identity::actor).
pub(crate) const WHO: &str = "/api/probe/who";
/// Answers the [`RequestBase`].
pub(crate) const BASE: &str = "/api/probe/base";
/// Answers the Viewer rung's [`Identity::is_host_admin`](crate::Identity::is_host_admin).
pub(crate) const IS_HOST_ADMIN: &str = "/api/probe/is-host-admin";

/// Answers the Viewer rung's [`Identity::satisfies`](crate::Identity::satisfies).
pub(crate) fn satisfies(role: Role) -> String {
    format!("/api/probe/satisfies/{role}")
}

/// A uid no test box gives a name.
#[cfg(unix)]
pub(crate) const NAMELESS_UID: u32 = 2_147_483_647;

pub(crate) fn rung(role: Role) -> String {
    format!("/api/probe/{role}")
}

pub(crate) struct Probe {
    pub(crate) https: Router,
    pub(crate) control: ControlRouter,
    store: Store,
    _dir: TempDir,
}

impl Probe {
    /// Callers resolved to the store's accounts, and the log at [`SessionAdmin`].
    pub(crate) async fn new() -> Self {
        Self::hosting(AboveAdmin::Present, Vec::new(), identity).await
    }

    /// [`new`](Self::new) under `above_admin`, with `host` mounted and `chassis` adding a product's own.
    pub(crate) async fn hosting(
        above_admin: AboveAdmin,
        host: Vec<Mount>,
        chassis: impl FnOnce(Chassis) -> Chassis,
    ) -> Self {
        let logs = LogsRung::SessionAdmin;
        let callers = |store: &Store| Callers::resolved_from_store(StoreAccounts(store.clone()));
        Self::build(callers, logs, above_admin, host, chassis, true).await
    }

    /// Callers the ingress proxy asserts, held as `serve_ingress` holds them.
    pub(crate) async fn ingress(
        first_sight: impl Fn(&str) -> Option<Role> + Send + Sync + 'static,
        chassis: impl FnOnce(Chassis) -> Chassis,
    ) -> Self {
        let callers = |store: &Store| Callers::asserted_by_ingress(store.clone(), first_sight);
        let (logs, above_admin) = (LogsRung::SessionAdmin, AboveAdmin::Absent);
        Self::build(callers, logs, above_admin, Vec::new(), chassis, true).await
    }

    /// Nobody tells callers apart: only a control socket gets in.
    pub(crate) async fn callerless(logs: LogsRung) -> Self {
        Self::build(
            |_| Callers::nobody(),
            logs,
            AboveAdmin::Present,
            Vec::new(),
            identity,
            true,
        )
        .await
    }

    pub(crate) async fn with_callers(callers: Callers, onboarding: bool) -> Self {
        let (logs, above_admin) = (LogsRung::SessionAdmin, AboveAdmin::Present);
        Self::build(
            |_| callers,
            logs,
            above_admin,
            Vec::new(),
            identity,
            onboarding,
        )
        .await
    }

    /// `resolver` tells callers apart, not declared to vouch for the store's accounts.
    pub(crate) async fn resolving(resolver: impl ResolveCaller) -> Self {
        Self::resolving_under(AboveAdmin::Present, resolver).await
    }

    /// [`resolving`](Self::resolving), with `host` mounted.
    pub(crate) async fn resolving_hosting(resolver: impl ResolveCaller, host: Vec<Mount>) -> Self {
        let callers = |_: &Store| Callers::resolved_by(resolver);
        let (logs, above_admin) = (LogsRung::SessionAdmin, AboveAdmin::Present);
        Self::build(callers, logs, above_admin, host, identity, true).await
    }

    pub(crate) async fn resolving_under(
        above_admin: AboveAdmin,
        resolver: impl ResolveCaller,
    ) -> Self {
        let callers = |_: &Store| Callers::resolved_by(resolver);
        let logs = LogsRung::SessionAdmin;
        Self::build(callers, logs, above_admin, Vec::new(), identity, true).await
    }

    pub(crate) async fn build(
        callers: impl FnOnce(&Store) -> Callers,
        logs: LogsRung,
        above_admin: AboveAdmin,
        host_routes: Vec<Mount>,
        shape: impl FnOnce(Chassis) -> Chassis,
        onboarding: bool,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("db"), None)
            .await
            .expect("store");
        let callers = callers(&store);
        let tls = Arc::new(Tls::minted_in(&dir).await);
        let routes = Router::new()
            .route("/probe/viewer", get(|_: Viewer| async {}))
            .route("/probe/operator", get(|_: Operator| async {}))
            .route("/probe/admin", get(|_: Admin| async {}))
            .route("/probe/hostadmin", get(|_: HostAdmin| async {}))
            .route("/probe/session-admin", get(|_: SessionAdmin| async {}))
            .route("/probe/unclaimed", get(|_: Unclaimed| async {}))
            .route(
                "/probe/who",
                get(|Viewer(who): Viewer| async move { who.actor().to_owned() }),
            )
            .route(
                "/probe/base",
                get(|RequestBase(base): RequestBase| async move { base.to_string() }),
            )
            .route(
                "/probe/is-host-admin",
                get(|Viewer(who): Viewer| async move { who.is_host_admin().to_string() }),
            )
            .route(
                "/probe/satisfies/{role}",
                get(|Viewer(who): Viewer, Path(role): Path<Role>| async move {
                    who.satisfies(role).to_string()
                }),
            )
            .merge(host_admin_only(
                Router::new().route("/probe/raised", get(|_: Viewer| async {})),
            ));
        let chassis = Chassis::new(
            store.clone(),
            Branding::unbranded(),
            "0.0.0",
            crate::logs(&[]),
        )
        .api(routes);
        let built = shape(chassis)
            .build(Backend {
                callers,
                logs,
                tls,
                listening: None,
                onboarding,
                names_the_box: false,
                above_admin,
                routes: host_routes,
                control_routes: Vec::new(),
            })
            .await
            .expect("the chassis builds");
        Self {
            https: built.https.layer(axum::Extension(crate::ServingPort(PORT))),
            control: built.control,
            store,
            _dir: dir,
        }
    }

    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    /// The id of a new administrator's account on this box.
    pub(crate) async fn admin_token(&self) -> String {
        self.token(Role::Admin).await
    }

    /// [`admin_token`](Self::admin_token), for an account named and ranked `role`.
    pub(crate) async fn token(&self, role: Role) -> String {
        self.store
            .create_user(role.as_str(), "unverified", role)
            .await
            .expect("an account")
            .id
    }

    /// `GET path` without local authority, naming the account `token` if any.
    pub(crate) async fn https(&self, path: &str, token: Option<&str>) -> Response {
        self.https_with("GET", path, token).await
    }

    pub(crate) async fn https_with(
        &self,
        method: &'static str,
        path: &str,
        token: Option<&str>,
    ) -> Response {
        let request = Req::new(self.https.clone(), method, path);
        match token {
            Some(id) => request.header(ACCOUNT, id),
            None => request,
        }
        .send()
        .await
    }

    /// `GET path` over a control socket at `ceiling`: once with no peer
    /// credentials and, on unix, once naming [`NAMELESS_UID`].
    pub(crate) async fn local(&self, ceiling: Role, path: &str) -> Vec<Response> {
        self.local_with(ceiling, "GET", path).await
    }

    pub(crate) async fn local_with(
        &self,
        ceiling: Role,
        method: &'static str,
        path: &str,
    ) -> Vec<Response> {
        let routers = [
            self.control.clone().with_local_authority(ceiling),
            #[cfg(unix)]
            self.control.clone().with_local_peer(ceiling, NAMELESS_UID),
        ];
        let mut responses = Vec::new();
        for router in routers {
            responses.push(Req::new(router, method, path).send().await);
        }
        responses
    }
}
