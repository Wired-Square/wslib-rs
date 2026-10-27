//! The appliance's router, authority and workers, beneath `wslib-appliance-server`
//! (behind a console or an ingress proxy), `wslib-appliance-https` (its own TLS
//! listener with sessions) and `wslib-appliance-service` (a desktop service).

mod about;
mod audit;
mod bounded;
mod compress;
mod console;
mod control;
mod error;
mod extract;
mod factors;
mod feed;
pub mod files;
mod hooks;
mod ingress;
mod logs;
#[cfg(test)]
mod probe;
mod procfs;
mod reached;
mod reauth;
mod redact;
mod retention;
mod routes;
mod spa;
mod state;
mod tasks;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tls;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRef, State};
use axum::http::{HeaderValue, header};
use axum::response::IntoResponse;
use axum::routing::get;
pub use tokio_util::sync::CancellationToken;
use tokio_util::sync::DropGuard;
use tower_http::compression::predicate::{DefaultPredicate, NotForContentType, Predicate};
use tower_http::compression::{CompressionLayer, CompressionLevel};
use wslib_appliance_config::BasePath;
use wslib_appliance_store::Store;
use wslib_appliance_types::Branding;
use wslib_appliance_types::branding::BrandingView;
use wslib_http_scaffold::EncoderCap;

pub use about::{About, ProductAbout};
pub use audit::Actor;

/// What [`audit!`] expands into; not for calling directly.
#[doc(hidden)]
pub use audit::record as __audit;
pub use control::{ControlRouter, ServeError, daemon};
pub use error::ApiError;
// `LocalAuthority` is not exported: a consumer could layer it onto its own routes and authorise everything.
pub use extract::{
    Admin, HostAdmin, Identity, LOCAL_ACTOR, Operator, Principal, ResolveCaller, SessionAdmin,
    Unclaimed, Viewer, host_admin_only,
};
pub use factors::{
    HostSessions, ReauthenticationWindow, password_proved, prove_acting_admin, prove_caller,
    reauthentication_route, remove_account_passkey, require_totp_enrolment, second_factor_routes,
};
pub use feed::{feed, sse};
pub use hooks::{BackupHooks, Notes};
pub use ingress::{INGRESS_SOURCE, RequestBase};
pub use logs::{Logs, logs};
pub use procfs::{boottime, box_id, hostname};
pub use reached::{Reached, ServingPort};
pub use reauth::{Proved, REAUTHENTICATION_WINDOW, reauthenticate};
pub use retention::{Clock, spawn_sweeper};
pub use routes::clean_name;
pub use state::ApplianceState;
pub use tasks::{Reconciled, TaskTable};
pub use wslib_auth::Proof;

use state::{Assets, BrandingBody, Listening, Logo};

/// What the serving crates build their backends from; a product never names it.
#[doc(hidden)]
pub mod backend {
    pub use wslib_appliance_types::{MAX_APP_LEN, is_app_name};

    #[cfg(unix)]
    pub use crate::console::serve_app_socket;
    pub use crate::control::{ControlEndpoint, GRACE, serve_control};
    pub use crate::extract::{Callers, SESSION_COOKIE, claimed};
    pub use crate::factors::{MAX_BODY as MAX_FACTOR_BODY, store_for};
    #[cfg(unix)]
    pub use crate::hooks::serve_hooks_socket;
    pub use crate::hooks::{HookCaller, backup_hooks, hooks};
    #[cfg(any(test, feature = "testing"))]
    pub use crate::ingress::gate as gate_ingress;
    pub use crate::ingress::serve_ingress;
    pub use crate::logs::{close_audit_queue, logs_writing_to};
    pub use crate::reauth::prove_password;
    pub use crate::redact::foreign;
    pub use crate::routes::logs::LogsRung;
    pub use crate::state::Listening;

    use axum_server::tls_rustls::RustlsConfig;
    use wslib_appliance_types::User;

    use crate::tls::Tls;
    use crate::{ApiError, ApplianceState, Identity, Logs, ServeError};

    /// For routes that must never reach a backend whose callers are accounts:
    /// `Chassis::build` refuses one that has sessions or a resolver.
    pub fn local_mount(routes: crate::Mount) -> crate::LocalMount {
        crate::LocalMount(routes)
    }

    pub fn onboarding(state: &ApplianceState) -> bool {
        state.onboarding
    }

    pub fn base_path(state: &ApplianceState) -> &str {
        state.base_path.as_str()
    }

    #[cfg(feature = "sessions")]
    pub fn sessions(state: &ApplianceState) -> Result<&wslib_appliance_auth::Sessions, ApiError> {
        state
            .sessions
            .get()
            .ok_or_else(|| ApiError::internal("issue a session", &"this backend keeps no sessions"))
    }

    pub fn signed_in(who: &Identity) -> Result<&User, ApiError> {
        who.signed_in()
    }

    pub fn logs(state: &ApplianceState) -> &Logs {
        &state.logs
    }

    pub fn ring(logs: &Logs) -> &wslib_telemetry::Logs {
        logs.ring()
    }

    /// Run `serving` until it ends or `stop` completes, which cancels `root` and
    /// waits for the drain; `stop` is polled after `serving`, so a first-poll bind has happened.
    pub async fn until_stop(
        serving: impl Future<Output = Result<(), ServeError>>,
        root: &tokio_util::sync::CancellationToken,
        stop: impl Future<Output = ()>,
    ) -> Result<(), ServeError> {
        tokio::pin!(serving);
        tokio::select! {
            biased;
            served = &mut serving => served,
            () = stop => {
                root.cancel();
                serving.await
            }
        }
    }

    /// Call after every stop handle has fired; abandons tasks still running at `deadline`.
    pub async fn join_tasks(
        tasks: Vec<tokio::task::JoinHandle<()>>,
        deadline: tokio::time::Instant,
    ) {
        let joined = async {
            for task in tasks {
                if let Err(e) = task.await {
                    tracing::error!(error = %e, "a registered task panicked");
                }
            }
        };
        if tokio::time::timeout_at(deadline, joined).await.is_err() {
            tracing::warn!(grace = ?GRACE, "a registered task had not ended; not waiting");
        }
    }

    /// Run `work` to its end whatever becomes of its request; it runs on its own
    /// task, so must not read the request's task-locals.
    pub fn to_completion<T: Send + 'static>(
        state: &ApplianceState,
        work: impl Future<Output = T> + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        state.unfinished.spawn(work)
    }

    /// Call before [`close_audit_queue`].
    pub async fn join_unfinished(state: &ApplianceState, deadline: tokio::time::Instant) {
        let finished = state.unfinished.finished();
        if tokio::time::timeout_at(deadline, finished).await.is_err() {
            tracing::warn!(grace = ?GRACE, "work run to completion had not ended; not waiting");
        }
    }

    /// Call after every stop handle has fired.
    pub async fn wind_down(state: &ApplianceState, tasks: Vec<tokio::task::JoinHandle<()>>) {
        let deadline = tokio::time::Instant::now() + GRACE;
        join_unfinished(state, deadline).await;
        close_audit_queue(&state.logs);
        join_tasks(tasks, deadline).await;
    }

    pub async fn load_or_mint(
        settings: &wslib_appliance_config::Tls,
        alias: Option<&str>,
    ) -> Result<Tls, ServeError> {
        Tls::load_or_mint(settings, alias).await
    }

    pub fn no_tls() -> Tls {
        Tls::none()
    }

    pub fn serves_tls(tls: &Tls) -> bool {
        tls.serves()
    }

    /// An install reloads this configuration in place.
    pub fn tls_config(tls: &Tls) -> RustlsConfig {
        tls.config()
            .expect("a backend that serves its own TLS listener loaded its pair at start")
    }

    #[cfg(any(test, feature = "testing"))]
    pub async fn minted_in(dir: impl AsRef<std::path::Path>) -> Tls {
        Tls::minted_in(dir).await
    }
}

/// The key `/healthz` reads. It need not exist; reading it is a real query, so a
/// database that is not answering fails the check.
const HEALTH_PROBE: &str = "health.probe";

/// This crate's half of an appliance's HTTP surface, before it is built.
#[doc(hidden)]
pub struct Chassis {
    store: Store,
    branding: Branding,
    logs: Logs,
    about: about::Source,
    hooks: hooks::Hooks,
    logo: Option<Logo>,
    api: Vec<Mount>,
    local: bool,
    routes: Vec<(String, Mount)>,
    base_path: BasePath,
    front: Option<Front>,
    tasks: Vec<Task>,
    os_store: tls::outbound::OsStore,
    /// A guard, so dropping this unbuilt still fires every [`shutdown`](Self::shutdown) handle.
    stop: DropGuard,
}

enum Front {
    Bundle(PathBuf),
    Page(Mount),
}

const TWO_FRONTS: &str = "a root page and a UI directory both answer `/`: set one";

type Task =
    Box<dyn FnOnce(ApplianceState, CancellationToken) -> tokio::task::JoinHandle<()> + Send>;

/// Routes for `Server::api`: a `Router<ApplianceState>` as it is, or a
/// `Router<S>` on a state of the product's own through [`Mount::new`].
pub struct Mount {
    routes: Box<dyn FnOnce(ApplianceState) -> Router<ApplianceState> + Send>,
    about: Vec<Box<dyn about::Erased>>,
    raisable: bool,
}

/// What a backend makes of the rung above Admin.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AboveAdmin {
    /// A HostAdmin is held as Admin.
    Absent,
    /// HostAdmin is a real role, but no mount is raised.
    Present,
    /// Every [`raisable`](Mount::raisable) mount needs HostAdmin, `/api/tls/*` included.
    Raising,
}

impl Mount {
    /// A router on a state of the product's own, built from the [`ApplianceState`]:
    /// a struct holding both, with `FromRef` for each (`#[derive(FromRef)]` does it).
    ///
    /// ```ignore
    /// #[derive(Clone, FromRef)]
    /// struct Hello {
    ///     appliance: ApplianceState,
    ///     poller: Poller,
    /// }
    ///
    /// pub fn routes(poller: Poller) -> Mount {
    ///     Mount::new(Router::new().route("/poller", get(view)), move |appliance| Hello {
    ///         appliance,
    ///         poller,
    ///     })
    /// }
    /// ```
    pub fn new<S, F>(routes: Router<S>, state: F) -> Self
    where
        ApplianceState: FromRef<S>,
        S: Clone + Send + Sync + 'static,
        F: FnOnce(ApplianceState) -> S + Send + 'static,
    {
        Self::from_fn(move |chassis| routes.with_state(state(chassis)))
    }

    /// Settings › About rows, listed ahead of every `Server::about` row.
    pub fn about(mut self, rows: impl About) -> Self {
        self.about.push(Box::new(rows));
        self
    }

    fn from_fn(
        routes: impl FnOnce(ApplianceState) -> Router<ApplianceState> + Send + 'static,
    ) -> Self {
        Self {
            routes: Box::new(routes),
            about: Vec::new(),
            raisable: false,
        }
    }

    /// Every rung on these routes is raised to [`HostAdmin`] under [`AboveAdmin::Raising`].
    #[doc(hidden)]
    pub fn raisable(self) -> Self {
        Self {
            raisable: true,
            ..self
        }
    }

    fn into_router(self, state: ApplianceState, raise: bool) -> Router<ApplianceState> {
        let routes = (self.routes)(state);
        match raise && self.raisable {
            true => host_admin_only(routes),
            false => routes,
        }
    }
}

/// Routes only a backend with no resolver mounts; deliberately not convertible into a [`Mount`].
pub struct LocalMount(Mount);

// **The only `From<Router<_>>`**: a second would break `ApplianceState` inference on `.api(Router::new()…)`.
impl From<Router<ApplianceState>> for Mount {
    fn from(routes: Router<ApplianceState>) -> Self {
        Self::from_fn(|_| routes)
    }
}

/// What the serving backend brings to `Chassis::build`.
#[doc(hidden)]
pub struct Backend {
    pub callers: backend::Callers,
    pub logs: backend::LogsRung,
    pub tls: Arc<tls::Tls>,
    pub listening: Option<Arc<dyn Listening>>,
    /// Whether a box with no accounts offers its first one to [`Unclaimed`];
    /// ignored unless the callers are declared to be the store's accounts.
    pub onboarding: bool,
    /// Whether `GET /api/branding` carries the hostname.
    pub names_the_box: bool,
    pub above_admin: AboveAdmin,
    pub routes: Vec<Mount>,
    /// As `routes`, on the control socket alone.
    pub control_routes: Vec<Mount>,
}

#[doc(hidden)]
pub struct Built {
    pub state: ApplianceState,
    pub https: Router,
    pub control: ControlRouter,
    pub stop: CancellationToken,
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Chassis {
    pub fn new(store: Store, branding: Branding, version: &str, logs: Logs) -> Self {
        Self {
            store,
            logs,
            about: about::Source {
                product: branding.app_name.clone(),
                version: version.to_string(),
                contributors: Vec::new(),
            },
            branding,
            hooks: hooks::Hooks::default(),
            logo: None,
            api: Vec::new(),
            local: false,
            routes: Vec::new(),
            base_path: BasePath::default(),
            front: None,
            tasks: vec![Box::new(|state: ApplianceState, _| {
                tokio::spawn(logs::write_audit_rows(
                    state.logs.ring(),
                    state.store.clone(),
                ))
            })],
            os_store: wslib_tls::Outbound::new,
            stop: CancellationToken::new().drop_guard(),
        }
    }

    /// For a harness: unpinned dials trust the installed authorities alone, never the OS store.
    #[cfg(any(test, feature = "testing"))]
    pub fn without_os_store(mut self) -> Self {
        self.os_store = |provider, trust| {
            wslib_tls::testing::outbound_with_os_roots(provider, trust, Vec::new())
        };
        self
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn shutdown(&self) -> CancellationToken {
        self.stop.token().child_token()
    }

    pub fn logo(mut self, bytes: impl Into<Bytes>, content_type: &str) -> Self {
        let content_type = HeaderValue::from_str(content_type).unwrap_or_else(|_| {
            tracing::error!(
                content_type,
                "the logo's content type is not a usable header value"
            );
            HeaderValue::from_static("application/octet-stream")
        });
        self.logo = Some(Logo::new(bytes.into(), content_type));
        self
    }

    /// Panics on a directory beside a [`root`](Self::root) page.
    pub fn ui(mut self, dir: Option<PathBuf>) -> Self {
        match (&self.front, dir) {
            (Some(Front::Page(_)), Some(_)) => panic!("{TWO_FRONTS}"),
            (Some(Front::Page(_)), None) => {}
            (_, dir) => self.front = dir.map(Front::Bundle),
        }
        self
    }

    pub fn about(mut self, rows: impl About) -> Self {
        self.about.contributors.push(Box::new(rows));
        self
    }

    pub fn api(mut self, routes: impl Into<Mount>) -> Self {
        self.api.push(routes.into());
        self
    }

    pub fn notes(mut self, notes: impl Notes) -> Self {
        self.hooks.notes = Some(Box::new(notes));
        self
    }

    pub fn backup_hooks(mut self, backup: BackupHooks) -> Self {
        self.hooks.backup = Some(backup);
        self
    }

    /// Panics on a `prefix` that is not `/` and one path segment, or that this crate serves itself.
    pub fn route(mut self, prefix: &str, routes: impl Into<Mount>) -> Self {
        assert!(
            prefix.strip_prefix('/').is_some_and(|segment| {
                BasePath::is_segment(segment)
                    && !["api", "assets", "healthz", spa::INDEX].contains(&segment)
            }),
            "a route prefix is `/` and one path segment, and not `/api`, `/assets`, \
             `/healthz` or `/{}`: {prefix:?}",
            spa::INDEX
        );
        self.routes.push((prefix.to_string(), routes.into()));
        self
    }

    /// Panics beside a UI directory.
    pub fn root(mut self, routes: impl Into<Mount>) -> Self {
        assert!(
            !matches!(self.front, Some(Front::Bundle(_))),
            "{TWO_FRONTS}"
        );
        self.front = Some(Front::Page(routes.into()));
        self
    }

    pub fn base_path(mut self, base: BasePath) -> Self {
        self.base_path = base;
        self
    }

    pub fn local_api(mut self, routes: LocalMount) -> Self {
        self.api.push(routes.0);
        self.local = true;
        self
    }

    pub fn task<F, Fut>(mut self, task: F) -> Self
    where
        F: FnOnce(ApplianceState, CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.tasks
            .push(Box::new(move |state, stop| tokio::spawn(task(state, stop))));
        self
    }

    /// Refuses with [`ServeError::NoCryptoProvider`] unless the process has a
    /// rustls provider installed.
    ///
    /// **The socket's router is returned without local authority**: only the
    /// function owning the socket applies it — see [`ControlRouter`].
    pub async fn build(mut self, backend: Backend) -> Result<Built, ServeError> {
        tls::provider()?;
        let backend::Callers {
            sessions,
            resolver,
            vouches,
        } = backend.callers;
        if self.local && (sessions.0.is_some() || resolver.is_some()) {
            return Err(ServeError::LocalRoutesWithResolver);
        }
        let outbound = Arc::new(tls::Outbound::load(&self.store, self.os_store).await?);

        let tasks = std::mem::take(&mut self.tasks);
        let (ui, mut root) = match self.front.take() {
            Some(Front::Bundle(dir)) => (Some(dir), None),
            Some(Front::Page(root)) => (None, Some(root)),
            None => (None, None),
        };
        let page = ui.as_ref().and_then(|dir| {
            let path = dir.join(spa::INDEX);
            std::fs::read(&path)
                .inspect_err(|error| {
                    let path = path.display();
                    let why = "the bundle's index.html is unreadable, so its page answers 404";
                    tracing::warn!(%path, %error, "{why}");
                })
                .ok()
        });
        let build = build_id(&self.about.version, page.as_deref());
        self.about.contributors.splice(
            0..0,
            self.api
                .iter_mut()
                .chain(self.routes.iter_mut().map(|(_, mount)| mount))
                .chain(root.as_mut())
                .flat_map(|mount| mount.about.drain(..)),
        );
        let onboarding = backend.onboarding && vouches == extract::Vouches::StoreAccounts;
        let state = ApplianceState {
            listening: backend.listening,
            store: self.store,
            sessions,
            passkeys: wslib_appliance_auth::Passkeys::default(),
            codes: wslib_appliance_auth::CodeAttempts::default(),
            pending: wslib_appliance_auth::PendingSignIns::default(),
            resolver,
            vouches,
            tls: backend.tls,
            outbound,
            logs: self.logs,
            about: Arc::new(self.about),
            hooks: Arc::new(self.hooks),
            stop: self.stop.token().child_token(),
            assets: Arc::new(Assets {
                branding: BrandingBody::new(BrandingView {
                    build,
                    branding: self.branding,
                    hostname: None,
                }),
                names_the_box: backend.names_the_box,
                logo: self.logo,
            }),
            onboarding,
            above_admin: backend.above_admin,
            base_path: self.base_path.clone(),
            unfinished: state::Unfinished::default(),
        };

        let raise = backend.above_admin == AboveAdmin::Raising;
        let merge = |api: Router<ApplianceState>, mount: Mount| {
            api.merge(mount.into_router(state.clone(), raise))
        };
        let api = backend
            .routes
            .into_iter()
            .chain([Mount::from(routes::tls::routes()).raisable()])
            .chain(self.api)
            .fold(Router::new(), merge);
        let control_api = backend.control_routes.into_iter().fold(api.clone(), merge);
        let base = |api| {
            Router::new()
                .nest("/api", routes::api(api, backend.logs))
                .route("/healthz", get(healthz))
        };
        let prefixes: Vec<String> = self
            .routes
            .iter()
            .map(|(prefix, _)| prefix.trim_start_matches('/').to_string())
            .collect();
        let routed = self
            .routes
            .into_iter()
            .fold(base(api), |router, (prefix, mount)| {
                router.nest(&prefix, mount.into_router(state.clone(), raise))
            });
        // **Must stay last**: it patches only the method routers registered before it.
        let control = base(control_api).method_not_allowed_fallback(routes::method_not_allowed);
        let routed = routed.method_not_allowed_fallback(routes::method_not_allowed);
        // A service at `/` alone, not a merge, so nothing else in the router is reachable;
        // being no method router, it carries its own fallbacks.
        let routed = match root {
            Some(root) => routed.route_service(
                "/",
                root.into_router(state.clone(), raise)
                    .method_not_allowed_fallback(routes::method_not_allowed)
                    .fallback(spa::fallback)
                    .with_state(state.clone()),
            ),
            None => routed,
        };
        let routed = match ui.as_deref() {
            Some(dir) => {
                routed.fallback_service(spa::bundle(dir, page, self.base_path.clone(), prefixes))
            }
            None => routed.fallback(spa::fallback),
        };
        let https = routed
            // After the fallback: `Router::layer` wraps only what is already registered.
            .layer(
                CompressionLayer::new()
                    .quality(CompressionLevel::Fastest)
                    .compress_when(
                        DefaultPredicate::new()
                            .and(NotForContentType::const_new("application/gzip")),
                    ),
            )
            // Outside compression, so it edits the request first and holds its permit over the body.
            .layer(EncoderCap::default());

        // No bundle, compression, base path or routes outside `/api` on the socket.
        let local = control.fallback(spa::fallback);

        let stop = self.stop.disarm();
        let tasks = tasks
            .into_iter()
            .map(|spawn| spawn(state.clone(), stop.child_token()))
            .collect();
        Ok(Built {
            https: spa::under(self.base_path.prefix(), https.with_state(state.clone()))
                .layer(axum::middleware::from_fn(error::as_page)),
            control: ControlRouter::new(local.with_state(state.clone())),
            state,
            stop,
            tasks,
        })
    }
}

/// Hashes the page too: every dirty build of one commit carries the same version.
fn build_id(version: &str, page: Option<&[u8]>) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(version);
    digest.update(page.unwrap_or_default());
    hex(&digest.finalize()[..8])
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Readiness, not liveness: 503 when the database is unreachable. **Unauthenticated**,
/// because a health check that needs a credential gets a shared one.
async fn healthz(State(app): State<ApplianceState>) -> Result<impl IntoResponse, ApiError> {
    app.store
        .setting(HEALTH_PROBE)
        .await
        .map_err(|e| ApiError::unavailable("reach the database", &e))?;

    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        r#"{"status":"ok"}"#,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_build_id_follows_the_page_as_well_as_the_version() {
        let page = |asset: &[u8]| build_id("0.1.0 (gabc-dirty)", Some(asset));
        let a = page(b"<script src=/assets/index-1.js>");
        assert_ne!(
            a,
            page(b"<script src=/assets/index-2.js>"),
            "a rebuilt bundle under one version is a new build"
        );
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn an_app_name_is_a_base_path_segment() {
        let mut names: Vec<String> = (0..=u8::MAX)
            .map(|byte| String::from_utf8_lossy(&[byte]).into_owned())
            .collect();
        names.extend([".", "..", "...", "", "a/b", "hello-app.1~x"].map(String::from));
        for name in names {
            assert_eq!(
                backend::is_app_name(&name),
                wslib_appliance_config::BasePath::is_segment(&name),
                "{name:?}"
            );
        }
        assert!(backend::is_app_name(&"a".repeat(backend::MAX_APP_LEN)));
        assert!(!backend::is_app_name(&"a".repeat(backend::MAX_APP_LEN + 1)));
    }

    #[tokio::test]
    async fn until_stop_cancels_the_root_before_waiting_for_the_drain() {
        let root = CancellationToken::new();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        let cancelled_at_resume = std::cell::Cell::new(None);
        let serving = async {
            resumed.await.expect("the stop resumes serving");
            cancelled_at_resume.set(Some(root.is_cancelled()));
            Ok(())
        };
        let stop = async { resume.send(()).expect("serving is waiting") };

        backend::until_stop(serving, &root, stop)
            .await
            .expect("serving ends Ok");
        assert_eq!(cancelled_at_resume.get(), Some(true));
    }

    #[tokio::test]
    async fn until_stop_returns_an_error_serving_ends_in_before_the_stop() {
        let serving = async {
            tokio::task::yield_now().await;
            Err(ServeError::Bind {
                address: "[::]:443".into(),
                because: "in use".into(),
            })
        };

        let served =
            backend::until_stop(serving, &CancellationToken::new(), std::future::pending()).await;
        assert!(matches!(served, Err(ServeError::Bind { .. })));
    }
}
