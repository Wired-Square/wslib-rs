//! The HTTP surface of a product that serves its own browser, with no console
//! in front: a TLS listener, a plain-HTTP redirect beside it, the control
//! socket, sessions, sign-in, your own password and the first account. A
//! product behind a console takes `wslib-appliance-server` instead, from the
//! same [`Mount`]s. Most of it is `wslib-appliance-core`'s, re-exported here.
//!
//! ```no_run
//! # fn example() -> std::process::ExitCode {
//! # use wslib_appliance_config::{ApplianceArgs, Resolver, ServingArgs};
//! # use wslib_appliance_https::Server;
//! # use wslib_appliance_store::Store;
//! # use wslib_appliance_types::Branding;
//! # let (args, serving) = (ApplianceArgs::default(), ServingArgs::default());
//! let _ = rustls::crypto::ring::default_provider().install_default();
//! let logs = wslib_appliance_https::logs(&["myappliance"]);
//! logs.feed(wslib_telemetry::Telemetry::new("info").journald()).init();
//! wslib_appliance_https::daemon("myappliance")
//!     .run(|stop| async move {
//!         let bootstrap = Resolver::new("myappliance", "MYAPPLIANCE")
//!             .serving(&serving)
//!             .resolve(&args)?;
//!         let store = Store::open(&bootstrap.db, None).await?;
//!
//!         // `wslib_build_id::build_version!()` in a real product.
//!         let server = Server::new(store, Branding::unbranded(), "1.0.0 (abc1234)", logs);
//!         server.ui(bootstrap.ui.clone()).serve(&bootstrap, stop).await?;
//!         Ok::<_, Box<dyn std::error::Error>>(())
//!     })
//!     .map_or_else(std::process::ExitCode::from, |()| std::process::ExitCode::SUCCESS)
//! # }
//! ```
//!
//! # A crypto provider
//!
//! This crate installs no rustls provider. Install one before serving, or
//! [`Server::serve`] refuses with [`ServeError::NoCryptoProvider`] before
//! loading or minting a pair.
//!
//! # Two listeners, two authorities
//!
//! The TLS listener and the control socket mount the same `/api`, bar
//! `/api/users…` (below). A request on the socket satisfies every role up to
//! Admin, on a box with no accounts too: it is the way back in when nobody can
//! sign in. [`SessionAdmin`] refuses it. `/api/users…` is always on the
//! socket, and on the TLS listener only by [`Server::users_routes`].

mod routes;
mod serve;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::Request;
use wslib_appliance_auth::Sessions;
use wslib_appliance_config::Bootstrap;
use wslib_appliance_core::{Backend, Built, Chassis, ServingPort, backend};
use wslib_appliance_store::Store;
use wslib_appliance_types::Branding;

/// The handle a consumer's tasks stop on. See [`Server::shutdown`](crate::Server::shutdown).
pub use wslib_appliance_core::CancellationToken;
pub use wslib_appliance_core::{
    About, Actor, Admin, ApiError, ApplianceState, Clock, HostAdmin, INGRESS_SOURCE, Identity,
    LOCAL_ACTOR, Logs, Mount, Operator, Principal, ProductAbout, REAUTHENTICATION_WINDOW, Reached,
    Reconciled, RequestBase, ResolveCaller, ServeError, SessionAdmin, TaskTable, Unclaimed, Viewer,
    audit, boottime, box_id, clean_name, daemon, feed, host_admin_only, hostname, issue_session,
    logs, reauthenticate, session_cookie, session_token_in, spawn_sweeper, sse, tls,
};

#[doc(hidden)]
pub use wslib_appliance_core::__audit;

/// An appliance's HTTP surface, assembled.
pub struct Server {
    chassis: Chassis,
    store: Store,
    users: bool,
    origin_port: Option<u16>,
}

impl Server {
    /// `version` is the product's `wslib_build_id::build_version!()`,
    /// expanded in its own crate; `logs` is the ring the subscriber fills.
    pub fn new(store: Store, branding: Branding, version: &str, logs: Logs) -> Self {
        Self {
            chassis: Chassis::new(store.clone(), branding, version, logs),
            store,
            users: false,
            origin_port: None,
        }
    }

    /// The port in the browser's address when a proxy in front, passing the
    /// browser's `Host` through, serves on a port other than the TLS
    /// listener's; a passkey ceremony then runs only on it. Never read from a
    /// forwarded header.
    pub fn origin_port(self, port: u16) -> Self {
        Self {
            origin_port: Some(port),
            ..self
        }
    }

    /// A handle that fires at the stop [`serve`](Self::serve) is handed,
    /// **before** the listeners drain, and whenever `serve` returns or the
    /// server is dropped unserved. Wait for your tasks after `serve` and before
    /// looking at its result. A child: cancelling it stops only the tasks
    /// holding it.
    pub fn shutdown(&self) -> CancellationToken {
        self.chassis.shutdown()
    }

    /// The image `GET /api/branding/logo` answers with. An unusable
    /// `content_type` is logged and served as `application/octet-stream`.
    pub fn logo(self, bytes: impl Into<Bytes>, content_type: &str) -> Self {
        self.with(|chassis| chassis.logo(bytes, content_type))
    }

    /// The directory holding the built browser bundle, or `None` for none,
    /// which leaves a [`root`](Self::root) page in place; `Some` beside `root`
    /// panics.
    pub fn ui(self, dir: Option<PathBuf>) -> Self {
        self.with(|chassis| chassis.ui(dir))
    }

    /// Rows for Settings › About, after every [`Mount`]'s and each other's, in
    /// call order.
    pub fn about(self, rows: impl About) -> Self {
        self.with(|chassis| chassis.about(rows))
    }

    /// The product's own routes, mounted **under `/api`** on the TLS listener
    /// and the control socket: `.route("/devices", …)` serves `/api/devices`.
    ///
    /// **Set no fallback** on it (`/api`'s answers an unmatched path with an
    /// `ApiError`) **and no compression layer** (the TLS listener's covers it).
    /// Never put a secret in a body beside text a caller chose: compression
    /// makes the secret measurable.
    pub fn api(self, routes: impl Into<Mount>) -> Self {
        self.with(|chassis| chassis.api(routes))
    }

    /// Routes **outside `/api`**, nested under `prefix` (`/` and one segment,
    /// never `/api`, `/assets`, `/healthz` or `/index.html`; any other panics)
    /// on the TLS listener under the base path, and not on the control socket.
    /// The bundle never answers a path under `prefix`, nor under `/apps`: a
    /// path no route matches there is a JSON 404.
    pub fn route(self, prefix: &str, routes: impl Into<Mount>) -> Self {
        self.with(|chassis| chassis.route(prefix, routes))
    }

    /// A page at the root of the base path for an appliance with no UI
    /// directory: `routes`' `/` answers `<base>` and `<base>/`, nothing else in
    /// it is reachable, and a [UI directory](Self::ui) as well panics.
    pub fn root(self, routes: impl Into<Mount>) -> Self {
        self.with(|chassis| chassis.root(routes))
    }

    /// Serve the account routes, `/api/users…` at Admin, on the TLS listener
    /// too; the control socket serves them either way. Over HTTPS the last
    /// enabled administrator cannot be demoted, disabled or deleted, and a
    /// password reset aimed at the caller's own account is refused; over the
    /// socket, neither applies.
    pub fn users_routes(self) -> Self {
        Self {
            users: true,
            ..self
        }
    }

    /// A task that runs for as long as the appliance serves, against the
    /// assembled [`ApplianceState`], handed a stop handle as
    /// [`shutdown`](Self::shutdown)'s and waited for after the drain, for the
    /// same grace; one still running then is abandoned with a warning.
    pub fn task<F, Fut>(self, task: F) -> Self
    where
        F: FnOnce(ApplianceState, CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.with(|chassis| chassis.task(task))
    }

    /// Listen until `stop` completes: TLS on `bootstrap`'s address and HTTPS
    /// port, the redirect on its redirect port when one is set, and the control
    /// socket at its `socket`, Admin at most. The first listener to fail stops
    /// the rest.
    ///
    /// The serving pair is `bootstrap.tls`, minted at the default location when
    /// absent. `bootstrap.browser_onboarding` decides whether a box with no
    /// accounts offers its first one to the browser. Every
    /// [`shutdown`](Self::shutdown) handle has fired by the time this returns.
    /// Refuses with [`ServeError::NoCryptoProvider`] when no rustls provider is
    /// installed.
    pub async fn serve(
        self,
        bootstrap: &Bootstrap,
        stop: impl Future<Output = ()>,
    ) -> Result<(), ServeError> {
        #[cfg(test)]
        install_test_provider();
        let tls = Arc::new(backend::load_or_mint(&bootstrap.tls, None).await?);
        let serving_tls = backend::serving_tls(&tls);
        serve::moved_port(&self.store, bootstrap.https_port).await;

        let port = serve::HttpsPort::new(bootstrap.https_port);
        let built = self.build(tls, port.clone(), bootstrap).await?;
        let served = serve::run(
            built.https,
            built.control,
            bootstrap,
            port,
            serving_tls,
            built.stop,
            stop,
        )
        .await;
        backend::wind_down(&built.state, built.tasks).await;
        served
    }

    fn with(self, change: impl FnOnce(Chassis) -> Chassis) -> Self {
        Self {
            chassis: change(self.chassis),
            ..self
        }
    }

    async fn build(
        self,
        tls: Arc<tls::Tls>,
        port: serve::HttpsPort,
        bootstrap: &Bootstrap,
    ) -> Result<Built, ServeError> {
        let sessions = Sessions::new(&self.store);
        let (routes, control_routes) = routes::api(self.users);
        let serving = port.clone();
        let origin_port = self.origin_port;
        let mut built = self
            .chassis
            .base_path(bootstrap.base_path.clone())
            .build(Backend {
                callers: backend::Callers::sessions(sessions),
                logs: backend::LogsRung::SessionAdmin,
                tls,
                listening: Some(Arc::new(port)),
                onboarding: bootstrap.browser_onboarding,
                names_the_box: false,
                above_admin: wslib_appliance_core::AboveAdmin::Present,
                routes,
                control_routes,
            })
            .await?;
        built.https = built.https.layer(axum::middleware::map_request(
            move |mut request: Request| {
                let port = origin_port.unwrap_or_else(|| serving.current());
                request.extensions_mut().insert(ServingPort(port));
                async move { request }
            },
        ));
        Ok(built)
    }
}

#[cfg(test)]
fn install_test_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
