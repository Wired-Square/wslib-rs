//! The HTTP surface every appliance shares (the audit log, the daemon's own
//! log, what the installation is, and the browser bundle) served behind a
//! console's proxy on a Unix socket, with the console's hooks on a second, or
//! behind Home Assistant's ingress proxy. Most of it is
//! `wslib-appliance-core`'s, re-exported here.
//!
//! ```no_run
//! # #[cfg(unix)]
//! # fn example() -> std::process::ExitCode {
//! # use wslib_appliance_config::{ApplianceArgs, Resolver};
//! # use wslib_appliance_server::{AppSocket, Server};
//! # use wslib_appliance_store::Store;
//! # use wslib_appliance_types::Branding;
//! # let args = ApplianceArgs::default();
//! # async fn poll(_: Store, _: wslib_appliance_server::CancellationToken) {}
//! let _ = rustls::crypto::ring::default_provider().install_default();
//! let logs = wslib_appliance_server::logs(&["myappliance"]);
//! logs.feed(wslib_telemetry::Telemetry::new("info").journald()).init();
//! wslib_appliance_server::daemon("myappliance")
//!     .run(|stop| async move {
//!         let bootstrap = Resolver::new("myappliance", "MYAPPLIANCE").resolve(&args)?;
//!         let store = Store::open(&bootstrap.db, None).await?;
//!         let proxied = bootstrap.proxied.as_ref().ok_or("not behind a console")?;
//!         let socket = AppSocket::new(&proxied.app_socket, proxied.console_uid);
//!
//!         let server = Server::new(store.clone(), Branding::unbranded(), "1.0.0 (abc1234)", logs);
//!         let polling = tokio::spawn(poll(store, server.shutdown()));
//!         let served = server.ui(bootstrap.ui.clone()).serve(&bootstrap, socket, stop).await;
//!         polling.await?;
//!         served?;
//!         Ok::<_, Box<dyn std::error::Error>>(())
//!     })
//!     .map_or_else(std::process::ExitCode::from, |()| std::process::ExitCode::SUCCESS)
//! # }
//! ```
//!
//! # A crypto provider
//!
//! This crate installs no rustls provider. Install one before serving, or
//! [`Server::serve`] and [`Server::serve_ingress`] refuse with
//! [`ServeError::NoCryptoProvider`].
//!
//! # Authorisation is in the signature
//!
//! A handler names [`Viewer`], [`Operator`], [`Admin`], [`SessionAdmin`] or
//! [`HostAdmin`], and cannot obtain an [`Identity`] any other way.
//! `SessionAdmin` is Admin, but is refused over a control socket, where a host
//! may serve the same routes; `HostAdmin` is refused there too.
//!
//! # A route that changes something writes one line
//!
//! [`audit!`] is that line, in a consuming crate as in this one:
//! `audit!(&app, &who, "asked for a restart").await`. Where there is no
//! route, the line is a `tracing` event named `audit` with an `actor` field,
//! and an `actor_id` field only where the actor is authenticated:
//!
//! ```
//! # fn refuse(who: &wslib_appliance_server::Identity, device: &str) {
//! tracing::warn!(
//!     name: "audit",
//!     actor = who.actor(),
//!     actor_id = who.account_id(),
//!     device,
//!     "refused to add a device"
//! );
//! # }
//! ```

mod serve;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Bytes;
use tokio::net::TcpListener;
use wslib_appliance_config::BasePath;
#[cfg(unix)]
use wslib_appliance_config::Bootstrap;
use wslib_appliance_core::{Backend, Built, Chassis, backend};
use wslib_appliance_store::Store;
use wslib_appliance_types::{Branding, Role};
use wslib_homeassistant::ingress::Peers;

/// The handle a consumer's tasks stop on. See [`Server::shutdown`].
pub use wslib_appliance_core::CancellationToken;
pub use wslib_appliance_core::{
    About, Actor, Admin, ApiError, ApplianceState, BackupHooks, Clock, HostAdmin, INGRESS_SOURCE,
    Identity, LOCAL_ACTOR, Logs, Mount, Notes, Operator, Principal, ProductAbout,
    REAUTHENTICATION_WINDOW, Reached, Reconciled, RequestBase, ResolveCaller, ServeError,
    SessionAdmin, TaskTable, Unclaimed, Viewer, audit, boottime, box_id, clean_name, daemon, feed,
    host_admin_only, hostname, logs, reauthenticate, spawn_sweeper, sse, tls,
};

#[doc(hidden)]
pub use wslib_appliance_core::__audit;

/// An appliance's HTTP surface, assembled.
pub struct Server {
    chassis: Chassis,
}

impl Server {
    /// `version` is the product's `wslib_build_id::build_version!()`,
    /// expanded in its own crate; `logs` is the ring the subscriber fills, and
    /// a subscriber of the product's own adds its [`layer`](Logs::layer).
    /// `branding` is served to anybody, before sign-in.
    pub fn new(store: Store, branding: Branding, version: &str, logs: Logs) -> Self {
        Self {
            chassis: Chassis::new(store, branding, version, logs),
        }
    }

    /// A handle that fires when the appliance is stopping.
    ///
    /// Take it before the builder methods consume `self`. It fires at the stop
    /// [`serve`](Self::serve) is handed, **before** the listeners drain, and
    /// whenever `serve` returns or the server is dropped unserved. Wait for
    /// your tasks after `serve` and before looking at its result.
    ///
    /// A child: cancelling it stops only the tasks holding it, never the
    /// appliance. It is `tokio_util`'s `CancellationToken`.
    pub fn shutdown(&self) -> CancellationToken {
        self.chassis.shutdown()
    }

    /// The image `GET /api/branding/logo` answers with, typically
    /// `include_bytes!`. An unusable `content_type` is logged and served as
    /// `application/octet-stream`.
    pub fn logo(self, bytes: impl Into<Bytes>, content_type: &str) -> Self {
        self.with(|chassis| chassis.logo(bytes, content_type))
    }

    /// The directory holding the built browser bundle, or `None` for none
    /// (a headless product, or one whose bundle a dev server serves), which
    /// leaves a [`root`](Self::root) page in place; `Some` beside `root`
    /// panics. A file with a `.gz` beside it is sent as that stored copy.
    pub fn ui(self, dir: Option<PathBuf>) -> Self {
        self.with(|chassis| chassis.ui(dir))
    }

    /// Rows for Settings › About, after every [`Mount`]'s and each other's, in
    /// call order.
    pub fn about(self, rows: impl About) -> Self {
        self.with(|chassis| chassis.about(rows))
    }

    /// The product's own routes, mounted **under `/api`**: `.route("/devices",
    /// …)` serves `/api/devices`. A `Router<ApplianceState>`, or a [`Mount`]
    /// on a state of the product's own.
    ///
    /// **Set no fallback** on it: `/api`'s is what answers an unmatched path
    /// with an `ApiError`. **And no compression layer**: the app socket's
    /// covers it. Keep a secret and text a caller chose out of one body, as
    /// compression makes the secret measurable.
    pub fn api(self, routes: impl Into<Mount>) -> Self {
        self.with(|chassis| chassis.api(routes))
    }

    /// What this product knows about the box's network, for the console to
    /// ask over the hooks socket; unused by
    /// [`serve_ingress`](Self::serve_ingress).
    pub fn notes(self, notes: impl Notes) -> Self {
        self.with(|chassis| chassis.notes(notes))
    }

    /// The backup hooks, served on the hooks socket alone; unused by
    /// [`serve_ingress`](Self::serve_ingress).
    pub fn backup_hooks(self, backup: BackupHooks) -> Self {
        self.with(|chassis| chassis.backup_hooks(backup))
    }

    /// Routes **outside `/api`**, nested under `prefix` (`/` and one path
    /// segment, never `/api`, `/assets`, `/healthz` or `/index.html`) on the
    /// app socket, under the base path. Panics on any other `prefix`.
    ///
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

    /// Listen on `socket`'s app socket, and its hooks socket when it names
    /// one, until `stop` completes; `stop` is first polled once every socket
    /// is listening. A socket that cannot bind fails the start. The hooks
    /// socket serves only the index, About, [`notes`](Self::notes) and
    /// [`backup_hooks`](Self::backup_hooks), to the console's uid alone.
    ///
    /// Who calls is what the console asserts in `Appliance-Identity`
    /// ([`ConsoleIdentity`](wslib_appliance_types::console::ConsoleIdentity)),
    /// read only on a connection from the console's uid; any other uid is
    /// served as nobody, at most four connections at once. There is no TLS,
    /// network listener, control socket, session, account or first-run offer,
    /// and a HostAdmin is held as Admin. Of `bootstrap`, only the base path
    /// matters.
    ///
    /// A dial to an unpinned host made before the OS trust store is read waits
    /// for it, at most 30 s. Every [`shutdown`](Self::shutdown) handle has
    /// fired by the time this returns. Refuses with
    /// [`ServeError::NoCryptoProvider`] when no rustls provider is installed.
    #[cfg(unix)]
    pub async fn serve(
        self,
        bootstrap: &Bootstrap,
        socket: AppSocket,
        stop: impl Future<Output = ()>,
    ) -> Result<(), ServeError> {
        let base_path = bootstrap.base_path.clone();
        let built = self
            .build(Arc::new(backend::no_tls()), base_path, Front::Console)
            .await?;
        let hooks = backend::hooks(&built.state);
        let served = serve::run(built.https, hooks, socket, built.stop, stop).await;
        backend::wind_down(&built.state, built.tasks).await;
        served
    }

    /// Listen on `ingress`'s address for Home Assistant's ingress proxy, until
    /// `stop` completes, as [`serve`](Self::serve) does.
    ///
    /// A peer outside its trusted list is a 403 on every path but `/healthz`.
    /// Who calls is what the proxy asserts in `X-Remote-User-Id` and
    /// `X-Remote-User-Name`, at the role this box keeps for that id
    /// (`Store::asserted_role`): one it has never seen takes `Ingress::new`'s
    /// first-sight role, and with none is a 403, kept with no role until it is
    /// given one or the rule gives one. `GET /api/session` answers it as `Caller::Console`.
    /// Everything is served at `/`, and the page names `X-Ingress-Path` as its
    /// base. There is no TLS, hooks socket, control socket, session, account or
    /// first-run offer, and a HostAdmin is held as Admin.
    pub async fn serve_ingress(
        self,
        ingress: Ingress,
        stop: impl Future<Output = ()>,
    ) -> Result<(), ServeError> {
        let listener = TcpListener::bind(ingress.bind)
            .await
            .map_err(|e| ServeError::Bind {
                address: ingress.bind.to_string(),
                because: e.to_string(),
            })?;
        self.serve_ingress_on(listener, ingress, stop).await
    }

    async fn serve_ingress_on(
        self,
        listener: TcpListener,
        ingress: Ingress,
        stop: impl Future<Output = ()>,
    ) -> Result<(), ServeError> {
        let peers = ingress.peers.clone();
        let built = self
            .build(
                Arc::new(backend::no_tls()),
                BasePath::default(),
                Front::Ingress(ingress),
            )
            .await?;
        let served = serve::ingress(built.https, listener, peers, built.stop, stop).await;
        backend::wind_down(&built.state, built.tasks).await;
        served
    }

    /// A task that runs for as long as the appliance serves, against the
    /// assembled [`ApplianceState`], for work that wants what only `serve`
    /// builds (outbound trust, [`audit!`]).
    ///
    /// Spawned once the state exists, handed a stop handle that fires as
    /// [`shutdown`](Self::shutdown)'s do, and waited for after the listeners
    /// drain, for the same grace; one still running then is abandoned with a
    /// warning.
    pub fn task<F, Fut>(self, task: F) -> Self
    where
        F: FnOnce(ApplianceState, CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.with(|chassis| chassis.task(task))
    }

    fn with(self, change: impl FnOnce(Chassis) -> Chassis) -> Self {
        Self {
            chassis: change(self.chassis),
        }
    }

    /// Ingress ignores `base_path`.
    async fn build(
        self,
        tls: Arc<tls::Tls>,
        base_path: BasePath,
        front: Front,
    ) -> Result<Built, ServeError> {
        #[cfg(test)]
        install_test_provider();
        use wslib_appliance_core::AboveAdmin;
        let (callers, above_admin, base_path) = match front {
            #[cfg(any(test, feature = "testing"))]
            Front::Resolver(callers) => (callers, AboveAdmin::Present, base_path),
            Front::Console => (
                backend::Callers::asserted_by_console(),
                AboveAdmin::Absent,
                base_path,
            ),
            Front::Ingress(ingress) => (
                backend::Callers::asserted_by_ingress(
                    self.chassis.store().clone(),
                    ingress.first_sight,
                ),
                AboveAdmin::Absent,
                BasePath::default(),
            ),
        };
        self.chassis
            .base_path(base_path)
            .build(Backend {
                callers,
                logs: backend::LogsRung::SessionAdmin,
                tls,
                listening: None,
                onboarding: true,
                names_the_box: false,
                above_admin,
                routes: Vec::new(),
                control_routes: Vec::new(),
            })
            .await
    }
}

#[cfg(test)]
fn install_test_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg_attr(not(unix), allow(dead_code))]
enum Front {
    #[cfg(any(test, feature = "testing"))]
    Resolver(backend::Callers),
    Console,
    Ingress(Ingress),
}

type FirstSight = Box<dyn Fn(&str) -> Option<Role> + Send + Sync>;

/// Where the ingress front door listens, the peers it answers, and the role a
/// caller this box has never seen takes. An idle connection is closed after 20
/// seconds.
pub struct Ingress {
    bind: SocketAddr,
    peers: Peers,
    first_sight: FirstSight,
}

impl Ingress {
    /// Listen on `bind`, answering the Supervisor's `172.30.32.2` alone. A
    /// caller this box has never seen takes what `first_sight` gives its user
    /// name, and with `None` is refused and kept with no role.
    pub fn new(
        bind: SocketAddr,
        first_sight: impl Fn(&str) -> Option<Role> + Send + Sync + 'static,
    ) -> Self {
        Self {
            bind,
            peers: Peers::home_assistant(),
            first_sight: Box::new(first_sight),
        }
    }

    /// Answer `peers` in place of the default, a v4-mapped v6 address as its
    /// v4 one. Loopback trusts every process in the container, and on a
    /// `host_network` add-on every process on the host.
    pub fn trusted_peers(mut self, peers: impl IntoIterator<Item = IpAddr>) -> Self {
        self.peers = Peers::new(peers);
        self
    }
}

/// Where a proxied app listens, the uid its console connects as, and where
/// the console calls its hooks.
///
/// Each socket's directory must be private to the app and the console. Each
/// socket is `0660`, so a console not running as root needs the app's group.
/// An idle connection is closed after 10 seconds, so a console pools one for
/// less than that.
#[cfg(unix)]
#[derive(Debug)]
pub struct AppSocket {
    path: PathBuf,
    console_uid: u32,
    hooks: Option<PathBuf>,
}

#[cfg(unix)]
impl AppSocket {
    /// `path` is a filesystem path, whose directory must exist. A
    /// `console_uid` that is the overflow uid (65534 or the kernel's) is
    /// refused when serving.
    pub fn new(path: impl Into<PathBuf>, console_uid: u32) -> Self {
        Self {
            path: path.into(),
            console_uid,
            hooks: None,
        }
    }

    /// Serve the hooks on a second socket at `path`, a filesystem path whose
    /// directory must exist, to `console_uid` alone: any other peer is hung
    /// up on unanswered.
    pub fn hooks(mut self, path: impl Into<PathBuf>) -> Self {
        self.hooks = Some(path.into());
        self
    }
}
