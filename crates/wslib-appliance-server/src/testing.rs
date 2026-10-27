//! An appliance a consuming crate drives its own routes through, behind the
//! `testing` feature, assembled as [`Server::serve`] assembles one: the caller
//! is what [`Req::from_console`] asserts ([`console`] makes one), and nobody
//! without it. Requests go through the assembled router, so every extractor,
//! layer and rejection on the path runs.
//!
//! Install a rustls provider before building a harness; a
//! [`resolver`](HarnessBuilder::resolver) harness mints its certificate with it.
//!
//! A control socket satisfies every role with no account at all. This crate
//! serves none, but a host serving the same routes on one does, so the
//! harness reaches them as the socket inside [`Req::local`] and nowhere else:
//! there a [`SessionAdmin`](crate::SessionAdmin) route answers 403 where an
//! [`Admin`](crate::Admin) one answers.

use std::path::{Path, PathBuf};

pub use wslib_appliance_core::testing::*;

use axum::Router;
use axum::body::Bytes;
use tempfile::TempDir;
use tokio_util::sync::DropGuard;
use wslib_appliance_core::backend;
use wslib_appliance_core::{Built, ControlRouter};
use wslib_appliance_store::Store;
use wslib_appliance_types::Role;
use wslib_appliance_types::console::ConsoleIdentity;

use crate::{About, ApplianceState, BackupHooks, CancellationToken, Front, Mount, Notes, Server};

const LOGO: &[u8] = br#"<svg xmlns="http://www.w3.org/2000/svg"/>"#;

/// What a console asserts for `username`, an account of `role` it keeps; its
/// id is `username`.
pub fn console(username: &str, role: Role) -> ConsoleIdentity {
    ConsoleIdentity {
        id: username.to_string(),
        username: username.to_string(),
        role,
        reauthenticated_at: None,
    }
}

/// An appliance on an in-memory database, driven through its real routers.
/// Its directory is removed when it is dropped.
pub struct Harness {
    state: ApplianceState,
    app: Router,
    hooks: Router,
    dir: TempDir,
    local: ControlRouter,
    /// Cancelled by `Harness::stop`, and on drop as when `serve` returns.
    stop: DropGuard,
}

type Deferred = Box<dyn FnOnce(Server) -> Server + Send>;

/// What to assemble before [`HarnessBuilder::build`].
pub struct HarnessBuilder {
    app_name: &'static str,
    logo: Option<(&'static [u8], &'static str)>,
    ui: Option<PathBuf>,
    api: Vec<Mount>,
    store: Option<Store>,
    deferred: Vec<Deferred>,
    dir: TempDir,
    bootstrap: wslib_appliance_config::Bootstrap,
    routes: Vec<(&'static str, Mount)>,
    front: Front,
}

impl HarnessBuilder {
    /// Assemble as [`Server::serve_ingress`] does with `ingress`, its bind
    /// address unused: a request other than `/healthz` is answered only when
    /// sent with [`Req::from_peer`] from a trusted peer.
    pub fn ingress(mut self, ingress: crate::Ingress) -> Self {
        self.front = Front::Ingress(ingress);
        self
    }

    /// Tell callers apart with `resolver` in place of the console, as a
    /// backend a host fronts does, with a serving certificate minted into the
    /// harness's directory.
    pub fn resolver(mut self, resolver: impl crate::ResolveCaller) -> Self {
        self.front = Front::Resolver(backend::Callers::resolved_by(resolver));
        self
    }

    /// [`resolver`](Self::resolver) over the store's own accounts, so the
    /// harness offers the box to [`Unclaimed`](crate::Unclaimed) until the
    /// store has an account.
    pub fn resolver_from_store(mut self, resolver: impl crate::ResolveCaller) -> Self {
        self.front = Front::Resolver(backend::Callers::resolved_from_store(resolver));
        self
    }

    /// As [`Server::route`].
    pub fn route(mut self, prefix: &'static str, routes: impl Into<Mount>) -> Self {
        self.routes.push((prefix, routes.into()));
        self
    }

    /// As [`Server::root`].
    pub fn root(mut self, routes: impl Into<Mount>) -> Self {
        let routes = routes.into();
        self.deferred.push(Box::new(|server| server.root(routes)));
        self
    }

    /// Serve under `base`, as `Bootstrap::base_path` does.
    pub fn base_path(mut self, base: wslib_appliance_config::BasePath) -> Self {
        self.bootstrap.base_path = base;
        self
    }

    /// A `Bootstrap` whose configuration directory is the harness's own.
    pub fn bootstrap(&self) -> &wslib_appliance_config::Bootstrap {
        &self.bootstrap
    }

    /// The harness's directory, removed with the harness.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The store the routes run on, in place of an in-memory one with the
    /// platform's tables alone: open it with the product's own migrations
    /// applied; the harness runs none.
    pub fn store(mut self, store: Store) -> Self {
        self.store = Some(store);
        self
    }

    /// As [`Server::api`].
    pub fn api(mut self, routes: impl Into<Mount>) -> Self {
        self.api.push(routes.into());
        self
    }

    /// As [`Server::about`].
    pub fn about(mut self, rows: impl About) -> Self {
        self.deferred.push(Box::new(|server| server.about(rows)));
        self
    }

    /// As [`Server::notes`].
    pub fn notes(mut self, notes: impl Notes) -> Self {
        self.deferred.push(Box::new(|server| server.notes(notes)));
        self
    }

    /// As [`Server::backup_hooks`].
    pub fn backup_hooks(mut self, backup: BackupHooks) -> Self {
        self.deferred
            .push(Box::new(|server| server.backup_hooks(backup)));
        self
    }

    #[cfg(test)]
    pub(crate) fn no_logo(mut self) -> Self {
        self.logo = None;
        self
    }

    #[cfg(test)]
    pub(crate) fn app_name(mut self, name: &'static str) -> Self {
        self.app_name = name;
        self
    }

    #[cfg(test)]
    pub(crate) fn logo(mut self, bytes: &'static [u8], content_type: &'static str) -> Self {
        self.logo = Some((bytes, content_type));
        self
    }

    /// A directory to serve the browser bundle from.
    pub fn ui(mut self, dir: &Path) -> Self {
        self.ui = Some(dir.to_path_buf());
        self
    }

    /// The appliance's tasks run as under `serve`, so a refusal reaches the
    /// audit log a moment after the request: see [`Harness::audit_row`].
    pub async fn build(self) -> Harness {
        #[cfg(test)]
        crate::install_test_provider();
        let store = match self.store {
            Some(store) => store,
            None => Store::open_in_memory(None).await.expect("in-memory store"),
        };

        let mut server = Server::new(
            store,
            harness_branding(self.app_name),
            Harness::VERSION,
            crate::logs(&[]),
        );
        if let Some((bytes, content_type)) = self.logo {
            server = server.logo(Bytes::from_static(bytes), content_type);
        }
        server = self
            .deferred
            .into_iter()
            .fold(server, |server, step| step(server));
        server = server.ui(self.ui);
        server = self.api.into_iter().fold(server, Server::api);
        server = self
            .routes
            .into_iter()
            .fold(server, |server, (prefix, routes)| {
                server.route(prefix, routes)
            });

        let tls = match &self.front {
            Front::Console | Front::Ingress(_) => backend::no_tls(),
            Front::Resolver(_) => backend::minted_in(&self.dir).await,
        };
        let base_path = self.bootstrap.base_path.clone();
        let peers = match &self.front {
            Front::Ingress(ingress) => Some(ingress.peers.clone()),
            Front::Console | Front::Resolver(_) => None,
        };
        let Built {
            state,
            https,
            control,
            stop,
            tasks: _,
        } = server
            .build(std::sync::Arc::new(tls), base_path, self.front)
            .await
            .unwrap_or_else(|e| panic!("the harness assembles: {e}"));
        Harness {
            hooks: backend::hooks(&state),
            state,
            app: match peers {
                Some(peers) => backend::gate_ingress(https, peers),
                None => https,
            },
            dir: self.dir,
            local: control,
            stop: stop.drop_guard(),
        }
    }
}

impl Harness {
    pub(crate) const VERSION: &'static str = "0.0.0 (test)";

    pub async fn new() -> Self {
        Self::builder().build().await
    }

    pub fn builder() -> HarnessBuilder {
        let dir = TempDir::new().expect("a directory for the harness");
        HarnessBuilder {
            app_name: "Widget Monitor",
            logo: Some((LOGO, "image/svg+xml")),
            ui: None,
            api: Vec::new(),
            store: None,
            deferred: Vec::new(),
            bootstrap: bootstrap_in(dir.path()),
            dir,
            routes: Vec::new(),
            front: Front::Console,
        }
    }

    /// Serve on an app socket in the harness's directory, as
    /// [`Server::serve`] does for a console connecting as `console_uid`, and
    /// answer its path once it is bound.
    #[cfg(unix)]
    pub async fn serve_app_socket(&self, console_uid: u32) -> PathBuf {
        let path = self.dir().join("app.sock");
        tokio::spawn(backend::serve_app_socket(
            self.app.clone(),
            path.clone(),
            console_uid,
            self.stop.token().clone(),
        ));
        bound(&path).await;
        path
    }

    /// As [`serve_app_socket`](Self::serve_app_socket), for the hooks.
    #[cfg(unix)]
    pub async fn serve_hooks_socket(&self, console_uid: u32) -> PathBuf {
        let path = self.dir().join("hooks.sock");
        tokio::spawn(backend::serve_hooks_socket(
            self.hooks.clone(),
            path.clone(),
            console_uid,
            self.stop.token().clone(),
        ));
        bound(&path).await;
        path
    }

    /// A request to the hooks, as the console sends one over the hooks socket.
    pub fn hook(&self, method: &'static str, path: &str) -> Req {
        Req::new(self.hooks.clone(), method, path)
            .harnessed(self.local.clone(), backend::logs(&self.state).clone())
            .on_hooks_socket()
    }

    /// The hooks router as anything but the hooks socket would mount it.
    #[cfg(test)]
    pub(crate) fn unmarked_hook(&self, method: &'static str, path: &str) -> Req {
        Req::new(self.hooks.clone(), method, path)
    }

    /// What [`HarnessBuilder::dir`] answered.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    pub fn state(&self) -> &ApplianceState {
        &self.state
    }

    pub fn store(&self) -> &Store {
        &self.state.store
    }

    /// What [`Server::shutdown`] hands a product: a child that fires at
    /// [`Harness::stop`].
    pub fn shutdown(&self) -> CancellationToken {
        self.stop.token().child_token()
    }

    /// Play the stop `serve` is handed.
    pub fn stop(&self) {
        self.stop.token().cancel();
    }

    pub fn get(&self, path: &str) -> Req {
        self.request("GET", path)
    }

    pub fn post(&self, path: &str) -> Req {
        self.request("POST", path)
    }

    pub fn put(&self, path: &str) -> Req {
        self.request("PUT", path)
    }

    pub fn delete(&self, path: &str) -> Req {
        self.request("DELETE", path)
    }

    pub fn request(&self, method: &'static str, path: &str) -> Req {
        Req::new(self.app.clone(), method, path)
            .harnessed(self.local.clone(), backend::logs(&self.state).clone())
    }

    /// The audit row whose message is `message`, waiting for the bridge to
    /// write it.
    ///
    /// # Panics
    ///
    /// If no such row lands within a second.
    pub async fn audit_row(&self, message: &str) -> wslib_appliance_types::AuditRecord {
        audit_row(self.store(), message).await
    }
}

#[cfg(unix)]
pub(crate) async fn bound(socket: &Path) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !socket.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} binds", socket.display()));
}
