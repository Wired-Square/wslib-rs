//! An appliance a consuming crate drives its own routes through, behind the
//! `testing` feature, starting with no accounts; [`Harness::admin`] and
//! [`Harness::signed_in`] make one and sign it in. Requests go through the
//! assembled router, so every extractor, layer and rejection on the path runs.
//!
//! Install a rustls provider before building a harness, which mints its
//! certificate with it and panics without one.
//!
//! The control socket's routes are reached inside [`Req::local`] and nowhere
//! else: there a [`SessionAdmin`](crate::SessionAdmin) route answers 403 where
//! an [`Admin`](crate::Admin) one answers.

use std::path::{Path, PathBuf};

pub use wslib_appliance_core::testing::*;

use axum::Router;
use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::Response;
use std::sync::OnceLock;
use tempfile::TempDir;
use wslib_appliance_core::backend::{self, SESSION_COOKIE};
use wslib_appliance_core::{Built, ControlRouter};
use wslib_appliance_store::Store;
use wslib_appliance_types::Role;

use crate::serve::{self, HttpsPort};
use crate::{About, ApplianceState, CancellationToken, Mount, Server};
use tokio_util::sync::DropGuard;

const LOGO: &[u8] = br#"<svg xmlns="http://www.w3.org/2000/svg"/>"#;

/// Hashed once for the suite, as argon2 is tens of milliseconds.
fn password_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| wslib_appliance_auth::hash_password(Harness::PASSWORD).expect("hash"))
}

/// An appliance on an in-memory database, driven through its real routers.
pub struct Harness {
    state: ApplianceState,
    https: Router,
    port: HttpsPort,
    /// Held, so the minted pair and what the routes wrote go with the harness.
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
    users: bool,
}

impl HarnessBuilder {
    /// As [`Server::users_routes`].
    pub fn users_routes(mut self) -> Self {
        self.users = true;
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

    /// A `Bootstrap` whose configuration directory is this harness's own.
    pub fn bootstrap(&self) -> &wslib_appliance_config::Bootstrap {
        &self.bootstrap
    }

    /// Removed with the harness.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The store the routes run on, with the product's own migrations applied;
    /// the default has the platform's tables alone.
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

    /// As [`Server::origin_port`].
    pub fn origin_port(mut self, port: u16) -> Self {
        self.deferred
            .push(Box::new(move |server| server.origin_port(port)));
        self
    }

    /// As [`Server::ui`].
    pub fn ui(mut self, dir: &Path) -> Self {
        self.ui = Some(dir.to_path_buf());
        self
    }

    #[cfg(test)]
    pub(crate) fn deployed(
        mut self,
        change: impl FnOnce(&mut wslib_appliance_config::Bootstrap),
    ) -> Self {
        change(&mut self.bootstrap);
        self
    }

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

        let port = HttpsPort::new(0);
        let tls = backend::minted_in(&self.dir).await;
        if self.users {
            server = server.users_routes();
        }
        let Built {
            state,
            https,
            control,
            stop,
            tasks: _,
        } = server
            .build(std::sync::Arc::new(tls), port.clone(), &self.bootstrap)
            .await
            .unwrap_or_else(|e| panic!("the harness assembles: {e}"));
        Harness {
            state,
            https,
            port,
            dir: self.dir,
            local: control,
            stop: stop.drop_guard(),
        }
    }
}

impl Harness {
    /// The password every account this harness creates has.
    pub const PASSWORD: &'static str = "correct horse battery";

    #[cfg(test)]
    pub(crate) const NEW_PASSWORD: &'static str = "a whole new password";

    pub(crate) const VERSION: &'static str = "0.0.0 (test)";

    pub async fn new() -> Self {
        Self::builder().build().await
    }

    /// Its bootstrap has `browser_onboarding` on.
    pub fn builder() -> HarnessBuilder {
        let dir = TempDir::new().expect("a directory for the harness");
        let mut bootstrap = bootstrap_in(dir.path());
        bootstrap.browser_onboarding = true;
        HarnessBuilder {
            app_name: "Widget Monitor",
            logo: Some((LOGO, "image/svg+xml")),
            ui: None,
            api: Vec::new(),
            store: None,
            deferred: Vec::new(),
            bootstrap,
            dir,
            routes: Vec::new(),
            users: false,
        }
    }

    /// Serve TLS on loopback as the appliance does, on a port the OS picks, and
    /// answer where. Until this is called, nothing listens.
    pub async fn serve_tls(&self) -> std::net::SocketAddr {
        let mut serving = self.state.https_port();
        tokio::spawn(serve::serve_tls(
            self.port.clone(),
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            self.https.clone(),
            backend::tls_config(&self.state.tls),
            self.stop.token().clone(),
        ));
        let port = *serving
            .wait_for(|&port| port != 0)
            .await
            .expect("the listener binds");
        (std::net::Ipv4Addr::LOCALHOST, port).into()
    }

    /// Take the TLS listener to be serving on `port` without binding it, for a
    /// passkey ceremony at `box.local:{port}`.
    pub fn serving_on(&self, port: u16) {
        self.port.set(port);
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

    /// What [`Server::shutdown`] hands a product: a child that fires when
    /// [`Harness::stop`] is called.
    pub fn shutdown(&self) -> CancellationToken {
        self.stop.token().child_token()
    }

    /// Play the stop `serve` is handed, so a test can assert a product's task ends.
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
        Req::new(self.https.clone(), method, path)
            .harnessed(self.local.clone(), backend::logs(&self.state).clone())
    }

    /// The audit row whose message is `message`; panics if none lands within a
    /// second.
    pub async fn audit_row(&self, message: &str) -> wslib_appliance_types::AuditRecord {
        audit_row(self.store(), message).await
    }

    /// Its id.
    pub async fn create(&self, username: &str, role: Role) -> String {
        self.store()
            .create_user(username, password_hash(), role)
            .await
            .expect("create")
            .id
    }

    fn sign_in_request(&self, username: &str, password: &str) -> Req {
        self.post("/api/session")
            .json(serde_json::json!({ "username": username, "password": password }))
    }

    /// The session token.
    pub(crate) async fn sign_in(&self, username: &str) -> String {
        let response = self.sign_in_request(username, Self::PASSWORD).send().await;
        assert_eq!(response.status(), StatusCode::OK, "sign-in failed");
        Self::session_from(&response).expect("a session cookie")
    }

    pub async fn signs_in(&self, username: &str, password: &str) -> bool {
        self.sign_in_request(username, password)
            .send()
            .await
            .status()
            == StatusCode::OK
    }

    /// An account of `role`, created and signed in: its session token.
    pub async fn signed_in(&self, username: &str, role: Role) -> String {
        self.create(username, role).await;
        self.sign_in(username).await
    }

    pub async fn admin(&self, username: &str) -> String {
        self.signed_in(username, Role::Admin).await
    }

    pub async fn user_id(&self, username: &str) -> String {
        self.store()
            .user_by_username(username)
            .await
            .expect("read")
            .expect("the account exists")
            .user
            .id
    }

    /// The session token a response set; a removal is none.
    pub fn session_from(response: &Response) -> Option<String> {
        let set = response.headers().get(header::SET_COOKIE)?.to_str().ok()?;
        let pair = set.split(';').next()?.trim();
        let token = pair.strip_prefix(SESSION_COOKIE)?.strip_prefix('=')?;
        (!token.is_empty()).then(|| token.to_string())
    }

    pub async fn session_rows(&self) -> i64 {
        let count = format!(
            "SELECT count(*) FROM {}",
            wslib_appliance_store::SESSIONS_TABLE
        );
        wslib_appliance_store::sqlx::query_scalar(&count)
            .fetch_one(self.store().pool())
            .await
            .expect("count the sessions")
    }
}
