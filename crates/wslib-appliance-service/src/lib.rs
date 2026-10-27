//! An appliance as a desktop service: the router served on control endpoints
//! alone, with no network listener, TLS, sign-in or onboarding, so a request
//! may do what its endpoint's ceiling allows. Who may open an endpoint is its
//! directory's group on macOS and the pipe's granted group on Windows.
//!
//! ```no_run
//! # use wslib_appliance_service::{LocalBootstrap, LocalError, Service};
//! # use wslib_appliance_types::Branding;
//! fn main() -> std::process::ExitCode {
//!     let _ = rustls::crypto::ring::default_provider().install_default();
//!     let bootstrap = LocalBootstrap::macos("My Appliance", "myappliance");
//!     wslib_appliance_service::daemon("myappliance")
//!         .run(|stop| async move {
//!             let logs = wslib_appliance_service::install_logs(&bootstrap.log_file, &["myappliance"])?;
//!             let store = bootstrap.open_store(None).await?;
//!             Service::new(store, Branding::unbranded(), "1.0.0 (abc1234)", logs)
//!                 .serve_local(&bootstrap, stop)
//!                 .await?;
//!             Ok::<_, LocalError>(())
//!         })
//!         .map_or_else(std::process::ExitCode::from, |()| std::process::ExitCode::SUCCESS)
//! }
//! ```
//!
//! This crate installs no rustls provider. Install one before serving, or
//! [`Service::serve_local`] refuses with [`ServeError::NoCryptoProvider`].
//! The Logs screen is mounted at `Admin`, so an Admin-ceiling endpoint's group
//! reads the daemon's scrollback; `SessionAdmin` refuses every endpoint.

mod bootstrap;
#[cfg(unix)]
mod checks;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use wslib_appliance_core::backend::{self, LogsRung};
use wslib_appliance_core::{AboveAdmin, Backend, Chassis};
use wslib_appliance_store::{Store, StoreError};
use wslib_appliance_types::Branding;
use wslib_service::{Daemon, LogFile, Refused};
use wslib_telemetry::Telemetry;

pub use bootstrap::{LocalBootstrap, LocalEndpoint};
pub use wslib_appliance_core::{
    About, ApplianceState, CancellationToken, LocalMount, Logs, Mount, ServeError, logs,
};

/// The [`Daemon`] to run [`Service::serve_local`] under, whose grace outlasts
/// the endpoints' own, so theirs ends the drain.
pub fn daemon(name: &str) -> Daemon {
    Daemon::new(name).grace(backend::GRACE + Duration::from_secs(2))
}

/// A ring capturing the family's crates and `crates`, and its subscriber,
/// filtered by `RUST_LOG` (`info` when unset), appending to the [`LogFile`] at
/// `path`. Panics if a global subscriber or `log` logger is already installed.
pub fn install_logs(path: &Path, crates: &[&str]) -> Result<Logs, LocalError> {
    let file = Arc::new(LogFile::open(path)?);
    let logs = backend::logs_writing_to(crates, path);
    logs.feed(Telemetry::new("info").writer(file)).init();
    Ok(logs)
}

/// Why the service would not start, or stopped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LocalError {
    /// A path of the installer's layout, or the log file, that fails its check.
    #[error(transparent)]
    Refused(#[from] Refused),

    #[error("there is no control endpoint to serve")]
    NoEndpoints,

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Serve(#[from] ServeError),
}

impl LocalError {
    #[cfg(unix)]
    pub(crate) fn refused(path: &Path, because: impl Into<String>) -> Self {
        Self::Refused(Refused::new(path, because))
    }
}

/// The appliance's router, assembled for [`serve_local`](Self::serve_local).
pub struct Service {
    chassis: Chassis,
}

impl Service {
    /// `version` is the product's `wslib_build_id::build_version!()`, expanded
    /// in its own crate; `logs` is what [`install_logs`] handed back.
    pub fn new(store: Store, branding: Branding, version: &str, logs: Logs) -> Self {
        Self {
            chassis: Chassis::new(store, branding, version, logs),
        }
    }

    /// As `Server::shutdown`: a child that fires when the service is stopping.
    pub fn shutdown(&self) -> CancellationToken {
        self.chassis.shutdown()
    }

    /// As `Server::logo`.
    pub fn logo(self, bytes: impl Into<Bytes>, content_type: &str) -> Self {
        self.with(|chassis| chassis.logo(bytes, content_type))
    }

    /// As `Server::about`.
    pub fn about(self, rows: impl About) -> Self {
        self.with(|chassis| chassis.about(rows))
    }

    /// As `Server::api`.
    pub fn api(self, routes: impl Into<Mount>) -> Self {
        self.with(|chassis| chassis.api(routes))
    }

    /// Routes that a backend with accounts refuses to serve.
    pub fn local_api(self, routes: LocalMount) -> Self {
        self.with(|chassis| chassis.local_api(routes))
    }

    /// As `Server::task`, except that the grace a task gets once stopped is
    /// the one the endpoints drain in, not a second one after it.
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

    /// Serve every endpoint of `bootstrap` until `stop` completes or one fails.
    ///
    /// Before anything binds, refuses a layout [`LocalBootstrap`] and
    /// [`LocalEndpoint`] refuse, then a process with no rustls provider. An
    /// unpinned dial before the OS trust store loads waits for it, at most 30 s.
    /// `stop` is first polled once every endpoint listens; from it, connections
    /// and tasks share one grace, inside launchd's default `ExitTimeOut` of
    /// 20 s. Every [`shutdown`](Self::shutdown) handle has fired on return.
    pub async fn serve_local(
        self,
        bootstrap: &LocalBootstrap,
        stop: impl Future<Output = ()>,
    ) -> Result<(), LocalError> {
        bootstrap.check().await?;
        #[cfg(test)]
        let _ = rustls::crypto::ring::default_provider().install_default();
        let built = self
            .chassis
            .ui(bootstrap.ui.clone())
            .build(Backend {
                callers: backend::Callers::nobody(),
                logs: LogsRung::Admin,
                tls: Arc::new(backend::no_tls()),
                listening: None,
                onboarding: false,
                names_the_box: false,
                above_admin: AboveAdmin::Absent,
                routes: Vec::new(),
                control_routes: Vec::new(),
            })
            .await?;
        let endpoints = bootstrap.control_endpoints();

        let mut stopped_at = None;
        let served = {
            let _stopped = built.stop.clone().drop_guard();
            let serving = backend::serve_control(built.control, endpoints, built.stop.clone());
            let stop = async {
                stop.await;
                stopped_at = Some(tokio::time::Instant::now());
            };
            backend::until_stop(serving, &built.stop, stop).await
        };
        let deadline = stopped_at.unwrap_or_else(tokio::time::Instant::now) + backend::GRACE;
        backend::close_audit_queue(backend::logs(&built.state));
        backend::join_tasks(built.tasks, deadline).await;
        Ok(served?)
    }
}
