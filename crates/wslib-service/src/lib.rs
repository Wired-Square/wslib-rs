//! A background service under launchd, systemd or the Windows service control
//! manager from one call: [`Daemon::run`] starts a runtime, hands `main` a
//! [`Stop`] that completes when the service manager asks the service to stop,
//! and judges how it ended. Beside it, the checks a service's own files need:
//! [`private_directory`] for its state, [`LogFile`] for its log where nothing
//! keeps a daemon's output, and the platforms' [`Layout`]s.
//!
//! ```no_run
//! use std::process::ExitCode;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use wslib_service::{Daemon, Layout, LogFile, Stop};
//!
//! # async fn serve(stop: Stop) -> std::io::Result<()> { stop.await; Ok(()) }
//! fn main() -> ExitCode {
//!     Daemon::new("widgets")
//!         .grace(Duration::from_secs(15))
//!         .run(|stop: Stop| async move {
//!             let layout = Layout::for_this_os("Widget Monitor", "widgets");
//!             if let Some(path) = &layout.log_file {
//!                 let log = Arc::new(LogFile::open(path)?);
//!                 wslib_telemetry::Telemetry::new("info").writer(log).init();
//!             } else {
//!                 wslib_telemetry::Telemetry::new("info").init();
//!             }
//!             let _held = wslib_service::private_directory(&layout.state_dir)?;
//!             serve(stop).await?;
//!             Ok::<_, Box<dyn std::error::Error>>(())
//!         })
//!         .map_or_else(ExitCode::from, |()| ExitCode::SUCCESS)
//! }
//! ```
//!
//! An app with a serve loop of its own takes `stop` as the future it ends on,
//! polled once it is listening:
//!
//! ```no_run
//! # use wslib_service::{Daemon, Stop};
//! # struct Server;
//! # impl Server {
//! #     async fn bind() -> std::io::Result<Self> { Ok(Server) }
//! #     async fn serve_until(self, stop: impl std::future::Future<Output = ()>) -> std::io::Result<()> {
//! #         stop.await;
//! #         Ok(())
//! #     }
//! # }
//! # fn main() -> Result<(), wslib_service::Failure> {
//! Daemon::new("widgets").run(|stop: Stop| async move {
//!     let server = Server::bind().await?;
//!     server.serve_until(stop).await
//! })
//! # }
//! ```

mod file_log;
mod layout;
#[cfg(any(windows, test))]
mod progress;
#[cfg(windows)]
mod scm;
#[cfg(any(target_os = "linux", test))]
mod systemd;
#[cfg(test)]
mod test_dir;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::any::Any;
use std::fmt::Display;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

pub use file_log::{LogFile, LogFileBuilder};
pub use layout::Layout;

const DEFAULT_GRACE: Duration = Duration::from_secs(15);

type Main = Box<dyn FnOnce(Stop) -> Pin<Box<dyn Future<Output = Result<(), String>>>> + Send>;

/// A service to run as `name`, under whichever service manager started it.
#[derive(Clone, Debug)]
#[must_use = "nothing runs until `run`"]
pub struct Daemon {
    name: String,
    grace: Duration,
}

impl Daemon {
    /// `name` is the service's: the Windows service and event source, and the
    /// `service` field of what this logs.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            grace: DEFAULT_GRACE,
        }
    }

    /// How long `main` takes to end once its [`Stop`] completes, 15 s unless
    /// set. It is `main`'s to keep; what it tells the service manager differs:
    ///
    /// - The service control manager: each start raises the service's
    ///   preshutdown timeout to `grace` + 5 s, if it is shorter.
    /// - systemd: the stop sends `EXTEND_TIMEOUT_USEC` of `grace` + 5 s.
    /// - launchd: nothing. Its `ExitTimeOut` is the plist's, 20 s by default,
    ///   so keep `grace` inside it.
    pub fn grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Run `main` on a multi-thread Tokio runtime of its own until it ends.
    ///
    /// **Ending once asked to stop is success, however `main` ended. Ending
    /// unasked, by returning or panicking, is a failure**, so that the service
    /// manager restarts it. An error, a panic or ending unasked is logged:
    /// through `tracing` once a subscriber is installed, and before then to
    /// stderr, or on Windows the Application event log under `name`. While
    /// `main` runs, the process's panic hook is one that logs a panic and where
    /// it happened, and the previous one is restored once it returns. Open what
    /// can fail, the log file included, inside `main`, so that its failure is
    /// the service's.
    ///
    /// The first poll of the [`Stop`] logs one `info` line naming the
    /// [`Manager`] and tells it the service is ready; how it stops is the
    /// manager's:
    ///
    /// - **Under the Windows service control manager**, the service is reported
    ///   as starting, with a checkpoint each second, until `main` first polls
    ///   its `Stop`, then as running, then as stopping, with a checkpoint each
    ///   second, from the stop until `main` returns. A stop, a preshutdown or a
    ///   shutdown completes the `Stop`. A failure is reported with a
    ///   service-specific exit code; what follows is the installer's to set,
    ///   such as a restart after 5 s with
    ///   `sc failure <name> reset= 86400 actions= restart/5000`, and
    ///   `sc failureflag <name> 1` so that an exit code counts as a failure. A
    ///   start that finds no failure actions logs a warning. An error or a
    ///   panic always goes to the Application event log under `name` as well;
    ///   a warning goes there only while no subscriber is installed. A start
    ///   that finds `name` unregistered as that log's event source registers
    ///   it, so that Event Viewer shows each message as written, and keeps an
    ///   installer's registration. Registering needs write access to HKLM, as
    ///   LocalSystem has; a start that cannot logs a warning, so a service
    ///   under another account has its installer register the source.
    /// - **On Windows, not started by the service control manager**, `main`
    ///   runs in the console, and Ctrl-C is the stop.
    /// - **Under systemd**, with `$NOTIFY_SOCKET` set on Linux, the first poll
    ///   sends `READY=1`, and the stop `STOPPING=1` with `EXTEND_TIMEOUT_USEC`
    ///   of the grace + 5 s. The watchdog is fed while `main` runs, when
    ///   systemd asked for one.
    /// - **Otherwise, as under launchd**, `SIGTERM` or `SIGINT` is the stop,
    ///   logged at `info`. Both handlers are registered before `main` is
    ///   called, so a signal sent while it starts stops it once it polls the
    ///   `Stop`.
    pub fn run<F, Fut, E>(self, main: F) -> Result<(), Failure>
    where
        F: FnOnce(Stop) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + 'static,
        E: Display,
    {
        let main: Main =
            Box::new(|stop| Box::pin(async { main(stop).await.map_err(|e| e.to_string()) }));
        #[cfg(windows)]
        let main = match scm::run(&self.name, self.grace, main) {
            Ok(ran) => return ran,
            Err(not_a_service) => not_a_service,
        };
        self.run_signalled(main)
    }

    fn run_signalled(self, main: Main) -> Result<(), Failure> {
        let requested = CancellationToken::new();
        let stop = {
            let requested = requested.clone();
            move || {
                let signalled = wslib_shutdown::stop_signal();
                tokio::spawn({
                    let requested = requested.clone();
                    async move {
                        let signal = signalled.await;
                        tracing::info!(signal = signal.as_str(), grace = ?self.grace, "stopping");
                        requested.cancel();
                    }
                });
                #[cfg(target_os = "linux")]
                if std::env::var_os("NOTIFY_SOCKET").is_some_and(|socket| !socket.is_empty()) {
                    tokio::spawn(async {
                        let fed = wslib_systemd_notify::feed_watchdog(std::future::pending());
                        if let Err(e) = fed.await {
                            tracing::warn!(error = %e, "could not feed systemd's watchdog");
                        }
                    });
                    return Stop::new(
                        Manager::Systemd,
                        systemd::stop(requested, self.grace, wslib_systemd_notify::notify),
                    );
                }
                let manager = if cfg!(windows) {
                    Manager::WindowsConsole
                } else {
                    Manager::Signals
                };
                Stop::new(manager, async move { requested.cancelled().await })
            }
        };
        drive(&self.name, &requested, main, stop)
    }
}

/// Runs `main` with the `Stop` that `stop` makes, inside the runtime, and
/// judges how it ended by whether `requested` was cancelled.
fn drive(
    name: &str,
    requested: &CancellationToken,
    main: Main,
    stop: impl FnOnce() -> Stop,
) -> Result<(), Failure> {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            let failure = Failure::Runtime(e);
            error(name, &failure);
            return Err(failure);
        }
    };
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new({
        let name = name.to_string();
        move |panic| {
            let at = panic.location().map(|at| format!(" at {at}"));
            error(
                &name,
                format_args!(
                    "a thread of the service panicked{}: {}",
                    at.unwrap_or_default(),
                    panic_message(panic.payload())
                ),
            );
        }
    }));
    let ran = std::panic::catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async { main(stop()).await })
    }));
    std::panic::set_hook(previous);
    runtime.shutdown_background();

    let asked = requested.is_cancelled();
    let failure = match ran {
        Err(_recorded_by_the_hook) => Failure::Panicked,
        Ok(Err(e)) => Failure::Ended(e),
        Ok(Ok(())) if asked => return Ok(()),
        Ok(Ok(())) => Failure::Unasked,
    };
    if !matches!(failure, Failure::Panicked) {
        error(name, &failure);
    }
    if asked { Ok(()) } else { Err(failure) }
}

fn panic_message(panic: &(dyn Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("no message")
}

fn subscribed() -> bool {
    !tracing::dispatcher::get_default(|d| d.is::<tracing::subscriber::NoSubscriber>())
}

#[cfg(windows)]
fn error(service: &str, message: impl Display) {
    scm::record(service, scm::Level::Error, message);
}

#[cfg(not(windows))]
fn error(service: &str, message: impl Display) {
    if subscribed() {
        tracing::error!(%service, "{message}");
    } else {
        eprintln!("{service}: {message}");
    }
}

/// How [`Daemon::run`] ran, as the [`Stop`] knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Manager {
    /// Under the Windows service control manager.
    WindowsService,
    /// On Windows, in a console, stopped by Ctrl-C.
    WindowsConsole,
    /// Under systemd, told through `$NOTIFY_SOCKET`.
    Systemd,
    /// Stopped by `SIGTERM` or `SIGINT`, as under launchd.
    Signals,
}

impl Manager {
    pub fn as_str(&self) -> &'static str {
        match self {
            Manager::WindowsService => "the service control manager",
            Manager::WindowsConsole => "a console",
            Manager::Systemd => "systemd",
            Manager::Signals => "signals",
        }
    }
}

impl Display for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Completes when the service manager asks the service to stop.
///
/// **The first poll tells the service manager the service is ready**, as
/// running to the service control manager and `READY=1` to systemd, so poll it
/// only once serving has started. That holds on every platform.
pub struct Stop {
    manager: Manager,
    stopping: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Stop {
    fn new(manager: Manager, stopping: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            manager,
            stopping: Box::pin(async move {
                tracing::info!(under = manager.as_str(), "serving");
                stopping.await;
            }),
        }
    }

    pub fn manager(&self) -> Manager {
        self.manager
    }
}

impl Future for Stop {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.stopping.as_mut().poll(cx)
    }
}

impl std::fmt::Debug for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stop")
            .field("manager", &self.manager)
            .finish_non_exhaustive()
    }
}

/// How [`Daemon::run`] failed: the service ended without being asked to, or
/// could not run at all.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// `main` returned this error, unasked.
    #[error("the service ended in error: {0}")]
    Ended(String),

    #[error("the service ended without being asked to stop")]
    Unasked,

    /// `main` panicked, unasked; the hook logged where.
    #[error("the service panicked")]
    Panicked,

    #[error("could not start a runtime: {0}")]
    Runtime(std::io::Error),

    /// The service control manager's dispatcher failed, other than by the
    /// process not having been started by it.
    #[error("could not run as a Windows service: {0}")]
    ServiceManager(std::io::Error),
}

impl From<Failure> for ExitCode {
    fn from(_: Failure) -> Self {
        ExitCode::FAILURE
    }
}

/// A directory or file of the service's that fails its check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("refusing {}: {because}", path.display())]
pub struct Refused {
    pub path: PathBuf,
    pub because: String,
}

impl Refused {
    fn new(path: &Path, because: impl Into<String>) -> Self {
        Self {
            path: path.to_path_buf(),
            because: because.into(),
        }
    }
}

/// The service's state directory, checked rather than trusted.
///
/// On unix: a directory, not a link to one, owned by this process's user, that
/// its group cannot write and others cannot use at all, with no extended ACL on
/// macOS.
///
/// On Windows: a directory, not a link or junction, owned by this process's
/// user, SYSTEM or Administrators, whose DACL grants nobody else anything, in a
/// directory with the same owners that nobody else may delete from, rename or
/// change the security of. Both stay open until the [`Held`] drops, so neither
/// can be renamed; keep it for as long as the directory is used.
pub fn private_directory(dir: impl AsRef<Path>) -> Result<Held, Refused> {
    let dir = dir.as_ref();
    #[cfg(unix)]
    return unix::private_directory(dir)
        .map(|()| Held {})
        .map_err(|because| Refused::new(dir, because));
    #[cfg(windows)]
    return windows::private_directory(dir).map(|handles| Held { _handles: handles });
}

/// What [`private_directory`] holds open: on Windows the directory and its
/// parent, and on unix nothing.
#[derive(Debug)]
#[must_use = "on Windows the directory may be renamed once this drops"]
pub struct Held {
    #[cfg(windows)]
    _handles: [std::fs::File; 2],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_reads_refusing_the_path_because() {
        let refused = Refused::new(Path::new("/var/lib/widgets"), "it is a symbolic link");
        assert_eq!(
            refused.to_string(),
            "refusing /var/lib/widgets: it is a symbolic link"
        );
    }

    #[test]
    fn a_failure_is_a_failing_exit_code() {
        assert_eq!(ExitCode::from(Failure::Unasked), ExitCode::FAILURE);
    }
}
