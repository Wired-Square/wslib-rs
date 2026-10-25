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
//!
//! A service that stops itself to apply an update cancels the [`Stop::token`],
//! which is a success and tells systemd nothing, returns why, and re-executes
//! once `run` has torn the runtime down:
//!
//! ```no_run
//! # use wslib_service::CancellationToken;
//! # use wslib_service::{Daemon, Stop};
//! # async fn serve(stop: Stop) -> std::io::Result<()> { stop.await; Ok(()) }
//! # fn stage_updates(token: CancellationToken) -> tokio::task::JoinHandle<bool> {
//! #     tokio::spawn(async move { token.cancel(); true })
//! # }
//! enum Stopped {
//!     Asked,
//!     ToApply,
//! }
//!
//! # #[cfg(unix)]
//! fn main() -> std::process::ExitCode {
//!     use std::os::unix::process::CommandExt;
//!
//!     let ran = Daemon::new("widgets").run(|stop: Stop| async move {
//!         // Cancels the token once an update is staged.
//!         let staging = stage_updates(stop.token());
//!         serve(stop).await?;
//!         let staged = staging.is_finished() && staging.await.unwrap_or(false);
//!         Ok::<_, std::io::Error>(if staged { Stopped::ToApply } else { Stopped::Asked })
//!     });
//!     match ran {
//!         Ok(Stopped::ToApply) => {
//!             let failed = std::process::Command::new("/proc/self/exe").exec();
//!             eprintln!("could not re-execute: {failed}");
//!             std::process::ExitCode::FAILURE
//!         }
//!         Ok(Stopped::Asked) => std::process::ExitCode::SUCCESS,
//!         Err(failure) => failure.into(),
//!     }
//! }
//! # #[cfg(not(unix))]
//! # fn main() {}
//! ```

mod file_log;
mod layout;
#[cfg(any(windows, test))]
mod progress;
#[cfg(windows)]
mod scm;
mod signal;
#[cfg(any(target_os = "linux", test))]
mod systemd;
#[cfg(test)]
mod test_dir;
#[cfg(feature = "testing")]
pub mod testing;
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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

pub use file_log::{LogFile, LogFileBuilder};
pub use layout::Layout;
pub use tokio_util::sync::CancellationToken;

const DEFAULT_GRACE: Duration = Duration::from_secs(15);
const TEARDOWN: Duration = Duration::from_secs(1);

type Value = Box<dyn Any + Send>;
type Main = Box<dyn FnOnce(Stop) -> Pin<Box<dyn Future<Output = Result<Value, String>>>> + Send>;

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

    /// How long `main` has to return once stopped, by the service manager or
    /// through [`Stop::token`]; 15 s unless set. It bounds everything `main`
    /// still does after the stop, not only a drain: unadvertising, joining
    /// tasks, flushing. It is the outer bound, so a drain timeout of the app's
    /// own, such as an HTTP server's, must sit inside it. Past it, `main` is
    /// dropped and `run` returns [`Failure::Overran`]. What it tells the
    /// service manager differs:
    ///
    /// - The service control manager: each start raises the service's
    ///   preshutdown timeout to `grace` + 5 s, if it is shorter.
    /// - systemd: a stop it sends is answered with `EXTEND_TIMEOUT_USEC` of
    ///   `grace` + 5 s, so this one setting covers both.
    /// - launchd: nothing. Its `ExitTimeOut` is the plist's, 20 s by default,
    ///   so keep `grace` inside it.
    /// - A container: nothing. Docker and the Home Assistant Supervisor send
    ///   `SIGKILL` 10 s after `SIGTERM` by default, so keep `grace` under 10 s
    ///   there; the 15 s default suits systemd and the service control
    ///   manager.
    pub fn grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Run `main` on a multi-thread Tokio runtime of its own until it ends,
    /// handing back what it returned.
    ///
    /// No runtime is needed before this, and there must not be one on the
    /// calling thread: call it from a plain `fn main`, not `#[tokio::main]`.
    /// Install telemetry first, there or inside `main`. The runtime is the one
    /// `#[tokio::main]` builds, multi-thread with every driver enabled; the
    /// app's own tokio features still apply, through feature unification. A
    /// CLI verb that runs instead of the service belongs before `run`, on a
    /// runtime of its own, since an `Ok` without a stop is
    /// [`Failure::Unasked`].
    ///
    /// **Ending once stopped is `Ok` with what `main` returned. Ending
    /// unasked, by returning or panicking, is a failure**, so that the service
    /// manager restarts it, and so is an error or a panic after the stop, or
    /// overrunning the [`grace`](Self::grace). An error, a panic, ending unasked
    /// or overrunning is logged: through `tracing` once a subscriber is
    /// installed, and before then to stderr, or on Windows the Application
    /// event log under `name`. While `main` runs, the process's panic hook is
    /// one that logs a panic and where it happened, and the previous one is
    /// restored once it returns. Open what can fail, the log file included,
    /// inside `main`, so that its failure is the service's. When `run` returns,
    /// the runtime has been shut down, waiting at most 1 s for its tasks, so
    /// what they held, sockets included, has been dropped. A task `main` left
    /// running gets that second, not the grace.
    ///
    /// The service is ready when `main` first polls its [`Stop`], or, once
    /// [`Stop::ready`] has been taken, when the [`Ready`] says so. The first
    /// time logs one `info` line naming the [`Manager`]. How it stops is the
    /// manager's:
    ///
    /// - **Under the Windows service control manager**, the service is reported
    ///   as starting, with a checkpoint each second, until it is ready, then as
    ///   running, then as stopping, with a checkpoint each second, from the
    ///   stop until `main` returns. A stop, a preshutdown or a shutdown control
    ///   is the stop, and so is cancelling [`Stop::token`]. A failure is
    ///   reported with a service-specific exit code; what follows is the
    ///   installer's to set, such as a restart after 5 s with
    ///   `sc failure <name> reset= 86400 actions= restart/5000`, and
    ///   `sc failureflag <name> 1` so that an exit code counts as a failure. A
    ///   stop the manager or the app asked for is not a failure unless `main`
    ///   overruns its grace. A start that finds no failure actions logs a
    ///   warning. An error or a panic always goes to the Application event log
    ///   under `name` as well; a warning goes there only while no subscriber is
    ///   installed. A start that finds `name` unregistered as that log's event
    ///   source registers it, so that Event Viewer shows each message as
    ///   written, and keeps an installer's registration. Registering needs
    ///   write access to HKLM, as LocalSystem has; a start that cannot logs a
    ///   warning, so a service under another account has its installer
    ///   register the source.
    /// - **On Windows, not started by the service control manager**, `main`
    ///   runs in the console, and Ctrl-C is the stop.
    /// - **Under systemd**, with `$NOTIFY_SOCKET` set on Linux, ready sends
    ///   `READY=1`, and `SIGTERM` or `SIGINT` is the stop, answered with
    ///   `STOPPING=1` and `EXTEND_TIMEOUT_USEC` of the grace + 5 s. A stop
    ///   through [`Stop::token`] sends nothing, so a process that re-executes
    ///   itself keeps its unit running. When systemd asked for a watchdog, it
    ///   is fed from the start of `run` until `main` returns, the drain
    ///   included, since systemd times it from the process's start. It is fed
    ///   from a task of its own, so it shows the runtime is alive, not that
    ///   the service is serving.
    ///   `$NOTIFY_SOCKET` and `$WATCHDOG_USEC` are left set, for a process
    ///   that re-executes itself.
    /// - **Otherwise, as under launchd**, `SIGTERM` or `SIGINT` is the stop,
    ///   logged at `info`. Both handlers are registered before `main` is
    ///   called, so a signal sent while it starts stops it once it is ready.
    pub fn run<F, Fut, T, E>(self, main: F) -> Result<T, Failure>
    where
        F: FnOnce(Stop) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + 'static,
        T: Send + 'static,
        E: Display,
    {
        let main: Main = Box::new(|stop| {
            Box::pin(async {
                match main(stop).await {
                    Ok(value) => Ok(Box::new(value) as Value),
                    Err(e) => Err(format!("{e:#}")),
                }
            })
        });
        #[cfg(windows)]
        let ran = match scm::run(&self.name, self.grace, main) {
            Ok(ran) => ran,
            Err(not_a_service) => self.run_signalled(not_a_service),
        };
        #[cfg(not(windows))]
        let ran = self.run_signalled(main);
        ran.map(|value| *value.downcast().expect("the value `main` returned"))
    }

    fn run_signalled(self, main: Main) -> Result<Value, Failure> {
        let grace = self.grace;
        let manager = CancellationToken::new();
        drive(&self.name, grace, manager.clone(), main, move |token| {
            #[cfg(target_os = "linux")]
            let systemd =
                std::env::var_os("NOTIFY_SOCKET").is_some_and(|socket| !socket.is_empty());
            let signalled = signal::stop_signal();
            tokio::spawn(async move {
                let signal = signalled.await;
                tracing::info!(signal = signal.as_str(), ?grace, "stopping");
                #[cfg(target_os = "linux")]
                if systemd {
                    systemd::stopping(grace, wslib_systemd_notify::notify);
                }
                manager.cancel();
            });
            #[cfg(target_os = "linux")]
            if systemd {
                tokio::spawn(async {
                    let fed = wslib_systemd_notify::feed_watchdog(std::future::pending());
                    if let Err(e) = fed.await {
                        tracing::warn!(error = %e, "could not feed systemd's watchdog");
                    }
                });
                return Stop::new(
                    Manager::Systemd,
                    token,
                    systemd::Systemd(wslib_systemd_notify::notify),
                );
            }
            let manager = if cfg!(windows) {
                Manager::WindowsConsole
            } else {
                Manager::Signals
            };
            Stop::new(manager, token, Untold)
        })
    }
}

/// Runs `main` with the `Stop` that `stop` makes from a child of `manager`,
/// the token the service manager's stop cancels, inside the runtime, and
/// judges how it ended by whether the child was cancelled.
fn drive(
    name: &str,
    grace: Duration,
    manager: CancellationToken,
    main: Main,
    stop: impl FnOnce(CancellationToken) -> Stop,
) -> Result<Value, Failure> {
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
    let token = manager.child_token();
    let ran = std::panic::catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            tokio::spawn({
                let token = token.clone();
                async move {
                    token.cancelled().await;
                    if !manager.is_cancelled() {
                        tracing::info!(?grace, "stopping, by the service itself");
                    }
                }
            });
            let overran = async {
                token.cancelled().await;
                tokio::time::sleep(grace).await;
            };
            tokio::select! {
                biased;
                ended = main(stop(token.clone())) => Some(ended),
                () = overran => None,
            }
        })
    }));
    std::panic::set_hook(previous);
    runtime.shutdown_timeout(TEARDOWN);

    let asked = token.is_cancelled();
    let failure = match ran {
        Err(_recorded_by_the_hook) => return Err(Failure::Panicked),
        Ok(None) => Failure::Overran(grace),
        Ok(Some(Err(e))) => Failure::Ended(e),
        Ok(Some(Ok(value))) if asked => return Ok(value),
        Ok(Some(Ok(_))) => Failure::Unasked,
    };
    error(name, &failure);
    Err(failure)
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
    /// Under no manager: a `Stop` from `testing::stop`.
    Detached,
}

impl Manager {
    pub fn as_str(&self) -> &'static str {
        match self {
            Manager::WindowsService => "the service control manager",
            Manager::WindowsConsole => "a console",
            Manager::Systemd => "systemd",
            Manager::Signals => "signals",
            Manager::Detached => "no service manager",
        }
    }
}

impl Display for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the service manager is told as the service runs.
trait Tell: Send + Sync {
    fn ready(&self, status: Option<&str>);
    fn status(&self, _: &str) {}
}

impl<T: Tell + ?Sized> Tell for Arc<T> {
    fn ready(&self, status: Option<&str>) {
        (**self).ready(status);
    }

    fn status(&self, status: &str) {
        (**self).status(status);
    }
}

struct Untold;

impl Tell for Untold {
    fn ready(&self, _: Option<&str>) {}
}

struct Shared {
    manager: Manager,
    tell: Box<dyn Tell>,
    explicit: AtomicBool,
    readied: AtomicBool,
}

impl Shared {
    fn ready(&self, status: Option<&str>) {
        if !self.readied.swap(true, Ordering::SeqCst) {
            tracing::info!(under = self.manager.as_str(), "serving");
            self.tell.ready(status);
        } else if let Some(status) = status {
            self.tell.status(status);
        }
    }
}

/// Completes when the service is stopped: by the service manager, or by
/// cancelling its [`token`](Self::token).
///
/// **The first poll tells the service manager the service is ready**, as
/// running to the service control manager and `READY=1` to systemd, so poll it
/// only once serving has started, or take [`ready`](Self::ready) to say so
/// yourself. That holds on every platform.
pub struct Stop {
    shared: Arc<Shared>,
    token: CancellationToken,
    polled: bool,
    stopped: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Stop {
    fn new(manager: Manager, token: CancellationToken, tell: impl Tell + 'static) -> Self {
        Self {
            shared: Arc::new(Shared {
                manager,
                tell: Box::new(tell),
                explicit: AtomicBool::new(false),
                readied: AtomicBool::new(false),
            }),
            stopped: Box::pin({
                let token = token.clone();
                async move { token.cancelled().await }
            }),
            token,
            polled: false,
        }
    }

    pub fn manager(&self) -> Manager {
        self.shared.manager
    }

    /// The handle that says when the service is ready, for when that is not
    /// when this is first polled. Taking it turns ready-on-first-poll off; it
    /// borrows, so take it before `stop` moves into a serve call, or into a
    /// library: once the first poll has said ready, taking it cannot undo
    /// that.
    pub fn ready(&self) -> Ready {
        self.shared.explicit.store(true, Ordering::SeqCst);
        Ready(self.shared.clone())
    }

    /// Cancelled when the service manager asks the service to stop. Cancelling
    /// it is a stop of the app's own: success, under the same grace, and on
    /// systemd sent as nothing, so the unit is not stopped with it.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

impl Future for Stop {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if !std::mem::replace(&mut self.polled, true)
            && !self.shared.explicit.load(Ordering::SeqCst)
        {
            self.shared.ready(None);
        }
        self.stopped.as_mut().poll(cx)
    }
}

impl std::fmt::Debug for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stop")
            .field("manager", &self.shared.manager)
            .finish_non_exhaustive()
    }
}

/// Tells the service manager the service is ready, taken from
/// [`Stop::ready`]: running to the service control manager, `READY=1` to
/// systemd, and nothing under launchd or in a console. One from a dropped
/// `Stop`, or a test's detached one, tells nobody, which is supported: a
/// harness can take `testing::stop().0.ready()` as a `Ready` that goes nowhere.
#[derive(Clone)]
pub struct Ready(Arc<Shared>);

impl Ready {
    /// The service is ready, with `status` as systemd's `STATUS=` in the same
    /// notification. Ready is said once: a later `send`, or one after the
    /// first poll said it, sends only its `status`, and under the service
    /// control manager nothing. The service control manager has no status
    /// text.
    pub fn send(&self, status: Option<&str>) {
        self.0.ready(status);
    }

    /// A `STATUS=` line for `systemctl status`, at any time; only systemd
    /// shows it.
    pub fn status(&self, status: &str) {
        self.0.tell.status(status);
    }
}

impl std::fmt::Debug for Ready {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ready").field(&self.0.manager).finish()
    }
}

/// How [`Daemon::run`] failed: the service ended unasked, badly or late, or
/// could not run at all.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// `main` returned this error, before or after the stop.
    #[error("the service ended in error: {0}")]
    Ended(String),

    #[error("the service ended without being asked to stop")]
    Unasked,

    /// `main` panicked; the hook logged where.
    #[error("the service panicked")]
    Panicked,

    /// `main` was still running its grace after the stop, and was dropped.
    #[error("the service did not end within its grace of {0:?} once stopped")]
    Overran(Duration),

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
#[non_exhaustive]
pub struct Refused {
    pub path: PathBuf,
    pub because: String,
}

impl Refused {
    /// `because` is the sentence the refusal ends with, such as "it is a
    /// symbolic link".
    pub fn new(path: impl Into<PathBuf>, because: impl Into<String>) -> Self {
        Self {
            path: path.into(),
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

/// Refuses `path` if it carries an extended ACL, as one a group or anyone else
/// could be let in by; `Ok` off macOS, where the mode says it all.
#[cfg(unix)]
pub fn no_extended_acl(path: impl AsRef<Path>) -> Result<(), Refused> {
    let path = path.as_ref();
    unix::no_extended_acl(path).map_err(|because| Refused::new(path, because))
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

    #[derive(Clone, Default)]
    struct Told(Arc<std::sync::Mutex<Vec<String>>>);

    impl Tell for Told {
        fn ready(&self, status: Option<&str>) {
            self.0.lock().unwrap().push(format!("ready {status:?}"));
        }

        fn status(&self, status: &str) {
            self.0.lock().unwrap().push(format!("status {status}"));
        }
    }

    fn polled_once(stop: &mut Stop) {
        let waker = std::task::Waker::noop();
        let _ = Pin::new(stop).poll(&mut Context::from_waker(waker));
    }

    #[test]
    fn the_first_poll_says_ready_once_unless_the_handle_was_taken() {
        let told = Told::default();
        let mut stop = Stop::new(Manager::Signals, CancellationToken::new(), told.clone());
        polled_once(&mut stop);
        polled_once(&mut stop);
        stop.ready().send(Some("late"));
        assert_eq!(*told.0.lock().unwrap(), ["ready None", "status late"]);

        let told = Told::default();
        let mut stop = Stop::new(Manager::Signals, CancellationToken::new(), told.clone());
        let ready = stop.ready();
        polled_once(&mut stop);
        ready.send(Some("x"));
        ready.send(None);
        assert_eq!(*told.0.lock().unwrap(), [r#"ready Some("x")"#]);
    }

    #[test]
    fn a_failure_is_a_failing_exit_code() {
        assert_eq!(ExitCode::from(Failure::Unasked), ExitCode::FAILURE);
    }
}
