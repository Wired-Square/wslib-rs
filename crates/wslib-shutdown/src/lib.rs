//! How a service learns it is being stopped: one listener for `SIGTERM` and
//! `SIGINT` (Ctrl-C off unix), registered once, which a service turns into
//! the cancelled token everything else drains on.
//!
//! **A registration that fails does not stop the service.** One that refuses
//! to start because it could not install a signal handler is worse than one
//! that has to be killed to stop, so that half logs and waits forever.

use std::fmt;
use std::future::Future;

use tokio_util::sync::CancellationToken;

/// What asked the process to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Signal {
    /// `SIGTERM`, as systemd and launchd send.
    Terminate,
    /// `SIGINT`, as a terminal's Ctrl-C sends on unix.
    Interrupt,
    /// Ctrl-C on a Windows console.
    CtrlC,
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Signal::Terminate => "SIGTERM",
            Signal::Interrupt => "SIGINT",
            Signal::CtrlC => "Ctrl-C",
        })
    }
}

/// Resolves when the process is asked to stop, naming what asked.
///
/// `SIGTERM` as well as `SIGINT`, because service managers send the former:
/// a service that only handles the latter is always killed rather than
/// stopped. Both handlers are registered at the call, not at the first poll.
#[cfg(unix)]
pub fn stop_signal() -> impl Future<Output = Signal> + Send + 'static {
    use tokio::signal::unix::{SignalKind, signal};

    let terminate = wait_for(Signal::Terminate, signal(SignalKind::terminate()));
    let interrupt = wait_for(Signal::Interrupt, signal(SignalKind::interrupt()));
    async move {
        tokio::select! {
            which = terminate => which,
            which = interrupt => which,
        }
    }
}

#[cfg(unix)]
async fn wait_for(
    which: Signal,
    registered: std::io::Result<tokio::signal::unix::Signal>,
) -> Signal {
    match registered {
        Ok(mut signal) => {
            signal.recv().await;
            which
        }
        Err(e) => registration_failed(which, e).await,
    }
}

/// Resolves on Ctrl-C, registered at the call.
#[cfg(windows)]
pub fn stop_signal() -> impl Future<Output = Signal> + Send + 'static {
    let registered = tokio::signal::windows::ctrl_c();
    async move {
        match registered {
            Ok(mut ctrl_c) => {
                ctrl_c.recv().await;
                Signal::CtrlC
            }
            Err(e) => registration_failed(Signal::CtrlC, e).await,
        }
    }
}

async fn registration_failed(which: Signal, e: std::io::Error) -> Signal {
    tracing::error!(signal = %which, error = %e, "could not listen for a signal");
    std::future::pending().await
}

/// Cancels `token` on the first [`stop_signal`], logging which; the handlers
/// are registered at the call.
pub fn cancel_on_stop(token: CancellationToken) -> impl Future<Output = ()> + Send + 'static {
    let stopping = stop_signal();
    async move {
        let which = stopping.await;
        tracing::info!(signal = %which, "shutting down");
        token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_displays_as_its_conventional_name() {
        assert_eq!(Signal::Terminate.to_string(), "SIGTERM");
        assert_eq!(Signal::Interrupt.to_string(), "SIGINT");
        assert_eq!(Signal::CtrlC.to_string(), "Ctrl-C");
    }

    /// **The only test in this crate that raises a signal**, and it raises it
    /// at its own process: a signal's disposition is process-wide, so this is
    /// safe only because `stop_signal` has registered a handler before the
    /// signal is sent. A second test doing the same would race this one's
    /// handler, and the handler stays for the rest of the test binary's life,
    /// so a harness that `TERM`s a hung run of this suite has to `KILL` it
    /// instead.
    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_is_a_shutdown_rather_than_a_kill() {
        let stopping = stop_signal();

        let sent = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .expect("run kill");
        assert!(sent.success());

        let which = tokio::time::timeout(std::time::Duration::from_secs(5), stopping)
            .await
            .expect("the signal was delivered");
        assert_eq!(which, Signal::Terminate);
    }
}
