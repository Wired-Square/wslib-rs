//! **A registration that fails does not stop the service.** One that refuses
//! to start because it could not install a signal handler is worse than one
//! that has to be killed to stop, so that half logs and waits forever.

use std::future::Future;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Signal {
    #[cfg(unix)]
    Terminate,
    #[cfg(unix)]
    Interrupt,
    #[cfg(windows)]
    CtrlC,
}

impl Signal {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            #[cfg(unix)]
            Signal::Terminate => "SIGTERM",
            #[cfg(unix)]
            Signal::Interrupt => "SIGINT",
            #[cfg(windows)]
            Signal::CtrlC => "Ctrl-C",
        }
    }
}

/// Both handlers are registered at the call, not at the first poll.
#[cfg(unix)]
pub(crate) fn stop_signal() -> impl Future<Output = Signal> + Send + 'static {
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

#[cfg(windows)]
pub(crate) fn stop_signal() -> impl Future<Output = Signal> + Send + 'static {
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
    tracing::error!(signal = which.as_str(), error = %e, "could not listen for a signal");
    std::future::pending().await
}
