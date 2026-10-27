//! Listening: the app socket and the hooks socket beside it, or the ingress
//! listener. Both drain on the token every [`Server::shutdown`](crate::Server::shutdown)
//! handle is a child of, which the caller's stop cancels before the drain.

use axum::Router;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wslib_appliance_core::backend;
use wslib_homeassistant::ingress::Peers;

#[cfg(unix)]
use crate::AppSocket;
use crate::ServeError;

pub(crate) async fn ingress(
    app: Router,
    listener: TcpListener,
    peers: Peers,
    root: CancellationToken,
    stop: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    let _stopped = root.clone().drop_guard();
    let serving = backend::serve_ingress(app, listener, peers, root.clone());
    backend::until_stop(serving, &root, stop).await
}

#[cfg(unix)]
pub(crate) async fn run(
    app: Router,
    hooks: Router,
    socket: AppSocket,
    root: CancellationToken,
    stop: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    // First, so that a socket that will not bind takes the consumer's tasks down too.
    let _stopped = root.clone().drop_guard();
    let console_uid = socket.console_uid;
    let hooks = async {
        match socket.hooks {
            Some(path) => backend::serve_hooks_socket(hooks, path, console_uid, root.clone()).await,
            None => Ok(()),
        }
    };
    // Joined, not spawned: one socket failing stops the appliance rather than leaving it half up.
    let serving = async {
        tokio::try_join!(
            backend::serve_app_socket(app, socket.path, console_uid, root.clone()),
            hooks,
        )
        .map(drop)
    };
    backend::until_stop(serving, &root, stop).await
}

/// Its parent is a file, so `serve` fails after the state is built.
#[cfg(all(test, unix))]
pub(crate) fn unbindable_socket(dir: &tempfile::TempDir) -> AppSocket {
    let blocked = dir.path().join("not-a-directory");
    std::fs::write(&blocked, "").expect("write");
    AppSocket::new(blocked.join("app.sock"), 4242)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_error_exit_from_serving_fires_the_handle_too() {
        let dir = tempfile::tempdir().unwrap();
        let stop = CancellationToken::new();
        let consumer = stop.child_token();
        let outcome = run(
            Router::new(),
            Router::new(),
            unbindable_socket(&dir),
            stop,
            std::future::pending(),
        )
        .await;

        assert!(outcome.is_err(), "{outcome:?}");
        assert!(consumer.is_cancelled());
    }
}
