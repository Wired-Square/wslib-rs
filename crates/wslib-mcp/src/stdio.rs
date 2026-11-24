//! The stdio transport: newline-delimited JSON-RPC on stdin/stdout until the
//! peer closes. Nothing else may write to stdout while a server is running.

use std::error::Error;
use std::fmt;

use rmcp::ServerHandler;
use rmcp::service::{QuitReason, ServerInitializeError, ServiceExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinError;

#[derive(Debug)]
#[non_exhaustive]
pub enum StdioError {
    Initialize(Box<ServerInitializeError>),
    /// The MCP service task panicked.
    Panicked,
    /// The runtime cancelled the MCP service task before it finished.
    Cancelled,
}

impl fmt::Display for StdioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialize(_) => f.write_str("MCP initialise failed"),
            Self::Panicked => f.write_str("the MCP service task panicked"),
            Self::Cancelled => f.write_str("the MCP service task was cancelled"),
        }
    }
}

impl Error for StdioError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Initialize(e) => Some(&**e),
            Self::Panicked | Self::Cancelled => None,
        }
    }
}

impl From<Box<ServerInitializeError>> for StdioError {
    fn from(e: Box<ServerInitializeError>) -> Self {
        Self::Initialize(e)
    }
}

fn joined(e: JoinError) -> StdioError {
    if e.is_panic() {
        StdioError::Panicked
    } else {
        StdioError::Cancelled
    }
}

pub async fn serve<S: ServerHandler + Send + 'static>(server: S) -> Result<(), StdioError> {
    serve_io(server, rmcp::transport::stdio()).await
}

/// The same server over any read/write pair — a unix socket, or
/// `tokio::io::duplex` in tests.
pub async fn serve_io<S, R, W>(server: S, io: (R, W)) -> Result<(), StdioError>
where
    S: ServerHandler + Send + 'static,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let running = server.serve(io).await.map_err(Box::new)?;
    match running.waiting().await.map_err(joined)? {
        QuitReason::JoinError(e) => Err(joined(e)),
        reason => {
            tracing::debug!(?reason, "MCP stdio server finished");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Idle;

    impl ServerHandler for Idle {}

    #[tokio::test]
    async fn a_peer_gone_before_initialise_keeps_rmcps_error() {
        let (peer, ours) = tokio::io::duplex(64);
        drop(peer);

        let refused = serve_io(Idle, tokio::io::split(ours)).await.unwrap_err();

        assert!(matches!(refused, StdioError::Initialize(_)), "{refused:?}");
        assert_eq!(refused.to_string(), "MCP initialise failed");
        assert!(
            refused
                .source()
                .and_then(|s| s.downcast_ref::<ServerInitializeError>())
                .is_some(),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn a_panicked_task_is_panicked_and_a_cancelled_one_cancelled() {
        let panicked = tokio::spawn(async { panic!("the service failed") })
            .await
            .unwrap_err();
        let cancelled = tokio::spawn(std::future::pending::<()>());
        cancelled.abort();
        let cancelled = cancelled.await.unwrap_err();

        let panicked = joined(panicked);
        let cancelled = joined(cancelled);

        assert!(matches!(panicked, StdioError::Panicked), "{panicked:?}");
        assert_eq!(panicked.to_string(), "the MCP service task panicked");
        assert!(matches!(cancelled, StdioError::Cancelled), "{cancelled:?}");
        assert!(panicked.source().is_none() && cancelled.source().is_none());
    }
}
