//! The stdio transport: newline-delimited JSON-RPC on stdin/stdout until the
//! peer closes. Nothing else may write to stdout while a server is running.

use rmcp::ServerHandler;
use rmcp::service::{QuitReason, ServerInitializeError, ServiceExt};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error)]
pub enum StdioError {
    #[error("MCP initialise failed: {0}")]
    Initialize(#[from] Box<ServerInitializeError>),
    #[error("MCP service task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
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
    match running.waiting().await? {
        QuitReason::JoinError(e) => Err(e.into()),
        reason => {
            tracing::debug!(?reason, "MCP stdio server finished");
            Ok(())
        }
    }
}
