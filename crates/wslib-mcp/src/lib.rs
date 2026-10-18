//! Hosting layer over [`rmcp`] for **tools-only** MCP servers.
//!
//! A consumer writes `#[tool_router]` impl blocks on its own state type and
//! hands the assembled [`ToolRouter`](rmcp::handler::server::router::tool::ToolRouter)
//! to [`server::ToolServer`], which is the whole `ServerHandler`. Everything
//! protocol-shaped that would otherwise be repeated per application lives here:
//!
//! - [`server`] — identity, supported protocol revisions, `tools/list` cache
//!   hints, and the `ServerHandler` implementation itself
//! - [`result`] — the `CallToolResult` conventions (structured vs text, tool
//!   failure vs protocol error)
//! - [`router`] — read-only stamping, permission-gated composition, and tools
//!   defined at runtime rather than by macro
//! - [`http`] (feature `http`) — the Streamable-HTTP listener: bearer token,
//!   `Host`/`Origin` policy, connection tracking, graceful shutdown
//! - [`stdio`] (feature `stdio`) — the stdio transport
//! - [`dom`] (feature `dom`) — tools that drive a webview's DOM through a
//!   consumer-supplied bridge
//! - [`bridge`] (feature `bridge`) — the request/reply correlator such a
//!   bridge is built on
//! - [`tauri_bridge`] (feature `tauri-bridge`) — that bridge over Tauri events
//!
//! `rmcp` is re-exported; its macros emit `rmcp::` paths, which a consumer's
//! `use wslib_mcp::rmcp;` satisfies, and `schemars` comes as `rmcp::schemars`.

pub use rmcp;

#[cfg(feature = "http")]
pub use tokio_util::sync::CancellationToken;

pub mod result;
pub mod router;
pub mod server;

#[cfg(feature = "bridge")]
pub mod bridge;
#[cfg(feature = "dom")]
pub mod dom;
#[cfg(feature = "tauri-bridge")]
pub mod tauri_bridge;

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "stdio")]
pub mod stdio;
