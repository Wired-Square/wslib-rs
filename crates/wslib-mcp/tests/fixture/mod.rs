//! A three-tool server exercising every registration path: a macro read
//! router, a macro write router with its own annotations, and a runtime tool.

#![allow(dead_code)]

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CacheScope, CallToolResult, JsonObject, Tool};
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use wslib_mcp::result::{ok_json, ok_text};
use wslib_mcp::router::{compose, dyn_tool, mark_read_only};
use wslib_mcp::server::{ServerIdentity, ToolListCache, ToolServer};

#[derive(Clone, Default)]
pub struct Echo;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EchoParams {
    /// Text to echo back.
    pub text: String,
}

#[tool_router(router = read_router)]
impl Echo {
    #[tool(description = "Answers pong.")]
    async fn ping_tool(&self) -> Result<CallToolResult, ErrorData> {
        Ok(ok_text("pong"))
    }
}

#[tool_router(router = write_router)]
impl Echo {
    #[tool(description = "Echoes text.", annotations(destructive_hint = true))]
    async fn echo(
        &self,
        Parameters(p): Parameters<EchoParams>,
    ) -> Result<CallToolResult, ErrorData> {
        ok_json(serde_json::json!({ "text": p.text }))
    }
}

pub fn router() -> ToolRouter<Echo> {
    let mut read = Echo::read_router();
    mark_read_only(&mut read);
    let mut router = compose(read, [Some(Echo::write_router())]);
    router.add_route(dyn_tool(
        Tool::new(
            "dyn_echo",
            "Echoes its arguments as text.",
            Arc::new(JsonObject::new()),
        ),
        |_: Echo, args| async move { Ok(ok_text(serde_json::Value::Object(args).to_string())) },
    ));
    router
}

pub const CACHE: ToolListCache = ToolListCache {
    ttl_ms: 300_000,
    scope: CacheScope::Private,
};

pub fn identity() -> ServerIdentity {
    ServerIdentity::new("fixture", "0.0.1")
        .with_title("Fixture")
        .with_instructions("Testing only.")
}

pub fn server(cache: Option<ToolListCache>) -> ToolServer<Echo> {
    let server = ToolServer::new(Echo, Arc::new(router()), identity());
    match cache {
        Some(cache) => server.with_list_cache(cache),
        None => server,
    }
}
