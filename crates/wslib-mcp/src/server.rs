//! The `ServerHandler` every consumer would otherwise write by hand.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, DiscoverResult, Implementation,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
    Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};

/// Protocol revisions this crate's servers implement — the list
/// `server/discover` publishes and the bound on `initialize` negotiation.
/// Narrower than rmcp's default, which advertises everything back to
/// 2024-11-05.
pub const SUPPORTED_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2026_07_28,
    ProtocolVersion::V_2025_11_25,
    ProtocolVersion::V_2025_06_18,
];

/// What a server says about itself in `initialize` and `server/discover`.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    pub name: Cow<'static, str>,
    pub version: Cow<'static, str>,
    pub title: Option<Cow<'static, str>>,
    pub instructions: Option<Cow<'static, str>>,
}

impl ServerIdentity {
    pub fn new(name: impl Into<Cow<'static, str>>, version: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            title: None,
            instructions: None,
        }
    }

    pub fn with_title(mut self, title: impl Into<Cow<'static, str>>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn with_instructions(mut self, instructions: impl Into<Cow<'static, str>>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// `ServerConfig`'s default identity is *rmcp's* own build env, so a server
    /// that leaves it alone introduces itself as "rmcp".
    pub fn server_config(&self) -> ServerConfig {
        let mut implementation = Implementation::new(self.name.clone(), self.version.clone());
        if let Some(title) = &self.title {
            implementation = implementation.with_title(title.clone());
        }
        let config = ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(implementation);
        match &self.instructions {
            Some(text) => config.with_instructions(text.clone()),
            None => config,
        }
    }
}

/// SEP-2549 freshness hints for `tools/list` and `server/discover`. A tool set
/// that only changes with a server restart can safely be held by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolListCache {
    pub ttl_ms: u64,
    pub scope: CacheScope,
}

impl ToolListCache {
    /// Protocol 2026-07-28 requires both hints on every list result, so a
    /// server that opts out of caching still has to send these.
    pub const UNCACHED: Self = Self {
        ttl_ms: 0,
        scope: CacheScope::Private,
    };
}

/// A tools-only server: the consumer's state `T` plus the router built from its
/// `#[tool_router]` impls. Cheap to construct per request (the Streamable-HTTP
/// transport does so under protocol 2026-07-28) as long as `T` is.
pub struct ToolServer<T> {
    inner: T,
    router: Arc<ToolRouter<T>>,
    identity: ServerIdentity,
    cache: ToolListCache,
}

impl<T: Send + Sync + 'static> ToolServer<T> {
    pub fn new(inner: T, router: Arc<ToolRouter<T>>, identity: ServerIdentity) -> Self {
        Self {
            inner,
            router,
            identity,
            cache: ToolListCache::UNCACHED,
        }
    }

    pub fn with_list_cache(mut self, cache: ToolListCache) -> Self {
        self.cache = cache;
        self
    }
}

impl<T: Send + Sync + 'static> ServerHandler for ToolServer<T> {
    fn get_info(&self) -> ServerConfig {
        self.identity.server_config()
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_VERSIONS)
    }

    async fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        Ok(
            DiscoverResult::from_server_info(SUPPORTED_VERSIONS.to_vec(), self.get_info())
                .with_ttl_ms(self.cache.ttl_ms)
                .with_cache_scope(self.cache.scope),
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.router.list_all())
            .with_ttl_ms(self.cache.ttl_ms)
            .with_cache_scope(self.cache.scope))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.router
            .call(ToolCallContext::new(&self.inner, request, context))
            .await
    }

    // The HTTP transport validates `Mcp-Param-*` headers through this.
    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.router.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_explicit_and_advertises_tools() {
        let info = ServerIdentity::new("fixture", "1.2.3")
            .with_title("Fixture")
            .with_instructions("Do things.")
            .server_config();
        assert_eq!(info.server_info.name, "fixture");
        assert_eq!(info.server_info.version, "1.2.3");
        assert_eq!(info.server_info.title.as_deref(), Some("Fixture"));
        assert_eq!(info.instructions.as_deref(), Some("Do things."));
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn get_tool_answers_from_the_router() {
        let mut router: ToolRouter<()> = ToolRouter::new();
        router.add_route(crate::router::dyn_tool(
            Tool::new("known", "a tool", Arc::new(serde_json::Map::new())),
            |(), _args| async { Ok(crate::result::ok_text("")) },
        ));
        let server = ToolServer::new((), Arc::new(router), ServerIdentity::new("s", "0"));
        assert!(server.get_tool("known").is_some());
        assert!(server.get_tool("unknown").is_none());
        assert_eq!(
            server.supported_protocol_versions().as_ref(),
            SUPPORTED_VERSIONS
        );
    }
}
