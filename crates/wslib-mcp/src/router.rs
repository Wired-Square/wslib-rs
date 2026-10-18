//! Assembling a `ToolRouter` from parts: gate-dependent groups, read-only
//! stamping, and tools whose schema is only known at runtime.

use std::future::Future;

use rmcp::ErrorData;
use rmcp::handler::server::router::tool::{ToolRoute, ToolRouter};
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};

/// `readOnlyHint: true` on every route, keeping any other hints already set.
/// Read-only-ness is a property of being *in* a read router, so it is stamped
/// once here rather than repeated on every tool where one omission would ship
/// a read tool with no hint.
pub fn mark_read_only<S>(router: &mut ToolRouter<S>) {
    for route in router.map.values_mut() {
        let annotations = route
            .attr
            .annotations
            .take()
            .unwrap_or_else(ToolAnnotations::new);
        route.attr.annotations = Some(annotations.read_only(true));
    }
}

/// `base` plus every `Some(group)`: the permission-gate composition
/// (`cfg.control.then(Self::control_router)`, …) both consumers do.
pub fn compose<S: Send + Sync + 'static>(
    mut base: ToolRouter<S>,
    gated: impl IntoIterator<Item = Option<ToolRouter<S>>>,
) -> ToolRouter<S> {
    for group in gated.into_iter().flatten() {
        base += group;
    }
    base
}

/// A tool defined by data rather than by `#[tool]` — one per table, say. `S`
/// is cloned per call so the handler can be a plain `async move` block; the
/// boxing rmcp wants happens here.
pub fn dyn_tool<S, F, Fut>(tool: Tool, handler: F) -> ToolRoute<S>
where
    S: Clone + Send + Sync + 'static,
    F: Fn(S, JsonObject) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<CallToolResult, ErrorData>> + Send + 'static,
{
    ToolRoute::new_dyn(tool, move |ctx: ToolCallContext<'_, S>| {
        let fut = handler(ctx.service.clone(), ctx.arguments.unwrap_or_default());
        Box::pin(async move { fut.await.map(Into::into) })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::ok_text;
    use std::sync::Arc;

    fn tool(name: &'static str) -> Tool {
        Tool::new(name, "t", Arc::new(JsonObject::new()))
    }

    fn router_with(names: &[&'static str]) -> ToolRouter<()> {
        let mut router = ToolRouter::new();
        for name in names {
            router.add_route(dyn_tool(tool(name), |(), _| async { Ok(ok_text("")) }));
        }
        router
    }

    #[test]
    fn mark_read_only_stamps_and_preserves() {
        let mut router = router_with(&["a", "b"]);
        router.map.get_mut("b").unwrap().attr.annotations =
            Some(ToolAnnotations::new().destructive(true));
        mark_read_only(&mut router);
        for t in router.list_all() {
            assert_eq!(
                t.annotations.as_ref().unwrap().read_only_hint,
                Some(true),
                "{}",
                t.name
            );
        }
        assert_eq!(
            router
                .get("b")
                .unwrap()
                .annotations
                .as_ref()
                .unwrap()
                .destructive_hint,
            Some(true)
        );
    }

    #[test]
    fn compose_merges_only_enabled_groups() {
        let composed = compose(
            router_with(&["base"]),
            [
                Some(router_with(&["a"])),
                None,
                Some(router_with(&["b", "c"])),
            ],
        );
        let names: Vec<_> = composed.list_all().into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["a", "b", "base", "c"]);
    }

    #[test]
    fn dyn_tool_keeps_the_declared_attr() {
        let route = dyn_tool::<(), _, _>(tool("dyn"), |(), _| async { Ok(ok_text("")) });
        assert_eq!(route.name(), "dyn");
        assert_eq!(route.attr.description.as_deref(), Some("t"));
    }
}
