//! Tools that drive a webview's DOM by CSS selector: `query` and `wait_for`
//! read, `click`, `type` and `press` act, and `console` reads what the page
//! logged. Each call goes to the page as
//! `(op, args)` over the consumer's own [`DomBridge`], and [`OPS_TS`] is the
//! page half that answers it. Ops fire synthetic events, so the window needs
//! no focus.

use std::future::Future;
use std::time::Duration;

use rmcp::ErrorData;
use rmcp::handler::server::router::tool::{ToolRoute, ToolRouter};
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use rmcp::schemars::{self, JsonSchema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::result::{internal_error, ok_json, tool_error};
use crate::router::{dyn_tool, mark_read_only};

/// How long an op may take to answer, beyond any wait it was asked to make.
pub const BRIDGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The page half, to be vendored byte-for-byte into the consumer's frontend.
pub const OPS_TS: &str = include_str!("../js/dom-ops.ts");

/// Carries an op to the page and its reply back; `Err` reaches the agent as
/// a tool failure.
pub trait DomBridge: Clone + Send + Sync + 'static {
    fn call(
        &self,
        op: &str,
        args: Value,
        timeout: Duration,
    ) -> impl Future<Output = Result<Value, String>> + Send;
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct QueryParams {
    /// CSS selector.
    pub selector: String,
    /// Keep only matches whose visible text contains this, case-sensitively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ClickParams {
    pub selector: String,
    /// Keep only matches whose visible text contains this, case-sensitively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Which match to click when several remain.
    #[serde(default)]
    pub index: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TypeParams {
    pub selector: String,
    /// Replaces the field's value.
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PressParams {
    /// A `KeyboardEvent.key` value, e.g. `Escape`, `ArrowDown`, `Enter`.
    pub key: String,
    /// Target element; defaults to the focused one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WaitState {
    Visible,
    Gone,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct WaitForParams {
    pub selector: String,
    /// Keep only matches whose visible text contains this, case-sensitively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub state: WaitState,
    #[serde(default = "default_wait_ms")]
    pub timeout_ms: u64,
}

fn default_wait_ms() -> u64 {
    5000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleLevel {
    Error,
    Warn,
    /// An uncaught exception (`window` `error`).
    Uncaught,
    /// An unhandled promise rejection.
    Rejection,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ConsoleParams {
    /// Empty the buffer after reading it.
    #[serde(default)]
    pub clear: bool,
    /// Keep only these levels; all of them if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub levels: Option<Vec<ConsoleLevel>>,
    /// Keep only entries after this `seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

/// `query`, `wait_for` and `console`, stamped read-only.
pub fn read_router<T: DomBridge>() -> ToolRouter<T> {
    let mut router = ToolRouter::new();
    router.add_route(relay::<T, QueryParams>(
        "query",
        "Every element matching a CSS selector: text, role, aria-label, form state (value, \
         checked, disabled, expanded, selected), rect, whether it lies wholly inside the \
         viewport, and the nearest overflow ancestor clipping it (null if none).",
        |_| BRIDGE_TIMEOUT,
    ));
    router.add_route(relay::<T, WaitForParams>(
        "wait_for",
        "Wait until an element matching the selector is visible, or until none is.",
        |p| Duration::from_millis(p.timeout_ms) + BRIDGE_TIMEOUT,
    ));
    router.add_route(relay::<T, ConsoleParams>(
        "console",
        "The page's console errors and warnings, uncaught exceptions and unhandled rejections \
         since load, oldest first: level, message, stack, `at` (epoch ms) and `seq`. Keeps the \
         last 200; `dropped` counts those evicted. Pass the last `seq` seen as `since` to read \
         only what is new.",
        |_| BRIDGE_TIMEOUT,
    ));
    mark_read_only(&mut router);
    router
}

/// `click`, `type` and `press`.
pub fn drive_router<T: DomBridge>() -> ToolRouter<T> {
    let mut router = ToolRouter::new();
    router.add_route(relay::<T, ClickParams>(
        "click",
        "Click an element as a pointer would: pointerdown, mousedown, mouseup, click.",
        |_| BRIDGE_TIMEOUT,
    ));
    router.add_route(relay::<T, TypeParams>(
        "type",
        "Set an input's value and fire input and change.",
        |_| BRIDGE_TIMEOUT,
    ));
    router.add_route(relay::<T, PressParams>(
        "press",
        "Fire keydown and keyup for a key.",
        |_| BRIDGE_TIMEOUT,
    ));
    router
}

fn relay<T, P>(
    op: &'static str,
    description: &'static str,
    timeout: fn(&P) -> Duration,
) -> ToolRoute<T>
where
    T: DomBridge,
    P: DeserializeOwned + Serialize + JsonSchema + 'static,
{
    let tool = Tool::new(op, description, JsonObject::new())
        .with_input_schema::<P>()
        .annotate(ToolAnnotations::new().open_world(false));
    dyn_tool(tool, move |bridge: T, args: JsonObject| {
        let request = normalise(args, timeout);
        async move {
            let (args, timeout) = request?;
            match bridge.call(op, args, timeout).await {
                Ok(reply) => ok_json(reply),
                Err(e) => Ok(tool_error(e)),
            }
        }
    })
}

/// Round-trips the arguments through `P`, so the page sees defaults filled in
/// and never an argument the schema did not allow.
fn normalise<P: DeserializeOwned + Serialize>(
    args: JsonObject,
    timeout: fn(&P) -> Duration,
) -> Result<(Value, Duration), ErrorData> {
    let params: P = serde_json::from_value(Value::Object(args))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let args = serde_json::to_value(&params).map_err(|e| internal_error(e.to_string()))?;
    Ok((args, timeout(&params)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn object(v: Value) -> JsonObject {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn defaults_are_filled_in_for_the_page() {
        let (args, _) =
            normalise::<ClickParams>(object(json!({ "selector": "b" })), |_| BRIDGE_TIMEOUT)
                .unwrap();
        assert_eq!(args, json!({ "selector": "b", "index": 0 }));

        let (args, _) =
            normalise::<PressParams>(object(json!({ "key": "Enter" })), |_| BRIDGE_TIMEOUT)
                .unwrap();
        assert_eq!(args, json!({ "key": "Enter" }));

        let (args, _) =
            normalise::<ConsoleParams>(object(json!({ "levels": ["uncaught"] })), |_| {
                BRIDGE_TIMEOUT
            })
            .unwrap();
        assert_eq!(args, json!({ "clear": false, "levels": ["uncaught"] }));
    }

    #[test]
    fn a_bad_argument_is_invalid_params() {
        let err = normalise::<WaitForParams>(
            object(json!({ "selector": "b", "state": "hidden" })),
            |_| BRIDGE_TIMEOUT,
        )
        .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn the_page_half_answers_every_op() {
        for op in ["query", "click", "type", "press", "wait_for", "console"] {
            assert!(
                OPS_TS.contains(&format!("  {op},")) || OPS_TS.contains(&format!("  {op}:")),
                "{op}"
            );
        }
    }
}
