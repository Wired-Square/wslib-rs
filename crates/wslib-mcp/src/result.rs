//! How a tool answers. Two conventions coexist across the consumers and both
//! are legitimate under the spec: a failure the *agent* should read is a
//! `CallToolResult` with `isError`, a failure of the *server* is a protocol
//! error. Pick per application, not per tool.

use rmcp::ErrorData;
use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;

/// Serialise `value` as the tool's answer. Objects go out as
/// `structuredContent` *and* a text block — the text is the compatibility path
/// pre-2026-07-28 clients read. Anything else is the text block alone:
/// `structuredContent` was object-only before SEP-2106 and clients still
/// enforce that, rejecting a top-level array as malformed.
pub fn ok_json<T: Serialize>(value: T) -> Result<CallToolResult, ErrorData> {
    let value = serde_json::to_value(value)
        .map_err(|e| internal_error(format!("Failed to serialise tool result: {e}")))?;
    if value.is_object() {
        return Ok(CallToolResult::structured(value));
    }
    Ok(ok_text(value.to_string()))
}

pub fn ok_text(text: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text.into())])
}

/// A failure for the agent to read inline (`isError: true`), not a protocol error.
pub fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

pub fn internal_error(message: impl Into<String>) -> ErrorData {
    ErrorData::internal_error(message.into(), None)
}

/// The "the app's error text is the tool's answer" convention: never a protocol error.
pub fn text_result(outcome: Result<String, String>) -> Result<CallToolResult, ErrorData> {
    Ok(match outcome {
        Ok(text) => ok_text(text),
        Err(text) => tool_error(text),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text_of(result: &CallToolResult) -> &str {
        &result.content[0].as_text().expect("text block").text
    }

    #[test]
    fn objects_are_structured_with_a_text_mirror() {
        let result = ok_json(json!({ "a": 1 })).unwrap();
        assert_eq!(result.structured_content, Some(json!({ "a": 1 })));
        assert_eq!(text_of(&result), r#"{"a":1}"#);
        assert_ne!(result.is_error, Some(true));
    }

    #[test]
    fn arrays_are_text_only() {
        let result = ok_json(json!([1, 2])).unwrap();
        assert_eq!(result.structured_content, None);
        assert_eq!(text_of(&result), "[1,2]");
    }

    #[test]
    fn tool_error_is_an_is_error_result() {
        let result = tool_error("boom");
        assert_eq!(result.is_error, Some(true));
        assert_eq!(text_of(&result), "boom");
    }

    #[test]
    fn text_result_maps_both_arms_to_results() {
        let ok = text_result(Ok("fine".into())).unwrap();
        assert_ne!(ok.is_error, Some(true));
        assert_eq!(text_of(&ok), "fine");
        let err = text_result(Err("bad".into())).unwrap();
        assert_eq!(err.is_error, Some(true));
        assert_eq!(text_of(&err), "bad");
    }

    #[test]
    fn internal_error_is_the_jsonrpc_internal_code() {
        let e = internal_error("x");
        assert_eq!(e.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert_eq!(e.message, "x");
    }
}
