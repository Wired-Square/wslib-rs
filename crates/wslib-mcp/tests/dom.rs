use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::RoleClient;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use serde_json::{Value, json};
use wslib_mcp::dom::{self, BRIDGE_TIMEOUT, DomBridge};
use wslib_mcp::router::compose;
use wslib_mcp::server::{ServerIdentity, ToolServer};
use wslib_mcp::stdio;

type Sent = Arc<Mutex<Vec<(String, Value, Duration)>>>;

#[derive(Clone, Default)]
struct Page {
    sent: Sent,
}

impl DomBridge for Page {
    async fn call(&self, op: &str, args: Value, timeout: Duration) -> Result<Value, String> {
        self.sent
            .lock()
            .unwrap()
            .push((op.into(), args.clone(), timeout));
        match args["selector"].as_str() {
            Some("#missing") => Err("0 match(es) for #missing; no index 0".into()),
            _ => Ok(json!({ "op": op })),
        }
    }
}

async fn connect(drive: bool) -> (RunningService<RoleClient, ()>, Sent) {
    let page = Page::default();
    let sent = page.sent.clone();
    let router = compose(dom::read_router(), [drive.then(dom::drive_router)]);
    let server = ToolServer::new(page, Arc::new(router), ServerIdentity::new("dom", "0.0.1"));
    let (server_end, client_end) = tokio::io::duplex(64 * 1024);
    tokio::spawn(stdio::serve_io(server, tokio::io::split(server_end)));
    let client = ().serve(tokio::io::split(client_end)).await.expect("initialise");
    (client, sent)
}

fn call(name: &'static str, args: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name).with_arguments(args.as_object().unwrap().clone())
}

#[tokio::test]
async fn read_tools_are_read_only_and_drive_tools_are_gated() {
    let (client, _) = connect(false).await;
    let listed: Vec<_> = client
        .list_tools(None)
        .await
        .unwrap()
        .tools
        .into_iter()
        .map(|t| {
            (
                t.name.to_string(),
                t.annotations
                    .and_then(|a| a.read_only_hint.zip(a.open_world_hint)),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("console".to_string(), Some((true, false))),
            ("query".to_string(), Some((true, false))),
            ("wait_for".to_string(), Some((true, false)))
        ]
    );

    let (client, _) = connect(true).await;
    let names: Vec<_> = client
        .list_tools(None)
        .await
        .unwrap()
        .tools
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(
        names,
        ["click", "console", "press", "query", "type", "wait_for"]
    );
}

#[tokio::test]
async fn ops_reach_the_page_normalised_with_their_timeouts() {
    let (client, sent) = connect(true).await;
    let reply = client
        .call_tool(call(
            "click",
            json!({ "selector": "button", "text": "Apply" }),
        ))
        .await
        .unwrap();
    assert_eq!(reply.structured_content, Some(json!({ "op": "click" })));
    client
        .call_tool(call(
            "wait_for",
            json!({ "selector": ".toast", "state": "gone" }),
        ))
        .await
        .unwrap();

    assert_eq!(
        *sent.lock().unwrap(),
        [
            (
                "click".into(),
                json!({ "selector": "button", "text": "Apply", "index": 0 }),
                BRIDGE_TIMEOUT
            ),
            (
                "wait_for".into(),
                json!({ "selector": ".toast", "state": "gone", "timeout_ms": 5000 }),
                Duration::from_millis(5000) + BRIDGE_TIMEOUT,
            ),
        ]
    );
}

#[tokio::test]
async fn a_page_error_is_a_tool_failure_and_bad_arguments_are_refused() {
    let (client, sent) = connect(true).await;
    let failed = client
        .call_tool(call("click", json!({ "selector": "#missing" })))
        .await
        .unwrap();
    assert_eq!(failed.is_error, Some(true));
    assert!(
        failed.content[0]
            .as_text()
            .unwrap()
            .text
            .contains("#missing")
    );

    assert!(
        client
            .call_tool(call("type", json!({ "selector": "input" })))
            .await
            .is_err()
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}
