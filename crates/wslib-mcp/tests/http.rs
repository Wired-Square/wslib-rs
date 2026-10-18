mod fixture;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::ServiceExt;
use rmcp::model::{CacheScope, CallToolRequestParams, JsonObject};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::json;
use wslib_mcp::CancellationToken;
use wslib_mcp::http::{self, ClientPolicy, ConnectionObserver, HostPolicy, HttpConfig, HttpError};
use wslib_mcp::server::ToolListCache;

const TOKEN: &str = "s3cret";
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}"#;

#[derive(Default)]
struct Recording(Mutex<Vec<(&'static str, String)>>);

impl ConnectionObserver for Recording {
    fn connected(&self, id: &str) {
        self.0.lock().unwrap().push(("connected", id.to_string()));
    }
    fn disconnected(&self, id: &str) {
        self.0
            .lock()
            .unwrap()
            .push(("disconnected", id.to_string()));
    }
}

struct Running {
    url: String,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), HttpError>>,
    observer: Arc<Recording>,
}

impl Running {
    async fn start(config: HttpConfig) -> Self {
        Self::start_with_cache(config, Some(fixture::CACHE)).await
    }

    async fn start_with_cache(config: HttpConfig, cache: Option<ToolListCache>) -> Self {
        let listener =
            http::bind_with_retry("127.0.0.1:0".parse().unwrap(), Duration::ZERO).unwrap();
        let url = format!(
            "http://127.0.0.1:{}/mcp",
            listener.local_addr().unwrap().port()
        );
        let observer = Arc::new(Recording::default());
        let config = HttpConfig {
            observer: Some(observer.clone()),
            ..config
        };
        let cancel = CancellationToken::new();
        let task = tokio::spawn(http::serve(
            listener,
            move || fixture::server(cache),
            config,
            cancel.clone(),
        ));
        Self {
            url,
            cancel,
            task,
            observer,
        }
    }

    async fn stop(self) -> Vec<(&'static str, String)> {
        self.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("serve returns promptly after cancel")
            .unwrap()
            .unwrap();
        self.observer.0.lock().unwrap().clone()
    }

    fn raw(&self) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .post(&self.url)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body(INITIALIZE)
    }
}

fn with_token() -> HttpConfig {
    HttpConfig {
        bearer_token: Some(TOKEN.into()),
        ..Default::default()
    }
}

fn args(value: serde_json::Value) -> JsonObject {
    value.as_object().unwrap().clone()
}

#[tokio::test]
async fn rmcp_client_round_trip_with_cache_hints_and_annotations() {
    let running = Running::start(with_token()).await;
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(running.url.clone()).auth_header(TOKEN),
    );
    let client = ().serve(transport).await.expect("initialise");

    let info = client.peer_info().expect("peer info");
    let implementation = info.server_info.as_ref().unwrap();
    assert_eq!(implementation.name, "fixture");
    assert_eq!(implementation.title.as_deref(), Some("Fixture"));
    assert_eq!(info.instructions.as_deref(), Some("Testing only."));

    let list = client.list_tools(None).await.unwrap();
    let names: Vec<&str> = list.tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, ["dyn_echo", "echo", "ping_tool"]);
    assert_eq!(list.ttl_ms, Some(300_000));
    assert_eq!(list.cache_scope, Some(CacheScope::Private));
    let annotations = |name: &str| {
        list.tools
            .iter()
            .find(|t| t.name == name)
            .unwrap()
            .annotations
            .clone()
            .unwrap()
    };
    assert_eq!(annotations("ping_tool").read_only_hint, Some(true));
    assert_eq!(annotations("echo").destructive_hint, Some(true));

    let echoed = client
        .call_tool(CallToolRequestParams::new("echo").with_arguments(args(json!({ "text": "hi" }))))
        .await
        .unwrap();
    assert_eq!(echoed.structured_content, Some(json!({ "text": "hi" })));

    let dynamic = client
        .call_tool(CallToolRequestParams::new("dyn_echo").with_arguments(args(json!({ "k": 1 }))))
        .await
        .unwrap();
    assert_eq!(dynamic.content[0].as_text().unwrap().text, r#"{"k":1}"#);

    let bad = client
        .call_tool(CallToolRequestParams::new("echo").with_arguments(args(json!({ "nope": 1 }))))
        .await
        .unwrap();
    assert_eq!(bad.is_error, Some(true));

    client.cancel().await.unwrap();
    let events = running.stop().await;
    let (connected, disconnected) = (&events[0], events.last().unwrap());
    assert_eq!(connected.0, "connected");
    assert!(!connected.1.is_empty(), "legacy session should carry an id");
    assert_eq!(disconnected, &("disconnected", connected.1.clone()));
}

#[tokio::test]
async fn stateless_tools_list_carries_the_required_cache_hints_when_uncached() {
    let running = Running::start_with_cache(HttpConfig::default(), None).await;
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        } }
    });
    let response = running
        .raw()
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/list")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let json: serde_json::Value = response.json().await.unwrap();
    assert_eq!(json["result"]["tools"].as_array().unwrap().len(), 3);
    assert_eq!(json["result"]["ttlMs"], 0);
    assert_eq!(json["result"]["cacheScope"], "private");

    let events = running.stop().await;
    assert_eq!(
        events,
        [
            ("connected", String::new()),
            ("disconnected", String::new())
        ]
    );
}

#[tokio::test]
async fn bearer_token_is_required_when_set() {
    let running = Running::start(with_token()).await;
    assert_eq!(running.raw().send().await.unwrap().status(), 401);
    assert_eq!(
        running
            .raw()
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        running
            .raw()
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let without_accept = reqwest::Client::new()
        .post(&running.url)
        .header("Content-Type", "application/json")
        .bearer_auth(TOKEN)
        .body(INITIALIZE)
        .send()
        .await
        .unwrap();
    assert_eq!(without_accept.status(), 406);
    running.stop().await;
}

#[tokio::test]
async fn host_policy_gates_the_host_header() {
    let loopback = Running::start(HttpConfig::default()).await;
    let refused = loopback
        .raw()
        .header("Host", "hass.example:8100")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
    assert_eq!(loopback.raw().send().await.unwrap().status(), 200);
    loopback.stop().await;

    let any = Running::start(HttpConfig {
        allowed_hosts: HostPolicy::Any,
        ..Default::default()
    })
    .await;
    assert_eq!(
        any.raw()
            .header("Host", "hass.example:8100")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    any.stop().await;
}

#[tokio::test]
async fn client_policy_gates_the_peer_address() {
    let elsewhere = ClientPolicy::Subnets(vec!["10.0.0.0/8".parse().unwrap()]);
    let refused = Running::start(HttpConfig {
        allowed_clients: elsewhere,
        ..Default::default()
    })
    .await;
    assert_eq!(refused.raw().send().await.unwrap().status(), 403);
    assert!(
        refused.stop().await.is_empty(),
        "a refused client is never reported connected"
    );

    let allowed = Running::start(HttpConfig {
        allowed_clients: ClientPolicy::Loopback,
        ..Default::default()
    })
    .await;
    assert_eq!(allowed.raw().send().await.unwrap().status(), 200);
    allowed.stop().await;
}

#[tokio::test]
async fn bind_with_retry_survives_a_stop_start_race() {
    let first = http::bind_with_retry("127.0.0.1:0".parse().unwrap(), Duration::ZERO).unwrap();
    let addr = first.local_addr().unwrap();
    let release = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(150));
        drop(first);
    });
    let rebound =
        tokio::task::spawn_blocking(move || http::bind_with_retry(addr, Duration::from_secs(2)))
            .await
            .unwrap();
    release.await.unwrap();
    assert_eq!(rebound.unwrap().local_addr().unwrap(), addr);
}
