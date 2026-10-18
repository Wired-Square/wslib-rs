mod fixture;

use rmcp::ServiceExt;
use rmcp::model::{CacheScope, CallToolRequestParams, ProtocolVersion};
use wslib_mcp::stdio;

#[tokio::test]
async fn serves_a_client_over_an_in_memory_pipe() {
    let (server_end, client_end) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(stdio::serve_io(
        fixture::server(None),
        tokio::io::split(server_end),
    ));

    let client = ().serve(tokio::io::split(client_end)).await.expect("initialise");
    let info = client.peer_info().expect("peer info");
    assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
    assert_eq!(info.server_info.as_ref().unwrap().name, "fixture");

    let list = client.list_tools(None).await.unwrap();
    assert_eq!(list.tools.len(), 3);
    assert_eq!(list.ttl_ms, Some(0));
    assert_eq!(list.cache_scope, Some(CacheScope::Private));

    let pong = client
        .call_tool(CallToolRequestParams::new("ping_tool"))
        .await
        .unwrap();
    assert_eq!(pong.content[0].as_text().unwrap().text, "pong");

    client.cancel().await.unwrap();
    server
        .await
        .unwrap()
        .expect("server finishes cleanly when the client hangs up");
}
