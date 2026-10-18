# wslib-mcp

The hosting layer for a **tools-only MCP server**, over
[`rmcp`](https://crates.io/crates/rmcp) 3.x. It owns what every server would
otherwise repeat — who it is, which protocol revisions it speaks, how a tool
answers, how the listener is guarded — so an application writes its tools and
nothing else.

**Not pure Rust.** `js/` holds TypeScript, the page halves of the `dom` and
`tauri-bridge` features, which an app copies into its frontend unchanged.

## What's here

- **`server`** — `ServerIdentity` (name, version, title, instructions),
  `SUPPORTED_VERSIONS` (`2026-07-28`, `2025-11-25`, `2025-06-18`),
  `ToolListCache` (SEP-2549 freshness hints), and `ToolServer<T>`: the
  `ServerHandler`, built from your state `T` and the `ToolRouter<T>` your
  `#[tool_router]` impls produce. It answers `initialize`, `server/discover`,
  `tools/list`, `tools/call` and the SEP-2243 header lookups.
- **`result`** — `ok_json` (objects as `structuredContent` plus a text mirror,
  anything else as text), `ok_text`, `tool_error` (`isError: true`, for the
  agent to read), `internal_error` (a protocol error), and `text_result` for
  the `Result<String, String>` convention.
- **`router`** — `mark_read_only` stamps `readOnlyHint` on a whole router,
  `compose` merges permission-gated groups, `dyn_tool` registers a tool whose
  schema is only known at runtime.
- **`http`** (feature `http`) — `bind_with_retry` and `serve`: the
  Streamable-HTTP listener with a bearer token, a `HostPolicy` for the `Host`
  header (`Loopback` or `Any`), a `ClientPolicy` for the peer address (`Any`,
  `Loopback`, `Private`, or explicit `Subnets`), an `Origin` allow-list, and a
  `ConnectionObserver` that is told when a client appears and when it has gone
  quiet. Runs its idle watchdog inside `serve`, so the final drain completes
  before it returns.
- **`stdio`** (feature `stdio`) — `serve` on the process's stdin/stdout, or
  `serve_io` on any read/write pair.
- **`dom`** (feature `dom`) — tools that drive a webview's DOM by CSS
  selector. `read_router()` holds `query`, `wait_for` and `console`, stamped read-only;
  `drive_router()` holds `click`, `type` and `press`. Each call reaches the
  page through your `DomBridge` impl, and `js/dom-ops.ts` answers it there.
- **`bridge`** (feature `bridge`) — `Pending`, the correlator under such a
  bridge: `open` an id, `settle` it (or `settle_json` from the page's
  `{ id, ok }` / `{ id, error }`), and `wait` for it with a timeout. Knows
  nothing of the transport.
- **`tauri_bridge`** (feature `tauri-bridge`) — `TauriBridge`, a `DomBridge`
  over Tauri events, and `js/tauri-bridge.ts`, its page half.

## Using it

From the `wired-square` registry (see the workspace README for its setup):

```toml
wslib-mcp = { version = "0.1", registry = "wired-square", features = ["http"] }
```

rmcp's macros emit `rmcp::` paths into your crate, and the re-export satisfies
them — no `rmcp` or `schemars` entry of your own:

```rust
use wslib_mcp::rmcp;
use rmcp::schemars::{self, JsonSchema};

#[derive(serde::Deserialize, JsonSchema)]
struct Args { name: String }
```

Declaring `rmcp = "3.4"` and `schemars = "1"` directly also works, at the same
major version as this crate's.

```rust
#[derive(Clone)]
struct MyTools { /* whatever your handlers need */ }

#[tool_router(router = read_router)]
impl MyTools {
    #[tool(description = "…")]
    async fn list_things(&self) -> Result<CallToolResult, ErrorData> { ok_json(…) }
}

let mut router = MyTools::read_router();
mark_read_only(&mut router);
let router = Arc::new(compose(router, [allow_control.then(MyTools::control_router)]));
let identity = ServerIdentity::new("my-app", env!("CARGO_PKG_VERSION")).with_title("My App");

let listener = http::bind_with_retry(([127, 0, 0, 1], 8787).into(), Duration::from_secs(2))?;
let config = HttpConfig { bearer_token: Some(token), allowed_origins: http::loopback_origins(8787), ..Default::default() };
http::serve(listener, move || ToolServer::new(MyTools { … }, router.clone(), identity.clone()), config, cancel).await?;
```

## Driving a webview (`dom`)

Implement `DomBridge` on your tools type over whatever already reaches the page
— Tauri events, a WebSocket — and compose the routers like any other group:

```rust
impl DomBridge for MyTools {
    async fn call(&self, op: &str, args: Value, timeout: Duration) -> Result<Value, String> {
        self.page.request(op, args, timeout).await
    }
}

let router = compose(base + dom::read_router(), [allow_ui.then(dom::drive_router)]);
```

The op names are the tool names, and `args` is the tool's params with defaults
filled in (`index: 0`, `timeout_ms: 5000`). `query`, `click` and `wait_for` take
an optional `text`, a case-sensitive substring of the element's visible text
applied after the selector, for the buttons CSS cannot tell apart; `query`
reports form state (`value`, `checked`, `disabled`, `expanded`, `selected`) so
a `type` can be read back. All six carry `openWorldHint: false`. `wait_for` gets `timeout_ms` plus
`BRIDGE_TIMEOUT`; every other op gets `BRIDGE_TIMEOUT` (10 s). A bridge `Err`
reaches the agent as a tool failure.

On the page, copy [`js/dom-ops.ts`](js/dom-ops.ts) into your frontend unchanged
and hand each request to `runDomOp(op, args)` (or register `DOM_OPS` one by
one). Importing it wraps `console.error` and `console.warn` and listens for
`window` `error` and `unhandledrejection`, keeping the last 200 for the `console`
tool, so import it before anything that can fail — a release webview has no
inspector, and an error boundary that logs and renders a fallback is otherwise
invisible. It has no framework imports and typechecks under `strict`,
`noUnusedLocals` and `noUnusedParameters` against ES2020 (`npx -p typescript
tsc -p js`). `type` writes through the native `value` setter, so React's
controlled inputs see the change. Keep your copy honest with a test:

```rust
assert_eq!(include_str!("../frontend/src/harness/dom-ops.ts"), wslib_mcp::dom::OPS_TS);
```

## Over Tauri events (`tauri-bridge`)

`TauriBridge` sends `harness:request` `{ id, op, args }` to one window
(`main` unless built with `for_window`) and awaits the `harness:reply` that
carries the same id. Build it once in `setup`, where it starts listening, and
clone it into your tools:

```rust
let page = TauriBridge::new(app.handle());

impl DomBridge for MyTools {
    async fn call(&self, op: &str, args: Value, timeout: Duration) -> Result<Value, String> {
        self.page.call(op, args, timeout).await
    }
}
```

`page.request(op, args, timeout)` reaches app ops of your own the same way.
A transport other than Tauri events builds the same thing on `bridge::Pending`.

The page must be allowed to listen for and emit events. A harness that exists
only in development builds can add the capability at runtime rather than ship
it:

```rust
app.add_capability(r#"{
    "identifier": "mcp-harness",
    "windows": ["main"],
    "permissions": ["core:event:allow-listen", "core:event:allow-unlisten", "core:event:allow-emit"]
}"#)?;
```

On the page, copy [`js/tauri-bridge.ts`](js/tauri-bridge.ts) unchanged into
the same directory as your copy of `dom-ops.ts`, which it imports as
`./dom-ops`, and start it after that import:

```ts
const stop = startHarnessBridge({
  navigate: ({ path }) => (navigate(String(path)), {}),
});
import.meta.hot?.dispose(() => stop.then((unlisten) => unlisten()));
```

The ops you pass are tried before the DOM ops, and a thrown error becomes the
reply's `error`. `answer(request, appOps)` is the same handling without the
events, for a test. Under hot reload, stop the old listener as above or every
request is answered twice. Keep the copy honest beside the `dom-ops.ts` one:

```rust
assert_eq!(include_str!("../frontend/src/harness/tauri-bridge.ts"), wslib_mcp::tauri_bridge::BRIDGE_TS);
```

## Things to get right

- **`HostPolicy`.** rmcp refuses any `Host` header that is not loopback, as
  the spec's DNS-rebinding defence. A listener clients reach by a LAN or DNS
  name must set `allowed_hosts: HostPolicy::Any` or every request is a 403.
  This is about the URL the client typed; restricting *who* may connect is
  `ClientPolicy`.
- **Build the router once.** Under protocol 2026-07-28 the HTTP transport runs
  the factory on every request. Share the `ToolRouter` behind an `Arc` and
  keep `T` cheap to construct.
- **`initialize` never answers `2026-07-28`.** That revision has no handshake
  — a 2026-07-28 client uses `server/discover` and per-request `_meta` — so
  rmcp 3.4 answers an `initialize` that asks for it with `2025-11-25`, the
  newest revision that *has* one. rmcp 3.1 echoed the request; a mixed-mode
  client that does both will see the difference in its `initialize` reply and
  nothing else.

## Tests

Unit tests sit beside the code. `tests/http.rs` and `tests/stdio.rs` stand up a
three-tool fixture server and drive it with rmcp's own client — over a real
loopback port and an in-memory pipe respectively; `tests/dom.rs` does the same
for the DOM routers over a recording bridge. `tauri_bridge`'s tests run the
round trip on Tauri's mock runtime. All need `--all-features` to run.
