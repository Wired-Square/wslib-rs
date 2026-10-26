# Changelog

## 0.2.1

- Rust 1.99 floor.
- tauri 2.12.1 floor, behind `tauri-bridge`.

## 0.2.0

- **Breaking:** `js/`, `dom::OPS_TS` and `tauri_bridge::BRIDGE_TS` are gone.
  The page halves are the npm package `@wired-square/mcp-bridge` from
  wslib-ts, imported as `@wired-square/mcp-bridge/dom-ops` and
  `@wired-square/mcp-bridge/tauri-bridge` (^0.1.0), in place of vendored
  copies and their `include_str!` tests. Names and behaviour are unchanged,
  so switching is an import-path change.
- `dom::OPS` lists the op names the DOM routers register, matching the
  package's `DOM_OPS`; with `tauri_bridge::REQUEST_EVENT` and `REPLY_EVENT`
  it is the contract between the two halves.

## 0.1.1

- Dependency floors raised to what the crate builds against from a fresh
  resolution: serde 1.0.228, serde_json 1.0.127, tracing 0.1.25, ipnet 2.9,
  tauri 2.11, tokio 1.38, tokio-util 0.7.9.

## 0.1.0

- Moved from `wslib-ai-mcp` 0.1.3 in wslib-ai-rs and renamed; the API is
  unchanged.
- Features `bridge` and `tauri-bridge`: `bridge::Pending` correlates a page's
  replies with the requests sent to it over any transport, and
  `tauri_bridge::TauriBridge` is a `DomBridge` over Tauri's `harness:request`
  and `harness:reply` events, with `js/tauri-bridge.ts` as its page half.
