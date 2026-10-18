# Changelog

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
