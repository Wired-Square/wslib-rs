# Changelog

## 0.1.0

- Moved from `wslib-ai-mcp` 0.1.3 in wslib-ai-rs and renamed; the API is
  unchanged.
- Features `bridge` and `tauri-bridge`: `bridge::Pending` correlates a page's
  replies with the requests sent to it over any transport, and
  `tauri_bridge::TauriBridge` is a `DomBridge` over Tauri's `harness:request`
  and `harness:reply` events, with `js/tauri-bridge.ts` as its page half.
