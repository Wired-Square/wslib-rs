# wslib-http-scaffold

The HTTP scaffold under an axum app: its single-page bundle, a health and a
version route, and the standard layers. Every refusal is a
[`wslib-api-error`](../wslib-api-error) body.

```rust
use wslib_http_scaffold::{Spa, health, standard_layers, version};

let app = Router::new()
    .nest("/api", api)
    .merge(health())
    .merge(version(env!("CARGO_PKG_VERSION"), env!("WSLIB_BUILD_ID")))
    .method_not_allowed_fallback(wslib_http_scaffold::wslib_api_error::extract::method_not_allowed)
    .fallback_service(Spa::from_dir("/usr/share/my-app/ui"));
let app = standard_layers(app);
```

## What's here

- **`Spa`**: the bundle as a fallback service, from disk (`from_dir`) or
  compiled in with rust-embed (`embedded::<Ui>()`, feature `embed`). An
  unmatched path answers `index.html`. A path whose first segment is reserved
  (`api` unless `reserving` replaces it) is a 404, judged on the path after
  percent-decoding and `.` and `..`, so `//api/x`, `/%2Fapi/x` and
  `/ui/../api/x` are refused too. `assets/` is `public, max-age=31536000,
  immutable` and a missing asset there is a 404, never the page; everything
  else is `no-store`. A `.gz` beside a file is sent to a client taking gzip.
- **`health`** and **`health_with(ready)`**: `GET /healthz` answering
  `{"status":"ok"}`, or `ready`'s error while it fails.
- **`version(version, build)`**: `GET /version` answering
  `{"version", "build"}`; `build` is wslib-build-id's `WSLIB_BUILD_ID`.
- **`standard_layers`**: tracing, gzip compression, and a panic answered as a
  500 error body. Call it last; it wraps only what the router already holds.
