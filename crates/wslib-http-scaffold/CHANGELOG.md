# Changelog

## 0.1.0

- `Spa`: a single-page bundle from disk, answering `index.html` for unmatched
  paths and never for a reserved prefix (`api` by default), judged on the
  resolved path. `assets/` is cached for ever and 404s when missing; the rest
  is `no-store`. Precompressed gzip is sent where it exists, and every refusal
  is a wslib-http-error body.
- `Spa::embedded` (feature `embed`): the same bundle compiled in with
  rust-embed, under the same rules, with an `ETag`.
- `health`, `health_with` and `version`: `GET /healthz` and `GET /version`.
  `standard_layers`: tracing, gzip and a panic answered as a 500 body.
