# Changelog

## 0.1.1

- `BasePath`: `/` or slash-separated URL-safe segments ending in `/`, parsed
  with or without its end slashes, moved unchanged from the chassis.
- `Spa::base_from(hook)`: `index.html` served with a `<base href>` for the
  base `hook` names for the request, made per request; a refusal from `hook`
  answers the page and no file. Without a hook nothing changes.
- `EncoderCap`: at most a set number of live gzip encoders (64 by default); a
  request past it is served uncompressed rather than delayed. `standard_layers`
  applies it. A `.gz` the `Spa` sends needs no encoder and holds none, so it
  still goes out compressed past the cap.

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
