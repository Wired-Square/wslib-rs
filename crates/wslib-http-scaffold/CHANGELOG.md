# Changelog

## 0.1.3

- `attachment(content_type, filename, body)`: a `Response` a browser saves
  as `filename`, marked `Cache-Control: no-store`. The name is sent as a
  quoted string, and one no header can carry falls back to `download`.

## 0.1.2

- `accepts_gzip(headers)`, now public, follows RFC 9110: `gzip` or `x-gzip`
  at a q-value above zero, else `*` above zero when gzip is not named. A
  malformed q-value is no acceptance. It was `gzip` alone, refused only at
  exactly `q=0`.
- `Spa::from_dir_with_page(dir, page)`: the bundle in `dir` with `page` as its
  `index.html`, for an app that read the page itself and needs the page
  served to be that one.
- A bundle with no `index.html` answers the page with a 404,
  `the bundle has no index.html`, where it was a 500 logged as an error on
  every request. `Spa::has_page` says so, to warn once at startup.

## 0.1.1

- `BasePath`: `/` or slash-separated URL-safe segments ending in `/`, parsed
  with or without its end slashes, moved unchanged from the chassis. Every
  other item is behind the new default feature `server`, so
  `default-features = false` is `BasePath` and serde alone.
- `index.html` is read once, as the `Spa` is built, and served from memory
  with a best-level gzip made then. `Spa::base(base)` renders it once with
  that `<base href>`.
- `Spa::base_from(hook)`: `index.html` served with a `<base href>` for the
  base `hook` names for the request, made per request and left to the
  compression layer; none falls back to `Spa::base`, else the plain page; a refusal from `hook`
  answers the page and no file. A `<base>` already in the page's head has its
  `href` rewritten, its other attributes kept. Without a hook nothing changes.
- A bundle with no `index.html`, from disk or embedded, answers the page with
  a 500 error body, logging the missing file, where it was a 404.
- `EncoderCap`: at most a set number of live gzip encoders (64 by default); a
  request past it is served uncompressed rather than delayed. `standard_layers`
  applies it. A `.gz` the `Spa` sends needs no encoder and holds none, so it
  still goes out compressed past the cap. `restore_accept_encoding` and
  `mark_stored` do the same for an app's own handler serving a stored gzip.
- `first_segment_is(path, segment)`: the rule a reserved prefix is judged
  by, for an app with no bundle.

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
