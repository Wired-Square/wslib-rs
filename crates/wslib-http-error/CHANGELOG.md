# Changelog

## 0.1.2

- Dependency floor raised to match the crates it shares a graph with:
  axum 0.8.7 (was 0.8). No change to the API.

## 0.1.1

- `internal` and `unavailable` log their cause through
  `wslib_telemetry::foreign_error`: a URL's userinfo is stripped and the cause
  cut to 512 bytes.
- An `ApiError` response carries a clone of its `ApiErrorBody` in its
  extensions, so an outer layer can recognise it and re-render it, as an HTML
  page for a browser, say.
- `ApiError` is boxed inside, one pointer wide, so `Result<_, ApiError>` no
  longer trips clippy's `result_large_err`.

## 0.1.0

- `ApiErrorBody`: `{"error": <sentence>, "code"?: <snake_case>}` with the
  app's own fields flattened beside them. Feature `ts` generates its
  TypeScript with ts-rs 11.
- `ApiError`: a status, its body and its headers, with a constructor per
  common status, `with_code`, `with_field` and `with_header`, and axum's
  `IntoResponse` behind the default feature `axum`. `too_many_requests` sets
  `Retry-After` in whole seconds. `internal` and `unavailable` answer "could
  not {what}" and log the cause.
- `extract`: `Json`, `Query` and `Path` refusing with an `ApiError` at axum's
  status, and `method_not_allowed` for axum's 405 fallback.
