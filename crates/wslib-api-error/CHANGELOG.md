# Changelog

## 0.1.0

- `ApiErrorBody`: `{"error": <sentence>, "code"?: <snake_case>}` with the
  app's own fields flattened beside them. Feature `ts` generates its
  TypeScript with ts-rs 11.
- `ApiError`: a status, its body and its headers, with a constructor per
  common status, `with_code`, `with_field` and `with_header`, and axum's
  `IntoResponse` behind the default feature `axum`. `too_many_requests` sets
  `Retry-After` in whole seconds. `internal` and `unavailable` answer "could
  not {what}" and log the cause.
