# Changelog

## 0.1.1

- Dependency floor raised to match the crates it shares a graph with:
  axum 0.8.7 (was 0.8). No change to the API.

## 0.1.0

- `ingress`: `Peers` (`home_assistant`, `new`, `with_loopback`, `exempt`,
  `refusal`),
  `gate` (403 for any other peer but on an exempt path) and `recognise`
  (refusing nobody), the arrival proof only they set and `arrived` to read
  it. Peers are compared canonicalised; an exempt path matches exactly.
- `Caller` from `X-Remote-User-Id`, `-Name` and `-Display-Name`, and
  `IngressBase` from `X-Ingress-Path`, read only on a request that arrived. A
  header sent twice or not UTF-8, or a path that is not a `BasePath`, is a
  400 naming it. `caller` reads the caller from `&Parts`; `spa_base` is the
  base as a `Spa::base_from` hook.
- The header names: `USER_ID`, `USER_NAME`, `DISPLAY_NAME`, `INGRESS_PATH`.
- `testing` feature: `trusted` and `RemoteUser`.
- Needs `wslib-http-scaffold` 0.1.1.
