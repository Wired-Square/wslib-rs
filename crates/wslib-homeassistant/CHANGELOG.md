# Changelog

## 0.1.0

- `ingress`: `Peers` (`home_assistant`, `new`, `with_loopback`, `exempt`),
  `gate` (403 for any other peer but on an exempt path) and `recognise`
  (refusing nobody), the arrival proof only they set and `arrived` to read
  it. Peers are compared canonicalised; an exempt path matches exactly.
- `Caller` from `X-Remote-User-Id`, `-Name` and `-Display-Name`, and
  `IngressBase` from `X-Ingress-Path`, read only on a request that arrived. A
  header sent twice or not UTF-8, or a path that is not a `BasePath`, is a
  400 naming it. `spa_base` is the base as a `Spa::base_from` hook.
- `testing` feature: `trusted` and `RemoteUser`.
- Needs `wslib-http-scaffold` 0.1.1.
