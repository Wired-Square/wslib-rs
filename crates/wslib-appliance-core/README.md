# wslib-appliance-core

The router, the authority and the workers under an appliance's backends:
`wslib-appliance-server` (behind a console or an ingress proxy),
`wslib-appliance-https` (its own TLS listener, with sessions) and
`wslib-appliance-service` (a desktop service). A product names one of those;
this crate supplies what its routes are written against.

## What a product's routes use

- **The rungs**: `Viewer`, `Operator`, `Admin`, `HostAdmin` and `SessionAdmin`
  extract the caller at that role or above, each yielding its `Identity`;
  `Unclaimed` is the first account's offer on a box with none. A control
  socket satisfies `Viewer`, `Operator` and `Admin` up to its ceiling, except
  on routes raised to `HostAdmin`, and never `SessionAdmin` or `HostAdmin`.
- **`Mount`**: routes on a state of the product's own beside
  `ApplianceState`, with any rows they add to Settings › About.
- **`ApiError`**, rendered as `wslib-http-error`'s body, and `audit!`, which
  writes a row to the audit log for a change a route made.
- **`Logs`**: the ring the Logs screen reads and audit events leave through,
  capturing this family's crates and the product's own by target.
- **`TaskTable`** and `spawn_sweeper`, for work that runs beside the routes,
  and `feed`/`sse` for live views.
- **`tls`**: the serving pair, and outbound trust in the OS store, pinned
  hosts and installed authorities.

## A crypto provider

This crate enables no rustls provider. Install one before serving, or
building refuses with `ServeError::NoCryptoProvider`:

```rust
let _ = rustls::crypto::ring::default_provider().install_default();
```

## Features

- `testing`: the harness-free half of a backend's test harness (a request
  builder, body readers, a TLS peer to dial, a passkey), for a product's tests.
  Its TLS peers, authorities and `self_signed` need a provider the test
  installs, such as a `rustls` dev-dependency with `ring`.
- `sessions`: `backend::Callers::sessions`, so the rungs take the session
  cookie, for a backend that keeps sessions.
