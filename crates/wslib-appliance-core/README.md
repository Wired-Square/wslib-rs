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
  A handler whose answer varies by role asks `Identity::satisfies(role)`.
  `Unclaimed::hold(&store)` begins the first account's write, re-checking
  that nobody claimed the box in between.
- **`Mount`**: routes on a state of the product's own beside
  `ApplianceState`, with any rows they add to Settings › About.
- **`ApiError`**, rendered as `wslib-http-error`'s body, and `audit!`, which
  writes a row to the audit log for a change a route made. A name of the
  product's that reaches an audit row goes through `clean_name` first.
- **`Logs`**: the ring the Logs screen reads and audit events leave through,
  capturing this family's crates and the product's own by target. Name every
  crate of the product's that emits an `audit` event: one from any other
  target is dropped. A field named like a credential is captured as
  `[redacted]`, a backstop behind `wslib_secret::Secret`.
- **`TaskTable`** and `spawn_sweeper`, for work that runs beside the routes,
  and `feed`/`sse` for live views.
- **`tls`**: the serving pair, and outbound trust in the OS store, pinned
  hosts and installed authorities (below).

## Asking again

A route whose consequence outlives the request, such as a factory reset,
takes the `Reached` extractor and a `Reauthentication` body and calls
`reauthenticate(&app, &who, &reached, proof, "factory reset")`. A route that
wants a second factor too while TOTP is on takes a `FactorProof` and calls
`prove_caller`. The control socket has nothing to prove and is answered 404,
so a route that must refuse it takes `SessionAdmin`.

A passkey ceremony runs only when the browser's address names the port the
listener serves: every TLS listener puts a `ServingPort` on each request, or
its ceremonies are refused. A console that signs its own callers in nests
`second_factor_routes` over its `HostSessions` and hands its password step
to `password_proved`.

## Dialling out

A product's HTTP client is built on `app.outbound.client_config()`, whose
verifier reads the store's pins and authorities live on every handshake. A
pooled connection outlives a removal, so rebuild clients when the tables
change:

```rust
let client = reqwest::Client::builder()
    .use_preconfigured_tls(app.outbound.client_config())
    .build()?;

let mut trust = app.outbound.subscribe();
while let Some(Ok(())) = stop.run_until_cancelled(trust.changed()).await {
    rebuild_clients();
}
```

- A pin is the whole identity: name and expiry go unchecked, and an expired
  pin still connects. An authority's own dates are not checked either.
- The OS store is read in the background at start and kept for the life of
  the process, so a `ca-certificates` upgrade is seen at the next restart.
  An unpinned dial before that read lands waits for it, at most 30 s.
- A static musl binary never resolves `.local`: dial an mDNS host by
  address.

On a backend with its own TLS listener, `app.tls` is the serving pair:
`replaceable()` says, before a transaction, whether `install_pem` would
refuse, and `pair()` reads both halves for a backup. On a backend with no
pair each answers `TlsError::Unsupported`.

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
