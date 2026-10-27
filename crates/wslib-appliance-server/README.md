# wslib-appliance-server

An appliance's backend behind a console or Home Assistant's ingress proxy:
the audit log, the daemon's own log, Settings › About, the branding and the
browser bundle, with a product's own routes mounted beside them. The caller
is the one the front door asserts; there are no sessions, accounts or TLS
here.

- **`Server::serve`** listens on a Unix app socket behind a console, reading
  the caller from `Appliance-Identity` on the console's uid alone, and on an
  optional hooks socket the console calls for About, network notes and
  backups.
- **`Server::serve_ingress`** listens on TCP for Home Assistant's ingress
  proxy, answering its trusted peers and the user it asserts.
- **`Server::api`**, **`route`**, **`root`** and **`task`** add the product's
  routes, pages and background work. Handlers take `wslib-appliance-core`'s
  rungs (`Viewer`, `Operator`, `Admin`, `SessionAdmin`, `HostAdmin`), which
  this crate re-exports.

## A crypto provider

This crate installs no rustls provider. Install one before serving, or
serving refuses with `ServeError::NoCryptoProvider`:

```rust
let _ = rustls::crypto::ring::default_provider().install_default();
```

## Features

- `testing`: `testing::Harness`, the appliance a product's tests drive its
  routes through, with `wslib-appliance-core`'s `testing` re-exported. Take it
  on a dev-dependency, and install a provider in the tests before building a
  harness.
