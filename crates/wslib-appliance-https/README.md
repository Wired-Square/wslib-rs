# wslib-appliance-https

An appliance's backend that serves its own browser, with no console in
front: a TLS listener, a plain-HTTP redirect beside it, the control socket,
sessions, sign-in, your own password and the first account. Most of it is
`wslib-appliance-core`'s, re-exported here.

- **`Server::serve`** listens on TLS at the bootstrap's address and HTTPS
  port, on the redirect port when one is set (it is off by default, and
  `redirect_port = 0` turns it off), and on the control socket, which
  satisfies every role up to Admin with no account at all.
- **`Server::users_routes`** serves `/api/users…` on the TLS listener too;
  the control socket always serves them. Over HTTPS the last enabled
  administrator cannot be demoted, disabled or deleted, and a password reset
  aimed at the caller's own account is refused.
- **`Server::api`**, **`route`**, **`root`** and **`task`** add the product's
  routes, pages and background work. Handlers take `wslib-appliance-core`'s
  rungs (`Viewer`, `Operator`, `Admin`, `SessionAdmin`, `HostAdmin`), which
  this crate re-exports; `SessionAdmin` refuses the control socket.
- A box with no accounts offers its first one to the browser when the
  bootstrap's `browser_onboarding` is on; otherwise its first account is
  made over the control socket.

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
