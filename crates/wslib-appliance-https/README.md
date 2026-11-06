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

## Sessions and second factors

`POST` and `DELETE /api/session` sign in and out with an `HttpOnly`,
`Secure`, `SameSite=Strict` cookie under the base path, and
`PUT /api/session/password` changes the caller's own password, proving the
current one. A session is a store row, re-checked against its account on
every request; disabling an account or changing its password deletes its
sessions.

A host on these sessions that checks credentials of its own issues the
session with `issue_session`, which hands back the same cookie.

When a second step is owed, `POST /api/session` answers 202 and a
`SecondStep` instead of a session: `next: "code"`, while TOTP is on, goes on
to `POST /api/session/code`, and `next: "enrol"`, for an account an
administrator required to enrol, to `POST /api/session/enrolment`. A passkey
signs in at `POST /api/session/passkey` with no code after it. While the
caller's TOTP is on, a change to its own password or factors, a backup, and
making an account or changing another's role, password, TOTP requirement or
passkeys each take a code, a recovery code or a passkey, never the password
alone.

A passkey ceremony runs only on the port in the browser's address. Behind a
dev server's proxy that passes `Host` through, `Server::origin_port` names
that port.

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
  harness. It starts with no accounts: `signed_in(username, role)` and
  `admin(username)` make one and answer a session token for `.cookie(..)`,
  and `serve_tls()` puts the real TLS listener on loopback.
