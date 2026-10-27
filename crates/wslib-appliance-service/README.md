# wslib-appliance-service

An appliance as a background service on a desktop, under launchd or the
Windows service control manager: `wslib-appliance-core`'s router served on
control endpoints alone, with no network listener, TLS, sign-in or
onboarding. A request may do what its endpoint's ceiling allows.

- **`LocalBootstrap::macos`** and **`LocalBootstrap::windows`** lay out the
  state directory, the database, the log file and one endpoint per role:
  sockets in directories owned by a group per role on macOS, pipes granted to
  a local group per role on Windows. Each field is public, so a product
  overrides any of them.
- **`Service::serve_local`** refuses, before anything binds, a state
  directory or endpoint directory that others could reach or replace, then
  serves until the product's stop.
- **`daemon`** is the `wslib-service` daemon to run it under, and
  **`install_logs`** the log ring and the file it writes.
- **`Service::api`**, **`about`**, **`logo`** and **`task`** add the
  product's routes, About rows and background work, as on
  `wslib-appliance-server`. **`local_api`** mounts routes that a backend with
  accounts refuses to serve.

## A crypto provider

This crate installs no rustls provider. Install one before
`daemon(..).run`, or `serve_local` refuses with
`ServeError::NoCryptoProvider`: the service logs that sentence and exits in
failure, and a service manager set to restart on failure keeps restarting
it. In `main`, before the daemon:

```rust
let _ = rustls::crypto::ring::default_provider().install_default();
```

## Features

- `testing`: `testing::Harness`, the service served on a temporary layout
  with a request over each role's endpoint. Take it on a dev-dependency, and
  install a provider in the tests before serving a harness.

  ```rust
  let builder = Harness::builder();
  let store = builder.bootstrap().open_store(Some(sqlx::migrate!("./migrations"))).await?;
  let service = Service::new(store, branding(), "0.0.0", wslib_appliance_service::logs(&[])).api(my_routes());
  let harness = builder.serve(service).await;
  assert_eq!(harness.get(Role::Viewer, "/api/devices").send().await.status(), StatusCode::FORBIDDEN);
  harness.stop().await;
  ```

  The OS trust store is never read under it, so an unpinned dial trusts the
  installed authorities alone.
