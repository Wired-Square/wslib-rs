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

## Behind a console

The console asserts the caller in one header, which
`wslib_appliance_types::console::ConsoleIdentity` writes and reads:

```text
Appliance-Identity: v1; id=<pct>; user=<pct>; role=<viewer|operator|admin|hostadmin>[; reauth=<unix seconds>]
```

A missing header is 401 and a malformed one 400. Any other peer uid is
served as nobody, at most four connections at once, which `<base>/healthz`
still answers. A HostAdmin is held as Admin. The sockets the deployment
names reach `main` as `Bootstrap::proxied`:

```rust
let p = bootstrap.proxied.as_ref().ok_or("not behind a console")?;
let mut socket = AppSocket::new(&p.app_socket, p.console_uid);
if let Some(hooks) = &p.hooks_socket {
    socket = socket.hooks(hooks);
}
let served = server.serve(&bootstrap, socket, stop).await;
```

The proxy must keep the base path, not strip it. In development,
`wslib-appliance-xtask dev-console` stands in for the console.

The hooks socket serves the console alone, under `/v1` rather than the base
path: `GET /v1` (which optional hooks are served), `GET /v1/about`,
`POST /v1/notes` from `Server::notes`, and `POST /v1/backup/capture`,
`inspect` and `restore` from `Server::backup_hooks`. An `Appliance-Identity`
there names the person in the audit log and grants nothing. A hook not
served is a 404.

## Behind Home Assistant's ingress

`Ingress::new(bind, first_sight)` answers the Supervisor's `172.30.32.2`
alone, and every other peer 403 on every path but `/healthz`. The caller is
the proxy's `X-Remote-User-Id`; its role is this box's, kept in
`asserted_roles`: the first time an id is seen it takes what `first_sight`
gives its user name (`None` is a 403, and the rule is asked again next
time), and from then on the kept role wins. The crate serves no route for
those roles; a product builds its own with `Store::asserted_callers`,
`set_asserted_role` and `forget_asserted_caller`, each under
`INGRESS_SOURCE`. The proxy asserts no recent proof, so `reauthenticate`
refuses every ingress caller. A handler that writes a link or a `Location`
takes `RequestBase`, the request's `X-Ingress-Path` here and the base path
on the other backends.

`bind` must be an address the Supervisor reaches, never loopback alone, and
the state directory one that outlives the container. A stop timeout must
exceed the daemon's 22 s grace, or the drain is killed.

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

  ```rust
  let store = Store::open_in_memory(Some(sqlx::migrate!("./migrations"))).await?;
  let app = Harness::builder().store(store).api(my_routes()).build().await;
  let admin = console("admin", Role::Admin);
  let response = app.post("/api/widgets").from_console(&admin).json(body).send().await;
  assert_eq!(app.post("/api/restart").local().send().await.status(), StatusCode::FORBIDDEN);
  ```

  `.local()` sends as a control socket, which tells a `SessionAdmin` route
  from an `Admin` one. `Harness::hook` sends on the hooks socket, and
  `builder().ingress(..)` with `Req::from_peer` drives the ingress front door.
