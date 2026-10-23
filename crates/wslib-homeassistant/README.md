# wslib-homeassistant

An app running as a Home Assistant add-on. `ingress` checks that a request
came through the ingress proxy, and reads the user and base path the proxy
names. Requests as the proxy sends them come with the `testing` feature.

Needs `wslib-http-scaffold` 0.1.1 or later, for `BasePath` and
`Spa::base_from`.

```rust
use wslib_homeassistant::ingress::{self, Caller, Peers};
use wslib_http_scaffold::Spa;

let peers = Peers::home_assistant().exempt("/healthz");
let app = Router::new()
    .route("/api/me", get(async |caller: Option<Caller>| /* … */))
    .merge(wslib_http_scaffold::health())
    .fallback_service(Spa::from_dir("/usr/share/my-app/ui").base_from(ingress::spa_base));
let app = ingress::gate(app, &peers);
```

The router must be served with `ConnectInfo<SocketAddr>`, as
`wslib-http-server` does; a request without it is no trusted peer's.

## Gate or recognise

- **`gate(router, &peers)`** when Ingress is the only way in. Any peer not in
  `peers` is a 403 error body on every path but the exempt ones.
- **`recognise(router, &peers)`** when the same port also serves the app's
  own sign-in. Nobody is refused; a request from a trusted peer carries the
  arrival proof, and the proxy's headers are read on that request alone.

Either way the proof is set only by these two, on a request whose
connection's peer, canonicalised (`::ffff:172.30.32.2` is `172.30.32.2`), is
trusted. `ingress::arrived(&extensions)` reads it. The proof lives in that
request's extensions alone, so a long-lived connection (a WebSocket) reads
`Caller` and `IngressBase` before the upgrade and keeps them.

## What's here

- **`Peers`**: `home_assistant()` is the Supervisor at `172.30.32.2`;
  `new(addresses)` names others. `with_loopback()` adds `127.0.0.1` and `::1`,
  which trusts every process in the container, and with `host_network` every
  process on the host, so it is never the default. `exempt(path)` answers that
  exact URI path to anyone under `gate`: `/healthz` exempt leaves `/healthz/`
  refused.
- **`Caller`** (`id`, `name`, `display_name`), extracted as `Option<Caller>`
  from `X-Remote-User-Id`, `-Name` and `-Display-Name`. None when the request
  did not arrive or the id is empty or absent; an empty or absent name is the
  id, an empty display name is none. A header sent twice, or not UTF-8, is a
  400 naming it. `ingress::caller(&parts)` reads the same for code that sees
  only the request's head.
- **`IngressBase(Option<BasePath>)`**: `X-Ingress-Path` on a request that
  arrived, for a link or a `Location`. One that is not a `BasePath` is a 400
  `x-ingress-path: <why>`.
- **`spa_base`**: the same, as a `Spa::base_from` hook, so `index.html` is
  served with `<base href>` for the ingress path and the bundle runs under it.
- **`testing::trusted(request)`** (feature `testing`): the request as if from
  the Supervisor. **`testing::RemoteUser::new(id).name(..).display_name(..)
  .on(request)`** adds the user headers.

No store, roles or audit: what a caller may do is the app's.
