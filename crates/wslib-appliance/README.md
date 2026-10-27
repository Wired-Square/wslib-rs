# wslib-appliance

The appliance family in one dependency:

- `wslib_appliance::types` is [`wslib-appliance-types`](../wslib-appliance-types),
  the wire contract; the `ts` feature turns on its TypeScript.
- `wslib_appliance::config` is [`wslib-appliance-config`](../wslib-appliance-config),
  the bootstrap settings.
- `wslib_appliance::store` is [`wslib-appliance-store`](../wslib-appliance-store),
  the database, behind the `store` feature (off by default).
- `wslib_appliance::auth` is [`wslib-appliance-auth`](../wslib-appliance-auth),
  the sign-in, behind the `auth` feature (off by default), which turns on
  `store`.
- `wslib_appliance::core` is [`wslib-appliance-core`](../wslib-appliance-core),
  the router, the authority and the workers, behind the `core` feature (off
  by default), which turns on `auth`. `use wslib_appliance::core;` shadows
  the built-in `core` crate in that module.
- `wslib_appliance::server` is [`wslib-appliance-server`](../wslib-appliance-server),
  the backend behind a console or an ingress proxy, behind the `server`
  feature (off by default), which turns on `core`.
- `wslib_appliance::https` is [`wslib-appliance-https`](../wslib-appliance-https),
  the backend that serves its own browser over TLS, behind the `https`
  feature (off by default), which turns on `core`.
- `wslib_appliance::service` is [`wslib-appliance-service`](../wslib-appliance-service),
  the backend served on control endpoints as a desktop service, behind the
  `service` feature (off by default), which turns on `core`.
- `wslib_appliance::backup` is [`wslib-appliance-backup`](../wslib-appliance-backup),
  the sealed backups, their routes and their schedule on any of the
  backends, behind the `backup` feature (off by default), which turns on
  `core`.
- `wslib_appliance::client` is [`wslib-appliance-client`](../wslib-appliance-client),
  a Windows desktop app's connection to the service's pipe, behind the
  `client` feature (off by default), which turns on nothing else.

```toml
[dependencies]
wslib-appliance = { version = "0.1", registry = "wired-square" }
```

Each `wslib-appliance-*` crate keeps its own version, and this crate pins
each exactly, so naming it is naming a matched set.

## Choosing a backend

Take `server` for a box whose console proxies to the app and signs people
in, or for Home Assistant's ingress; `https` for a package with nothing in
front of it, which needs its own TLS listener, sign-in and accounts; and
`service` for a desktop. All three take the same `Mount`s, so a product
writes its routes once, and one binary can carry `server` and `https` and
pick at start: behind a console when `Bootstrap::proxied` is set, else
HTTPS.

The browser half is `@wired-square/appliance-ui` and `@wired-square/kit`, in
wslib-ts. A product's packaging, and a stand-in console for development, are
`wslib-appliance-xtask`'s; see its README.
