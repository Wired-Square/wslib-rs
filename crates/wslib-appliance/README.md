# wslib-appliance

The appliance family in one dependency:

- `wslib_appliance::types` is [`wslib-appliance-types`](../wslib-appliance-types),
  the wire contract; the `ts` feature turns on its TypeScript.
- `wslib_appliance::config` is [`wslib-appliance-config`](../wslib-appliance-config),
  the bootstrap settings.
- `wslib_appliance::store` is [`wslib-appliance-store`](../wslib-appliance-store),
  the database, behind the `store` feature (off by default).

```toml
[dependencies]
wslib-appliance = { version = "0.1", registry = "wired-square" }
```

Every `wslib-appliance*` crate is released at one version, and this crate
pins each exactly, so naming it is naming a matched set.
