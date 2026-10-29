# wslib-appliance-types

An appliance's wire contract: the types its daemon, its browser and any other
client share, both what a client reads and the request bodies it sends. Serde
only; no runtime, database or HTTP stack comes with it.

```rust
use wslib_appliance_types::{Page, Role, User};

if caller.allows(Role::Operator) { /* … */ }
let page: Page<User> = serde_json::from_str(&body)?;
```

## What's here

- **`Role`**: `Viewer < Operator < Admin < HostAdmin`, a ladder; `allows`
  is "at least", `as_str` and `FromStr` the stored slug, `LADDER` every role.
- **`AppLink`**: one entry of an app switcher, `href` an origin-absolute path.
- **Accounts and sessions**: `User`, `ListedUser`, `AppRole`, and the bodies
  in `account` and `session`. Every password or code is a
  `wslib_secret::Secret`, and no request body in `session` carries an account id.
- **Second factors**: `totp` and `passkey`, over `wslib-auth-totp`'s
  `ClockSkew` and `wslib-auth-passkey`'s WebAuthn JSON.
- **The rest of an appliance's surface**: `about`, `audit` (with `Page` and
  `MAX_AUDIT_PAGE`), `backup` (a bundle's plaintext header and the schedule),
  `branding` (theme tokens and their caps), `console` (the identity header a
  proxied app reads), `hooks` (console to app, never exported to
  TypeScript), `host`, `log`, `manifest` (an app's container manifest and its
  OCI label), `pending` (a change applied and not yet known to have taken),
  `tls` and `trust`.
- **`Availability`**: a subsystem `Ready { via }` or `Unsupported { because }`.
- **`ApiErrorBody`**: `wslib-http-error`'s, re-exported.
- **Constants a browser needs**: password and username bounds, `STALE_PROOF`,
  `MAX_APP_LEN` and `is_app_name`, the backup and branding caps.

## The `ts` feature

Every type a browser reads or sends derives ts-rs 11's `TS`. ts-rs writes a
type, and each type it references, into `TS_RS_EXPORT_DIR` when an `export`
test runs, this crate's or a consumer's; set the variable in the consumer's
`.cargo/config.toml`. `constants.ts` comes only from this crate's own tests.
A field wider than 32 bits is `number`, never `bigint`, and a `Secret` is a
plain `string`.

## The manifest

`manifest::AppManifest` is what an app run as a container declares to its
console. The image carries it, less `image`, as an `AppLabel` in its
`MANIFEST_LABEL` OCI label, and the console adds the image it loaded, pinned
by digest, with `AppManifest::from_label`. `name` passes `is_app_name` and is
the base path, `/apps/<name>/`. An unknown field is refused at parse, and
`validate()` names the first rule broken. Read `ManifestSchema` first: a
`schema` newer than `MANIFEST_SCHEMA` is kept and not run, never refused as
corrupt. A manifest is written at its `oldest_schema()`, so one that declares
no devices stays at schema 1 and an older console still runs it. The console
runs the image as a uid of its choosing in group 0.
