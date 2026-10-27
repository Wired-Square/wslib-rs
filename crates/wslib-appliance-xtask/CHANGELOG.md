# Changelog

## 0.1.0

Moved from `appliance-xtask` 0.17.1 in wslib-appliance-rs; what differs:

- Installed from the registry: `cargo install wslib-appliance-xtask
  --registry wired-square`. The binary is `wslib-appliance-xtask`, and the
  rendered scripts call it by that name.
- The templates, in `templates/`, and `appliance.toml.example` live in the
  crate, so the published crate renders on its own.
- Rendered files name `wslib-appliance-xtask`, `wslib-appliance-config` and
  `wslib-appliance-store` where they named the old crates. A scaffold
  rendered by 0.17.1 shows as drift until rendered again.
- Renders for `wslib-appliance-config` 0.1.1, `wslib-appliance-store` 0.1.1
  and `wslib-appliance-server` 0.1.0.
- Messages and rendered comments that meant this tool say
  `wslib-appliance-xtask` where they said "the chassis", and point at
  `cargo install` and this crate's README rather than a tag or a build guide.
  `appliance.toml.example` says "an earlier release's" for "an earlier tag's".
- `--version` names the commit only when built from a checkout; a registry
  install prints `(unknown)` for it.
- No `pins_gate` test: it checked a CI step of the old repository. No test
  that a consumer's scaffold is in step either: no consumer lives here.
