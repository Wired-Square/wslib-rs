# Changelog

## 0.1.1

- `gates`: the rules a product's CI checks with the version of this tool it
  installs; a failed gate exits `1`, and a warning never fails. The default
  run compiles nothing: the product's own forbidden names, no `sqlx::query!`,
  every `wslib-appliance*` crate in `Cargo.lock` from a registry (a warning
  when one is not at the version this tool renders for), exactly one rustls
  provider where rustls is in the graph, and `packaging diff`. `--release`
  adds clippy for `aarch64-unknown-linux-musl` and the host with
  `-D warnings`, and the tests.

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
  `wslib-appliance-xtask` or "this tool" where they said "the chassis" or
  "chassis-owned", and point at
  `cargo install` and this crate's README rather than a tag or a build guide.
  `appliance.toml.example` says "an earlier release's" for "an earlier tag's".
- `--version` names the commit only when built from a checkout; a registry
  install prints `(unknown)` for it.
- No `pins_gate` test: it checked a CI step of the old repository. No test
  that a consumer's scaffold is in step either: no consumer lives here.
