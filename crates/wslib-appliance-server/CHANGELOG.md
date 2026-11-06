# Changelog

## 0.1.4

- `HarnessBuilder::console_app(name, usernames)`: the harness answers
  `GET /api/switcher` at the origin root as the console in front does, with
  the console and then each declared app the asserted caller holds a role
  in. A product's own router still does not answer it.
- Re-exports `HookCaller`, for a product's own routes on
  `BackupHooks::routes`.
- Pins `wslib-appliance-core` at 0.1.4.

## 0.1.3

- Pins `wslib-appliance-core` 0.1.3.

## 0.1.2

- Pins `wslib-appliance-core` 0.1.2.

## 0.1.1

- Pins `wslib-appliance-core` 0.1.1.

## 0.1.0

Moved from `appliance-server` 0.17.1 in wslib-appliance-rs; what differs:

- No rustls crypto provider is installed: the consumer installs one before
  serving. `Server::serve` and `Server::serve_ingress` refuse with
  `ServeError::NoCryptoProvider` when none is installed, where 0.17.1
  installed ring itself. A `testing::Harness` needs one too, and panics
  without it.
- The `test-support` feature is `testing`. `testing::TempDir` is gone: use
  `tempfile`. The harness's directory is a `tempfile` one.
- `testing`, `tls` and the other items re-exported from `wslib-appliance-core`
  carry that crate's changes, and `files` is no longer re-exported; see its
  changelog.
- A harness that cannot assemble panics with "the harness assembles: " and
  the refusal (was "the trust tables load"); a `resolver` harness with no
  provider panics while minting its pair.
- The routes' audit rows carry `wslib_appliance_core` and
  `wslib_appliance_auth` targets (was `appliance_core`, `appliance_auth`).
  The log ring captures `wslib_appliance_*` in place of `appliance_*`, so a
  product's own `appliance_*` crates must now be named to `logs` (see
  `wslib-appliance-core`).
- `wslib-appliance-core`'s reworded refusal for a reserved name in an
  asserted identity ("a user name reserved for the appliance") reaches the
  app and hooks sockets and the ingress front.
