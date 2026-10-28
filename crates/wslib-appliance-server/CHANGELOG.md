# Changelog

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
