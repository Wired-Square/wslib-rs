# Changelog

## 0.1.3

- `PUT /api/users/{id}/enabled` and `DELETE /api/users/{id}` take the acting
  administrator's proof over a session, as a role change does: the switch in
  its body's `proof`, the delete as a bare `FactorProof` body. The control
  socket still gives none, and a delete with no body still reads. A browser
  on an appliance-ui before one that sends the proof on enable and delete is
  refused.
- Needs `wslib-appliance-types` 0.1.3.
- An installed or restored pair reaches the browsers already connected: the
  listener drains their connections, which reconnect on the new pair, rather
  than serving the old one until they idle out. `wslib-http-server` >= 0.1.7.
- Pins `wslib-appliance-core` at 0.1.3.
- `axum-server` is no longer a dependency.

## 0.1.2

- Pins `wslib-appliance-core` 0.1.2.

## 0.1.1

- Pins `wslib-appliance-core` 0.1.1.

## 0.1.0

Moved from `appliance-https` 0.17.1 in wslib-appliance-rs; what differs:

- No rustls crypto provider is installed: the consumer installs one before
  serving. `Server::serve` refuses with `ServeError::NoCryptoProvider` when
  none is installed, before loading or minting the serving pair, where 0.17.1
  installed ring itself. A `testing::Harness` needs one too, and panics
  without it.
- The `test-support` feature is `testing`. `testing::TempDir` is gone: use
  `tempfile`. The harness's directory is a `tempfile` one.
- `testing`, `tls` and the other items re-exported from `wslib-appliance-core`
  carry that crate's changes, and `files` is no longer re-exported; see its
  changelog.
- A harness that cannot assemble panics with "the harness assembles: " and
  the refusal (was "the trust tables and session keys load").
- Audit rows carry the `wslib_appliance_https`, `wslib_appliance_core` and
  `wslib_appliance_auth` targets (was `appliance_https`, `appliance_core`,
  `appliance_auth`). The log ring captures
  `wslib_appliance_*` in place of `appliance_*`, so a product's own
  `appliance_*` crates must now be named to `logs` (see
  `wslib-appliance-core`).
