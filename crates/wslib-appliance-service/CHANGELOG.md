# Changelog

## 0.1.5

- Pins `wslib-appliance-core` at 0.1.5.

## 0.1.4

- Pins `wslib-appliance-core` at 0.1.4.

## 0.1.3

- Pins `wslib-appliance-core` 0.1.3.

## 0.1.2

- libc's floor is 0.2.183, the workspace's.
- Pins `wslib-appliance-core` 0.1.2.

## 0.1.1

- Pins `wslib-appliance-core` 0.1.1.

## 0.1.0

Moved from `appliance-service` 0.17.1 in wslib-appliance-rs; what differs:

- No rustls crypto provider is installed: the consumer installs one before
  serving. `Service::serve_local` refuses with
  `LocalError::Serve(ServeError::NoCryptoProvider)` when none is installed,
  after the layout's checks and before anything binds, where 0.17.1
  installed ring itself. A `testing::Harness` needs one too, and
  `HarnessBuilder::serve` panics without it.
- The `test-support` feature is `testing`.
- `logs`, `Logs`, `ServeError` and the other items re-exported from
  `wslib-appliance-core` carry that crate's changes, among them what the ring
  `install_logs` builds captures; see `wslib-appliance-core`'s changelog.
- On Windows, a `LocalBootstrap::service` that is no installed service's own
  account fails at serving, as `wslib-appliance-core`'s `owned_by_service`
  now does.
- `daemon` is `wslib-service` 0.1.3's: a stop of the service's own writes
  its "stopping, by the service itself" line even when the product's `main`
  returns at once.
