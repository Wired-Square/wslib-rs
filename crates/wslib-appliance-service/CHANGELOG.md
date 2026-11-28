# Changelog

## 0.2.1

- On wslib-appliance-core 0.2.1.

## 0.2.0

- Pins `wslib-appliance-core` at 0.2.0. On wslib-appliance-store 0.2,
  wslib-file-atomic 0.2 and wslib-service 0.2.
- `LocalError::Refused`, `Store` and `Serve` say only what failed, and give
  the `Refused`, `StoreError` or `ServeError` through `source()`, rather
  than being that error.
- `LocalError::Unreadable` is a control endpoint's directory whose metadata
  could not be read, and `LocalError::GroupLookup` an endpoint's group that
  could not be looked up, each with the `io::Error` as `source`; both were a
  `Refused` carrying that error's text.
- `LocalError::GroupLookupPanicked`: the thread looking up an endpoint's
  group panicked. It was a `Refused` saying the lookup failed.

## 0.1.6

- Pins `wslib-appliance-core` at 0.1.6.

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
