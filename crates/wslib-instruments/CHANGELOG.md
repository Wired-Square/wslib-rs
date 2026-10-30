# Changelog

## 0.1.0

- The bench-instrument readers, moved in: `Probe`, `Sample`, `Value`,
  `ProbeError`, `ProbeUri` with `open` and `narrowed`, `Cluster`, the 121GW
  over BLE with its raw-notify tap, and the WiredReflow over CAN.
- Every backend is behind a feature, none on by default. A probe whose backend
  is left out still parses, and opening it fails with
  `ProbeError::FeatureDisabled` naming the feature. `URI_FORMS` is now a list
  of the forms this build opens, beside `BUS_FORMS`.
- `gvret=<host>[:<port>]`: a WiredReflow on a GVRET device over TCP.
- A CAN bus runs its runtime on a thread of its own, so a probe may be opened,
  read and dropped inside a tokio runtime.
- `Sample` carries `wall_clock` beside `at`, both taken from one `Stamp`.
- `serde`: `Sample`, `Value` and `ProbeUri`.
- btleplug 0.13.
