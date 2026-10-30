# Changelog

## 0.1.0

- The bench-instrument readers, moved in: `Probe`, `Sample`, `Value`,
  `ProbeError`, `ProbeUri` with `open` and `narrowed`, `Cluster`, the 121GW
  over BLE with its raw-notify tap, and the WiredReflow over CAN.
- `Probe::name` is the probe's canonical URI, which parses back:
  `121gw:<target>`, `wiredreflow:<bus>@<device>` with the device found, and a
  narrowed probe's `/<signal>` slugs after it.
- Every backend is behind a feature, none on by default. A probe whose backend
  is left out still parses, and opening it fails with
  `ProbeError::FeatureDisabled` naming the feature. `URI_FORMS` is now a list
  of the forms this build opens, beside `BUS_FORMS`.
- A bus hint offers only what the platform has: `slcan=by-id:` on Linux, a
  SocketCAN interface on Linux, gs_usb and PEAK on macOS and Windows. On
  Windows, `slcan=<name>` opens the bare port name, e.g. `COM3`.
- `gvret=<host>[:<port>]`: a WiredReflow on a GVRET device over TCP.
- `signal` re-exports `SignalKey` and the quantity, aspect and channel
  constants the probes' keys use.
- A CAN bus runs its runtime on a thread of its own, so a probe may be opened,
  read and dropped inside a tokio runtime.
- `Sample` carries `wall_clock` beside `at`, both taken from one `Stamp`.
  `ble::Chunk` carries a `Stamp` too, so a capture feeds `decode::samples`.
- `serde`: `Sample`, `Value`, `ProbeUri` and `ble::Seen`.
- btleplug 0.13. `ble::scan` returns `io::Result`.
