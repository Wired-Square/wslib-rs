# Changelog

## 0.1.1

- `gw121::notify` reads and writes the `.notify` capture format, one chunk per
  line, for `Replay` to decode. A parse error names its line.

## 0.1.0

- Bench-instrument probes behind one blocking `Probe`, each reading
  FrameLink signals: the EEVblog 121GW over BLE (`ble`), and a WiredReflow
  board over SLCAN, SocketCAN, gs_usb, PEAK or GVRET (`can-*`). No backend is
  on by default.
- `ProbeUri` parses `121gw[:<target>]` and `wiredreflow:<bus>[@<device-id>]`,
  each with `/<signal>` selectors, and `open` opens one. A backend this build
  leaves out fails with `ProbeError::FeatureDisabled`. `Probe::name` is the
  probe's canonical URI.
- `Cluster` polls several probes and holds each signal's latest sample.
- `gw121::Replay` decodes the chunks `Gw121Probe::start_tapped` captures, and
  `ble::scan` lists the meters in range.
- A probe runs its own runtime on its own thread, so it can be used inside a
  tokio runtime.
- `serde`: `Sample`, `Value`, `ProbeUri` and `ble::Seen`.
