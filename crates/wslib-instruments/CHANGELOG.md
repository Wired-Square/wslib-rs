# Changelog

## 0.3.0

- `wiredreflow::bus::CanBus`'s parse fails with wslib-can-bus'
  `BusParseError`, not a `String`. An empty bus still names the buses this
  crate opens.
- It refuses a SocketCAN interface name containing `@` or `/`, which a
  wiredreflow URI can't address: `@` starts the device id and `/` a signal.
- The CAN bus address and its opener come from wslib-can-bus. The `can-*`
  features alone decide which buses it opens and which `BUS_FORMS` it lists.
- A build that opens no CAN bus says to build it with an adapter this
  platform reaches, not to enable a `can-*` feature.
- A gs_usb or PEAK bus on Linux says to name its SocketCAN interface, not to
  use `can-socketcan`.
- wslib-framelink-protocol 0.2.1's `can_id` reads and writes a WiredReflow
  device id, with the same messages.
- wslib-can's floor is 0.1.2, the same as wslib-isotp's and
  wslib-framelink's.

## 0.2.0

- On wslib-framelink-protocol 0.2, whose `SignalKey` it re-exports.

## 0.1.2

- `Cluster` is `Sync` again, so it can be shared across threads.
- `Probe::release_within` declares the longest dropping a probe waits for
  what it holds, 15 s unless a probe says otherwise. A narrowed probe passes
  on its inner probe's.
- Dropping a `Cluster` waits as long as dropping all its probes at once would,
  plus up to 1 s while each finishes its poll, not for each probe in turn.
- Dropping a WiredReflow probe waits for its CAN task too, rather than giving
  up on it first.
- The `wiredreflow` scheme matches in any case, like `121gw`.
- An error that lists bus forms names only the `BUS_FORMS` this build opens.

## 0.1.1

- `gw121::notify` reads and writes the `.notify` capture format, one chunk per
  line, for `Replay` to decode. A parse error names its line.
- Dropping a probe or a `Cluster` waits for its thread, so the adapter is free
  to reopen once the drop returns. A thread still running after 15 s is left
  to finish alone.

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
