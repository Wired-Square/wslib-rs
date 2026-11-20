# Changelog

## 0.5.0

- On wslib-can-bus 0.3, whose `CanBus` it re-exports at `wiredreflow::bus`,
  and wslib-can 0.2.
- `uri::open`, `Gw121Probe::start` and `start_tapped`, and
  `WiredReflowProbe::start` fail with `probe::StartError`, in place of an
  `io::Error`: `FeatureDisabled`, `Unreachable`, `Bus` with wslib-can-bus'
  `OpenError` as its `source()`, `Thread`, `Runtime`, `Panicked`,
  `NoWiredReflow`, `ManyWiredReflows` and `Ended`. `StartError::kind` is
  the `io::ErrorKind` the `io::Error` had. `ProbeError::FeatureDisabled` is
  gone.
- `ProbeError::Disconnected { why, source }`: `why` is this crate's
  sentence, and the error that cut the instrument off (btleplug's, the CAN
  adapter's, or an `io::Error`) is the `source()`, held in an `Arc`, in
  place of one message holding both. `ProbeError` and `cluster::Latest` are
  no longer `PartialEq` or `Eq`.
- `ProbeError::Panicked { unrestarted }`: the 121GW's link thread
  panicked; `unrestarted`, the `source()`, is why it could not be started
  again.
- `gw121::ble::scan` fails with `ScanError`, a failed Bluetooth step with
  btleplug's error as its `source()`, in place of an `io::Error`.
- `ProbeUriError::Bus` holds a WiredReflow bus's `BusParseError`, and
  `ProbeUriError::UnknownSignal` a selector's signal-key parse error, each
  the `source()`, in place of their text in `Target` and `Signal`.
  `signal::parse` returns wslib-framelink-protocol's error, not a `String`.

## 0.4.0

- On wslib-can-bus 0.2, whose `CanBus` it re-exports at `wiredreflow::bus`.
  A WiredReflow bus still opens as classic CAN at its own rate.
- `wiredreflow::device_id_text` and `wiredreflow::DEVICE_ID_DIGITS` write a
  WiredReflow device id as its URI does, re-exported from
  wslib-framelink-protocol's `can_id`.

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
