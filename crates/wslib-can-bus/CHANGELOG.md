# Changelog

## 0.3.0

- `OpenError::Open`'s source is an `OpenCause`: `Io` for finding the
  adapter, or `Adapter` with the adapter's wslib-can `CanError`, in place of
  an `io::Error` wrapping either. `source()` returns the `io::Error` or the
  `CanError` itself.
- `OpenError::Open` names only the bus that did not open; the cause comes
  only through `source()`. `kind()` is the cause's `io::Error` kind, a GVRET
  connect's included, so a missing adapter or port is `NotFound`, and a USB
  listing that fails keeps its own.
- `SerialPort`'s parse fails with `PortParseError`, not a `String`.
  `BusParseError::Port` carries it as its source for an SLCAN bus whose port
  doesn't parse.
- On wslib-serial 0.2, wslib-can-slcan 0.2, wslib-can-gvret 0.2,
  wslib-can-gsusb 0.2, wslib-can-pcan 0.2 and wslib-can-socketcan 0.2.
  wslib-can's floor is 0.1.4.

## 0.2.0

- `open` takes a `BusConfig` in place of `bitrate: Option<u32>`.
  `BusConfig::classic(bitrate)` opens as before.
- `BusConfig::fd(bitrate, data_bitrate)` opens the adapter for CAN FD:
  SocketCAN with an FD socket, and SLCAN, gs_usb and PEAK at the data
  bitrate given, at the adapter's default sample point. Without a data
  bitrate those three fail with `OpenError::NoDataBitrate`. GVRET has no CAN
  FD and fails with `OpenError::NoFd`.
- `BusConfig` and `CanMode` need no feature, so a build without `task` can
  name them.

## 0.1.0

- `CanBus` and `SerialPort` parse and write a CAN adapter's address: `can0`,
  `slcan=<name>`, `slcan=by-id:<name>`, `gsusb[=<serial>]`, `pcan[=<serial>]`
  and `gvret=<host>[:<port>]`. Both are `Hash`.
- No bus contains `@`, which follows a bus to start a device id. No bus
  contains `/`, which no port name, serial or interface name holds.
- `CanBus`'s parse fails with `BusParseError`. `Empty` displays as a request
  for one of `BUS_FORMS`, and a caller that opens other forms can name its
  own. `Invalid` carries the reason.
- `BUS_FORMS` lists the forms this build opens.
- `task`: `open` opens a wslib-can task on a bus, through each adapter
  feature that is on: `slcan`, `socketcan`, `gsusb`, `pcan` and
  `gvret`. Each of them enables `task`.
- `open` takes an `Option<u32>` bitrate. An SLCAN, gs_usb or PEAK adapter
  sets the bus's rate, so it needs one and fails with `OpenError::NoBitrate`
  without it. A SocketCAN interface and a GVRET device ignore it.
  `BusKind::sets_bitrate` names the kinds that need one.
- A gs_usb or PEAK bus picks its adapter by serial.
- `OpenError` says when a feature is off, when the platform reaches an
  adapter another way, or why opening failed.
