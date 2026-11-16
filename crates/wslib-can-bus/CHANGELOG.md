# Changelog

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
