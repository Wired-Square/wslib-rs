# wslib-can-bus

A CAN adapter's address, `CanBus`, written as one short string, and a
wslib-can task opened on it. Every crate that names a CAN adapter uses this
grammar.

```rust
use wslib_can::CanOptions;
use wslib_can_bus::{BusConfig, CanBus, open};

let bus: CanBus = "slcan=ttyACM0".parse()?;
let task = open(&bus, BusConfig::classic(Some(500_000)), CanOptions::default()).await?;
```

| Bus                                 | Feature     | Where                            |
| ----------------------------------- | ----------- | -------------------------------- |
| `can0`, any SocketCAN interface     | `socketcan` | Linux                            |
| `slcan=<name>`, `/dev/<name>`       | `slcan`     | anywhere; bare `COM3` on Windows |
| `slcan=by-id:<name>`                | `slcan`     | Linux                            |
| `gsusb[=<serial>]`                  | `gsusb`     | macOS, Windows                   |
| `pcan[=<serial>]`                   | `pcan`      | macOS, Windows                   |
| `gvret=<host>[:<port>]`, port 23    | `gvret`     | anywhere, over TCP               |

- On Linux, gs_usb and PEAK adapters are SocketCAN interfaces, so name those.
  A gs_usb or PEAK bus without a serial takes the one adapter attached.
- A bus contains no `/` or `@`, so `@` can follow it, e.g. to start a device
  id. An IPv6 GVRET host is written in brackets.
- `open` runs an SLCAN, gs_usb or PEAK adapter at `BusConfig`'s bitrate.
  Without one it fails with `OpenError::NoBitrate`. A SocketCAN interface and
  a GVRET device keep their own bitrate and ignore the one given.
  `BusKind::sets_bitrate` says which kinds take one.
- `BusConfig::fd` opens the adapter for CAN FD. SLCAN, gs_usb and PEAK need
  its data bitrate too, or fail with `OpenError::NoDataBitrate`. SocketCAN
  opens an FD socket at the interface's own rates. GVRET has no CAN FD and
  fails with `OpenError::NoFd`. An adapter without CAN FD refuses it as
  `OpenError::Open`.
- A bus this build doesn't open still parses. `open` fails with
  `OpenError::FeatureOff` when its feature is off, and with
  `OpenError::Unreachable` when this platform reaches its adapter another
  way. `refusal` says which without opening. `BUS_FORMS` lists only what
  this build opens.

## Features

None is on by default. A default build is the address types alone, with no
dependencies.

- `task`: `open`, which refuses every bus unless an adapter feature is on
  too. A library that opens a bus should enable only `task`, and leave the
  adapters to the application.
- `slcan`, `socketcan`, `gsusb`, `pcan`, `gvret` (with `task`): `open` on
  that adapter, through the matching `wslib-can-*` crate's `transport`.
