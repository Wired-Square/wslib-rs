# wslib-instruments

Bench-instrument readers behind one blocking `Probe`. Every reading is a
FrameLink signal (`wslib-framelink-protocol`), named by its key slug, e.g.
`device.0.measurement.temperature.ch0`, and stamped on the process's clock and
the wall clock.

```rust
use std::time::{Duration, Instant};

use wslib_instruments::{signal::slug, uri::{ProbeUri, open}};

let uri: ProbeUri = "wiredreflow:slcan=cu.usbmodem2101@028F08/TC1".parse()?;
let mut probe = open(&uri)?;
for sample in probe.next(Instant::now() + Duration::from_secs(2))? {
    println!("{} {}", slug(&sample.key), sample.value);
}
```

- `Probe::name` is the probe's canonical URI, e.g. `wiredreflow:can0@028F08`
  with the device it found, which parses back. A narrowed probe keeps its
  probe's name: the selection is not part of its identity.
- `Probe::next` blocks until a reading or the deadline. A probe runs its own
  runtime on its own thread, so it may be opened, read and dropped inside a
  tokio runtime, a current-thread one included.
- `Cluster` polls several probes, each on its own thread, and holds each
  signal's latest sample, stale once older than the probe's maximum interval.
- `uri::narrowed` and the `/<signal>` selectors keep only the signals asked for.

## Probes

- **EEVblog 121GW over Bluetooth LE** (`ble`): `121gw` or
  `121gw:<address-or-name>`. Thermocouple temperature, the meter's internal
  temperature, and the meter status (APO, low battery, OL). The stale burst
  the meter replays on connecting is dropped. `Gw121Probe::start_tapped`
  copies every raw notification out for capture, `gw121::notify` reads and
  writes a capture as text, `gw121::Replay` decodes it again, and `ble::scan`
  lists the meters in range.
- **WiredReflow board over CAN**: `wiredreflow:<bus>[@<device-id>]`. TC1, TC2,
  CJ1 and CJ2 at 0.1 °C every 500 ms, and each channel's MAX31856 fault byte.
  TC1 and TC2 are published only when the board's fault report for the same
  reading is clear. Without a device id, the one board on the bus is found.
  The adapter runs in normal mode, because CAN needs a second node to
  acknowledge the board's frames; the probe never transmits.

| Bus                                 | Feature         | Where                 |
| ----------------------------------- | --------------- | --------------------- |
| `can0`, any SocketCAN interface     | `can-socketcan` | Linux                 |
| `slcan=<name>`, `/dev/<name>`       | `can-slcan`     | anywhere; bare `COM3` on Windows |
| `slcan=by-id:<name>`                | `can-slcan`     | Linux                 |
| `gsusb[=<serial>]`                  | `can-gsusb`     | macOS, Windows        |
| `pcan[=<serial>]`                   | `can-pcan`      | macOS, Windows        |
| `gvret=<host>[:<port>]`, port 23    | `can-gvret`     | anywhere, over TCP    |

On Linux, gs_usb and PEAK adapters are SocketCAN interfaces, so name those. A
port name can't contain `@`, which starts the device id.

## Features

None is on by default, and a default build pulls in no btleplug, tokio or CAN
backend. A probe whose backend is left out still parses; opening it fails with
`ErrorKind::Unsupported` around `ProbeError::FeatureDisabled`, naming the
feature. `URI_FORMS` and `BUS_FORMS` list only what this build opens.

- `ble`: the 121GW, over btleplug.
- `can-slcan`, `can-socketcan`, `can-gsusb`, `can-pcan`, `can-gvret`: a
  WiredReflow on that adapter.
- `serde`: `Sample`, `Value` and `ProbeUri`. A sample serialises its key as
  the slug and `wall_clock` as microseconds since the Unix epoch.

Linux builds with `ble` need `libdbus-1-dev` and `pkg-config`. On macOS, a
process without Bluetooth permission scans silently and finds nothing, with no
error.
