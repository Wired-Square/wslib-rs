# wslib-mcu-flash

What Wired Square's tools share when they **flash a microcontroller**: which
family a chip is in and where its images go, which host tty a USB serial
resolves to, how a firmware file becomes bytes, one progress/cancel seam, and
the backends themselves. An application supplies the artefacts, the port list
and a progress sink; nothing here knows about a fixture, a Tauri window or a
release store.

## What's here

Always on, no optional dependencies:

- **`chip`** — `ChipFamily` (`Esp32`, `Stm32`), `classify_chip` from a chip
  name's prefix, the ESP32 bootloader / application offsets and
  `default_offset` per artefact kind, `pretty_esp_chip` (`esp32s3` →
  `ESP32-S3`), and `lookup_stm32_pid` for the AN3155 product ids.
- **`ports`** — `SerialPort` (path, label, USB serial, interface number, vid/pid,
  strings), `ports_for_serial` (a composite device's ttys, interface order),
  `describe_ports`, and the `Enumerator` closure type the DFU wait polls.
- **`endpoint`** — `UsbAccess`, `Transport`, `FlashEndpoint`, `pairing_error`
  (which (family, access, transport) triples have a backend at all) and
  `resolve_endpoint`, which turns a pinned USB serial or an auto-detected
  Espressif port into the tty or DFU serial to flash through. Pure over a
  `&[SerialPort]` slice, so every branch is unit-tested without hardware.
- **`image`** — Intel HEX as `WriteSpan`s (gaps preserved) or its first span,
  DFU / DfuSe unwrapping, `load_spans` / `load_flat` by extension, and
  `pad_word_with_ff`.
- **`progress`** — `FlashStage` and the `FlashProgress` trait: `on_progress`
  (a line), `on_stage`, `on_target`, `on_bytes` and `cancelled()`, the last
  four defaulted. `LogProgress` collects lines; `check_cancel` is the
  backends' cancel point.
- **`artefact`** — `MaterialisedArtefact`: a kind, an offset and a path on disk.

Behind features:

| Feature | Adds | Pulls in |
| --- | --- | --- |
| `ports` | `ports::discover`, `resolve_by_serial`, `usb_info_for` — the host's USB ttys | `serialport` |
| `esptool` | `tool::EsptoolFlasher` — `esptool write-flash` / `erase-flash` as a child process | `tokio`, `async-trait` |
| `dfu-util` | `tool::DfuUtilFlasher` — `dfu-util -S <serial> -a <alt> -D <image>`, then a wait for the ttys to return | `tokio`, `async-trait` |
| `espflash` | `esp` — the Espressif serial bootloader in process: `detect_chip`, `flash`, `read_flash`, `erase` | `espflash`, `serialport` |
| `dfu` | `dfu` — USB DFU 1.1 / DfuSe in process: `list_devices`, `flash` | `dfu-nusb`, `dfu-core`, `nusb` 0.1 |
| `stm32-uart` | `stm32_uart` — ST AN3155 over a USB-UART with RTS/DTR bootloader entry: `detect_chip`, `flash`, `read_flash`, `erase`; `detect` when `espflash` is on too | `serialport` |
| `mcumgr` | `mcumgr` — an MCUboot image over SMP on a `wslib_mcumgr::Session`: `flash`, then test or confirm and reset; `wslib_mcumgr` re-exported. `mcumgr-udp` and `mcumgr-ble` add its transports | `wslib-mcumgr` |
| `serde` | `Serialize` / `Deserialize` on the stage, family, port and chip-info types | `serde` |

## Using it

From the `wired-square` registry (see the workspace README for its setup):

```toml
wslib-mcu-flash = { version = "0.1", registry = "wired-square", features = ["ports", "esptool"] }
```

On Linux, `ports`, and so `espflash` and `stm32-uart`, needs `libudev-dev`
and `pkg-config` for `serialport`.

The tool backends are `async` and expect a tokio runtime:

```rust
use wslib_mcu_flash::{ChipFamily, MaterialisedArtefact, Transport, UsbAccess};
use wslib_mcu_flash::endpoint::{resolve_endpoint, FlashEndpoint};
use wslib_mcu_flash::progress::LogProgress;
use wslib_mcu_flash::tool::{EsptoolFlasher, Flasher};

let ports = wslib_mcu_flash::ports::discover();
let endpoint = resolve_endpoint(ChipFamily::Esp32, UsbAccess::Native, Transport::Direct, Some("58:8C"), &ports)?;
let FlashEndpoint::Tty { path, .. } = endpoint else { unreachable!() };

let artefacts = vec![MaterialisedArtefact { kind: "application".into(), offset: Some(0x20000), path: "app.bin".into() }];
let mut log = LogProgress::default();
EsptoolFlasher::new("esp32c6".into(), path, 921_600, artefacts, false)?
    .flash(&mut log)
    .await?;
```

The in-process backends block on the port or the USB handle. They take the
progress sink by `&mut`, so hand them a runtime's blocking pool:

```rust
use wslib_mcu_flash::esp::{self, EspFlashOptions};

let options = EspFlashOptions { chip: esp::parse_chip(Some("esp32s3"))?, ..Default::default() };
tokio::task::spawn_blocking(move || {
    let mut sink = MySink::new(flash_id);          // impl FlashProgress; `cancelled()` reads your registry
    esp::flash("/dev/ttyACM0", "app.bin".as_ref(), 0x10000, &options, &mut sink)
}).await??;
```

`mcumgr` is `async` on the caller's session, whatever its transport:

```rust
use wslib_mcu_flash::mcumgr::{self, Activation, McumgrOptions};
use wslib_mcu_flash::wslib_mcumgr::Session;

let session = Session::connect_udp("192.168.1.42:1337".parse()?).await?;
let options = McumgrOptions { activation: Activation::Confirm, ..Default::default() };
mcumgr::flash(&session, "zephyr.signed.bin".as_ref(), &options, &mut sink).await?;
```

## Gotchas

- **Two kinds of backend.** `tool::*` spawn a process and `mcumgr` talks
  SMP, both `async`; `esp`, `dfu` and `stm32_uart` are synchronous and must
  not run on an async executor thread. The crate deliberately picks no
  runtime for them.
- **Cancellation is co-operative.** A backend asks `progress.cancelled()`
  between chunks (and, for DFU, on each progress event, where it also resets
  the device to fail the transfer). A sink that never returns `true` is
  uncancellable, which is what a station wants.
- **`dfu` pins `nusb` 0.1** through `dfu-nusb` 0.1. A consumer on `nusb` 0.2
  keeps both: alias the 0.1 copy (`nusb_dfu = { package = "nusb", version = "0.1" }`)
  and let this crate own it.
- **`esptool` speaks esptool 5**: the `esptool` executable and its hyphenated
  flags (`--before default-reset`, `write-flash`). `EsptoolFlasher::with_binary`
  only renames the program (`esptool.py` on a PlatformIO install, say); an
  esptool 4 install wants underscored flags and is not supported.
- **`--all-features` to test.** The crate defaults to no backends.
