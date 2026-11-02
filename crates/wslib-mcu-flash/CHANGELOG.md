# Changelog

## 0.2.0

- `identity::PortIdentity` names a port by USB serial (`usb:<serial>`), by
  USB topology path (`usb-path:<name>`, a `/dev/serial/by-path` entry) or by
  tty. It parses strictly, prints as the same string and, with `serde`,
  serialises as it.
- `SerialPort.topology` holds a port's `/dev/serial/by-path` names; `ports`
  fills it on Linux. `by_path_index` reads such a directory.
- `ports_for_identity`, `identities_for` and `resolve_identity` replace
  `ports_for_serial` and `resolve_by_serial`.
- `resolve_endpoint` takes `Option<&PortIdentity>`, so a USB-serial bridge
  with no serial number is addressable by the USB port it sits on.
  `FlashEndpoint::Tty` and `DetectedDirectDevice` carry an `identity`; an
  auto-detected port reports its serial, else its first topology name.
- A topology identity off Linux fails as unsupported, never as not attached.
- `FlashError::NotAttached` names the identity: `USB device "usb:X" not
  attached`.
- `esp`: `EspFlashOptions.expected_mac` makes `flash`, `flash_images` and
  `erase` refuse, with `FlashError::IdentityMismatch` and before anything is
  written, a chip whose MAC differs or cannot be read.
  `identity::mac_matches` compares MACs across `:` / `-` and case.

## 0.1.2

- `dfu`: `flash_alt` downloads to a chosen alt setting, with a DfuSe address
  or none for a plain DFU 1.1 target; `flash` is `flash_alt` on alt 0.
  `detach_and_flash` takes a running application's DFU runtime interface
  into DFU mode (DETACH, then a USB reset unless the device detaches
  itself), downloads, and waits for its ttys to return, honouring the
  cancel throughout. `DetachOptions` sets the alt, address and waits.
- `esp`: `flash_images` writes several `(offset, image)` pairs in one
  bootloader session, refusing empty or overlapping images, and reports
  bytes over their total.

## 0.1.1

- `mcumgr`: `mcumgr::flash` uploads an MCUboot image over a
  `wslib_mcumgr::Session`, then tests or confirms it and resets, as
  `Activation` says; it reports through `FlashProgress` and honours its
  cancel mid-upload. `wslib_mcumgr` is re-exported. `mcumgr-udp` and
  `mcumgr-ble` turn on wslib-mcumgr's transports.
- serde's floor is 1.0.228, thiserror's 2.0.20, tokio's 1.53.1, async-trait's 0.1.92 and wslib-file-atomic's 0.1.6.

## 0.1.0

- Moved from wslib-mcu-rs, where it was distributed by git tag. This is the
  API of tag `v0.1.1`, unchanged: the registry line starts at 0.1.0, which is
  not a downgrade.
- Fixes on top of git `v0.1.1`:
  - `stm32_uart::read_flash` reads 256 bytes or more; a full 256-byte chunk
    was sent as length 0 and refused.
  - `run_cmd_streaming`, under `EsptoolFlasher` and `DfuUtilFlasher`, kills
    the tool when `cancelled()` turns true, returning `Cancelled`, or when the
    future is dropped.
  - Its relay decodes output lossily and also ends a line at `\r`, so a byte
    that isn't UTF-8 no longer stops relaying and closes the tool's pipe.
  - `esp::flash` reports success once the write has finished, even if a
    cancel arrives after it.
  - `esp::read_flash` and `stm32_uart::read_flash` write beside the output
    file and rename it into place on success, so a failed or cancelled read
    leaves an existing file as it was. The file is created `0644`.
  - `EsptoolFlasher` runs esptool with `TERM=dumb` and `NO_COLOR=1`, so
    progress arrives as plain lines without cursor or colour codes.
