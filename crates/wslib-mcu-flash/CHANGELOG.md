# Changelog

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
