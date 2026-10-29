# Changelog

## 0.1.0

- `protocol`: the Modbus size limits, function and exception names,
  `ExceptionCode`, and register and coil packing.
- `RegisterType`, `WriteBank` and `UnknownRegisterType`; a write names its
  bank, so a coil and a register at one address are different targets.
- `ModbusManifest`: a TOML register map parsed, decoded (`decode_frame`,
  `decode_coil_frame`, exact through `rust_decimal`) and encoded
  (`encode_signal`, `encode_enum`, `merge_register_writes`,
  `overlay_register_writes`, `group_contiguous`), and `set_frame_disabled`,
  which keeps the file's comments. A write is the exact inverse of a read in
  every byte and word order; a value that isn't finite is refused. A signal
  that can't be laid out (no bits, a numeric one over 64, or past the bank's
  65 536 addresses) is skipped at parse and reported by `validate`.
- `validate`: findings in a catalogue's `[meta]` and `[frame.modbus]`
  sections.
- `PollSchedule`, `ItemSchedule` and `FrameBackoff`: which reads are due, on
  the caller's clock, a refused read backing off.
- `chunk_ranges` and `RegisterSweep`: reads for a device with no register map,
  and a sweep's plan.
- `tcp`: `ModbusTcp`, a lazy connection that reconnects after any transport
  error, and `Poller`, a schedule read over it.
- `task`: `spawn`, a task owning a connection and a poller, reconnecting with
  backoff.
- `write`: writes, verified or not, and with `task` a `PollWriter` that writes
  between the task's reads. Off by default; without it no write path is
  compiled.
- `testing`: a fake Modbus TCP device on loopback.
- `ts`: `ts_rs::TS` on every serde type, under ts-rs 12.
