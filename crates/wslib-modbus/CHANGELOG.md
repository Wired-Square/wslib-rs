# Changelog

## 0.2.1

- On Windows, a device closing the connection is `TransportError::Closed`,
  not `Io`.
- Modbus RTU, with no feature: `ModbusRtuStream`, which frames messages off a
  byte stream by the length rules and CRC-16/Modbus, with vendor codes declared
  by `with_vendor_functions` or laid out by `VendorLength` rules;
  `ModbusRtuOptions`; and `RtuTap`, which stamps each message by the read that
  delivered its last byte, never earlier than a stamp before it.
  `RtuTap::new(options, baud, bits_per_char)` takes the line rate and the bits
  per character, start, parity and stop included, as exact integers.
- `RtuTap::set_options` reframes a line with new options and keeps the
  timestamp floor, where rebuilding the tap with `new` loses it.
- `LengthRule::from_toml`, `is_modelled_function`,
  `ModbusRtuStream::frames_function` and `rule_rejections`: `validate` reads a
  function code's rules and the modelled codes through the stream's own table.
- `ManifestMeta::parse`: a catalogue's `[meta]` name and version.
- `ts`: `VendorLength`, `LengthRule`, `Selector` and `VendorLen`.
- tokio's floor is 1.53.3; a consumer building with
  `--locked` on an older lockfile may need `cargo update -p tokio`.

## 0.2.0

- Breaking: `encode_signal` and `encode_enum` refuse a value the field can't
  hold once unscaled and rounded with `EncodeError::OutOfRange`, carrying the
  raw value and the field's raw range. 0.1.0, like the code it was ported
  from, clamped it to the field's width.
- `testing`: `RegisterBanks`, holding, input, coil and discrete banks that
  `device` answers from. A write lands in its bank and reads back, a test
  seeds and inspects them, and `apply_writes(false)` acknowledges writes
  without applying them.
- rust_decimal's floor is 1.42; a consumer building with `--locked` on an
  older lockfile may need `cargo update -p rust_decimal`.

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
