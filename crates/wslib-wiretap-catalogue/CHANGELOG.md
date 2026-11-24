# Changelog

## 0.4.0

- On wslib-serial 0.2, whose `DelimiterOptions` it re-exports, and
  wslib-modbus 0.3, whose `Finding`, `RegisterType`, `UnknownRegisterType`
  and `WriteBank` it re-exports, and wslib-wiretap-protocol 0.3.
- `DocumentError` is the error of `edit::apply_edit`, `apply_edits` and
  `bump_meta_version`, `migrate::migrate`, `dbc::render_catalogue_as_dbc`
  and its `_with_mode`, and `dbc::import::convert_dbc_to_toml`, in place of
  a `String`: `Refused` for the crate's own sentences, `Toml` and
  `TomlDocument` with toml's and toml_edit's errors, and `Dbc` with
  can-dbc's error, boxed, each the `source()`.
- `CatalogueError::Toml` and `RtuRulesError::Toml` say "catalogue is not
  valid TOML", with toml's error as their `source()`.
- `DocumentError`, `CatalogueError::Toml` and `RtuRulesError::Toml` no longer
  write toml's line and column, or can-dbc's text, in their `Display`. A
  caller that showed `to_string()` now shows less and gets no compile error:
  walk `source()` for the rest.

## 0.3.1

- Takes `wslib-quantity` 0.2.0.

## 0.3.0

- `ChecksumConfig` is gone: `SerialConfig::checksum` is a `FrameChecksum`, so
  a serial-level checksum goes through `verify_frame_checksum` and carries a
  name, parameters and notes. Its byte order is `endianness`, from a
  `byte_order` or `endianness` key; a catalogue with only the legacy
  `big_endian` key reads as before (big when true, otherwise little for a
  checksum wider than a byte). The served and TS `SerialConfig.checksum` is
  now a `FrameChecksum`, with `endianness` in place of `bigEndian`.
- `validate` checks every frame's checksum tables and `[meta.serial.checksum]`,
  at paths such as `frame.serial.0x10.checksum[0].algorithm`: an unknown or
  missing algorithm, a missing or malformed `start_byte`, an out-of-range byte
  length, calculation range or byte order, and a `crc_custom` with no
  polynomial. The parser drops such a table, which before went unreported.
- `SerialChecksumFields` takes a frame checksum's fields (`name`,
  `endianness`, the CRC and offset parameters, `notes`) and drops `big_endian`,
  so a solved checksum set through `SetSerialConfig` reads back unchanged. The
  op writes `endianness` and removes a legacy `big_endian` or `byte_order`.

## 0.2.0

- `Signal::precision`, from a signal's `precision` key beside `unit` and
  `display`: the decimal places its numeric display is fixed to, rounded half
  away from zero. Without it the display keeps every digit, as before. The TS
  `Signal` gains `precision?: number | null`.
- The numeric display goes through wslib-quantity's `format_decimal`.
- `validate` reports a `precision` that is not a whole number from 0 to 28, in
  every section, Modbus included; the parser reads one as no precision.

## 0.1.1

- serde's floor is 1.0.228.
- thiserror's floor is 2.0.20.

## 0.1.0

- The WireTAP catalogue, moved from `wiretap-catalog` at v0.10.2: the model,
  parse, validate, decode, edit, migrate, mirror, layout, mux cases, summary,
  text, serial framing and its detection, DBC, `rtu_rules` and `rtu_decode`,
  and `byte_name` from `wiretap-decode`. The TOML format, the serde shapes and
  the TS declarations are unchanged.
- Rust names say catalogue: `Catalogue` (TS `Catalog`), `CatalogueSummary` (TS
  `CatalogSummary`), `CatalogueError`, `SerialFramer::with_catalogue` and
  `render_catalogue_as_dbc*`.
- The Modbus register map, schedules, sweep and RTU framing are
  wslib-modbus's, and the shared enums (`RegisterType`, `WriteBank`,
  `SignalFormat`, `DisplayHint`, `Endianness`) and `ValidationError` are
  wslib-modbus's and wslib-bits' types, re-exported.
- `validate` takes `[meta]` and `[frame.modbus]` from `wslib_modbus::validate`,
  whose messages say "Catalogue", and which also reports a Modbus signal that
  can't be laid out. A malformed register key's finding now follows the serial
  ones rather than preceding them.
- The RTU adapters: `FrameTunnel::stream` (was `ModbusRtuStream::new`),
  `RtuSettings::options` (was `ModbusRtuOptions::from_settings`),
  `Catalogue::rtu_options` and `Catalogue::tunnel_stream`.
