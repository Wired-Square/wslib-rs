# Changelog

## 0.1.1

- serde's floor is 1.0.228.

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
