# wslib-wiretap-catalogue

WireTAP-format device catalogues: one TOML file describing a device's CAN,
serial and Modbus frames and how to decode them. This crate parses, validates,
decodes, edits and migrates them, frames a serial line by them, and bridges to
Vector DBC. It takes bytes and returns values, with no I/O and no clock; the
Modbus register map, poll schedules and RTU framing are wslib-modbus's.

```rust
use wslib_wiretap_catalogue::{Catalogue, decode, validate};

let catalogue = Catalogue::parse(&text)?;     // shorthands and mirror/copy resolved
let findings = validate::validate(&text);     // field path and message
let frame = catalogue.frame(0x123).unwrap();
for s in decode::decode_frame(&catalogue, frame, &bytes).signals {
    println!("{} = {}", s.name, s.display);
}
```

- `Catalogue::parse` resolves the three frame sections into one model: mirror
  and copy inheritance, header-field masks, mux trees, and the Modbus authoring
  shorthands through `wslib_modbus::ModbusManifest`.
- `validate::validate` returns `{ field, message }` findings. `[meta]` and
  `[frame.modbus]` are `wslib_modbus::validate`'s, so their messages say
  "Catalogue"; the CAN and serial rules are this crate's. The granular
  `validate_*_fields` check one form's fields.
- `decode`: bytes to signal values, 1 to 64 bits signed or unsigned (to 2048
  for text), scaled exactly, in either byte and word order, through enum, hex,
  text and Unix-time formats and nested mux selection.
- `rtu`: a catalogue's `[meta.modbus.function_code.<code>]` tables as
  `wslib_modbus::ModbusRtuOptions` (`Catalogue::rtu_options`), a `[…tunnel]`
  table's stream (`FrameTunnel::stream`, and `Catalogue::tunnel_stream` with the
  catalogue's codes), and `RtuSettings`, what a user picks for a line, with
  `options(Some(&catalogue))` unioning it with a catalogue's codes. `rtu_rules`
  reads just the codes and the name from a catalogue's text.
- `rtu_decode::decode_rtu_message`: a recovered RTU message as signals, named
  `Modbus_{Request|Response}_*`; saved layouts key on those names.
- `serial_framing::SerialFramer` cuts a serial stream into frames by SLIP, a
  delimiter or Modbus RTU, and says where a frame's id sits;
  `framing_detect::detect` says which of them a raw stream uses, and what RTU
  could not frame.
- `edit::apply_edit` and `apply_edits`: in-place edits through `toml_edit`
  that keep comments and formatting; `migrate::migrate` brings a catalogue's
  text to the current schema.
- `mirror::MirrorTracker`: does a mirrored frame still agree with its source?
- `summary::CatalogueSummary`: counts and resolved per-frame rows for a report.
- `dbc`: import a `.dbc` and export one, extended (`SG_MUL_VAL_`) and
  flattened multiplex alike.
- `text`: the source as text: a line diff, `[meta].name` from a file that may
  not parse, and the filename rules.
- `byte_name` and `parse_byte_name`: the name a field cut without a catalogue
  is saved under.

The TOML format is unchanged from the catalogues already written.

The off-by-default `ts` feature derives `ts_rs::TS` on every public serde type,
under the names consumers already import: `Catalogue` as `Catalog`,
`CatalogueSummary` as `CatalogSummary`, `DiffRow` as `DiffLine` and
`RtuSettings` as `ModbusRtuOptions`. `cargo test --features ts` pins the
declarations.

```toml
wslib-wiretap-catalogue = { version = "0.1", registry = "wired-square" }
```
