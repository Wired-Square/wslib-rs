# wslib-framelink-board

FrameLink board definitions: the TOML naming a board's interfaces,
peripherals and signals for display. Signals are keyed by their
`SignalKey`'s slug, such as `interface.0.config.datarate`, never by the id a
device renumbers. Names shown to a user still derive from a device's live
capabilities; the TOML only overrides them.

```rust
use wslib_framelink_board::load_board_def;
use wslib_framelink_protocol::dsig::parse_signal_key;

let board = load_board_def("wiredflexlink", "esp32c6-v0.0.2").expect("embedded");
let name = board.signal_name(&parse_signal_key("interface.0.config.datarate")?);
```

- `parse_board_def`, `load_board_def` and `embedded_boards`: the boards this
  crate embeds, matched by name and revision. A device's own copy is
  authoritative; `BoardDef::merge_defaults` fills its empty sections.
- `editable`: a definition to edit and write back as TOML, with labels for
  rules not yet on the device.
- `scaffold` and `sync`: a board TOML made from, or brought up to date with,
  a live device, edited in place so hand-written names and comments survive.
- `display` and `resolve`: names for interfaces, frame definitions and
  signals, and names back to a device's ids.
- `discover_leds`: the LEDs among a device's signals, labelled by the board's
  `"LED5 Colour (CAN0)"` suffix. LED colour is BRGB: brightness in the top
  byte.
- `compress`: a board TOML gzipped for storing on a device.

```toml
wslib-framelink-board = { version = "0.3", registry = "wired-square" }
```
