# wslib-bits

Bits and bytes of a payload: a field cut by bit position, byte order and sign,
16-bit word swaps, hex byte strings, Modbus register readings, and value
formatting. No schema: the caller says where a field is.

```rust
use wslib_bits::{BitOrder, Endianness, extract_field};

let order = BitOrder::Registers { endianness: Endianness::Big, word_order: Some(Endianness::Little) };
// 0x0001_86A0 stored low word first.
assert_eq!(extract_field(&[0x86, 0xA0, 0x00, 0x01], 0, 32, order, false), 100_000.0);
```

A coil bank has one order, eight to a byte and least significant bit first;
`BitOrder::Coils` reads it so, and never swaps words.

## Features

- `decimal`: `scale`, which scales in `rust_decimal` so that `3374 × 0.1` is
  `337.4` and not `337.40000000000003`, and `ScaledField::decode`.
  `format_decimal` is deprecated: wslib-quantity's
  `format_decimal(value, Precision::Exact)` replaces it.
- `display`: `DisplayHint`, a signal's `display` value, which needs
  `serde_json`.
- `ts`: `ts_rs::TS` (ts-rs 12) on every serde type. `groups::Group` exports as
  `GroupedValue`. Nothing here writes a `.ts` file.
