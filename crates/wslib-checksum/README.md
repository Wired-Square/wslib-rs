# wslib-checksum

Checksum algorithms, and an engine that answers which checksum configuration
explains a set of frames off a link, and says why when none does.

```rust
use wslib_checksum::{ChecksumAlgorithm, crc32, calculate_checksum_simple};

assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
let crc = calculate_checksum_simple(ChecksumAlgorithm::Crc16Modbus, &[0x01, 0x03, 0x00, 0x00, 0x00, 0x01]);
```

- **Algorithms**: XOR, Sum8, seven CRC-8s, CRC-16 Modbus and CCITT, the CRC-8
  and CRC-16 parameterised forms, and CRC-32.
- **Detection**: `detect_checksum` sweeps a candidate space built from
  per-column statistics, scores and ranks the survivors, and folds ranges that
  say the same thing.
- **Solving**: `solve_additive` and `solve_crc` compute the answer from the
  samples. For payloads of one length a CRC's `init` and `xorOut` cannot be
  told apart, so `CrcParameters::alternatives` lists the other pairs that fit;
  none of them is the answer on its own.

Offsets are end-relative: a negative index counts from the end, so frames of
different lengths on one link line up. Explanations are `ChecksumNote { code,
values }` for the caller to translate; `ALL_NOTES` lists every code and its
values, for a locale file to be checked against.

## Features

- `ts`: `ts_rs::TS` (ts-rs 12) on every serde type. Nothing here writes a
  `.ts` file.
