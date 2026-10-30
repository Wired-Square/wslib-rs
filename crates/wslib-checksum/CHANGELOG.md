# Changelog

## 0.1.1

- serde's floor is 1.0.228.

## 0.1.0

- Eleven named algorithms (XOR, Sum8, seven CRC-8s, CRC-16 Modbus and CCITT),
  parameterised CRC-8 and CRC-16, and `crc32` (IEEE 802.3).
- Frame addressing from either end: `resolve_byte_index`, `extract_checksum`,
  `validate_checksum`.
- `analyse_columns` and `analyse_columns_from`: per-byte-column statistics.
- `detect_checksum`: a candidate space built from column priors, swept,
  scored and ranked, with `ChecksumNote`s explaining the verdict (each value a
  `NoteValue`, a number or a string) and `ALL_NOTES` listing every note it can
  emit.
- `solve_additive`, `solve_crc` and `solve_all`: the checksum computed from
  the samples rather than searched for.
- `diverse_samples` and friends, choosing payloads that differ.
- `ts`: `ts_rs::TS` on every serde type, under ts-rs 12.
