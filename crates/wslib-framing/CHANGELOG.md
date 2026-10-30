# Changelog

## 0.1.0

- `Framed`: a decoded frame and where in the input it ended.
- `cobs`: COBS both ways, `0x00`-delimited: `stuff` and `decode` for one
  block, `encode` and `encode_into` with both delimiters, and `CobsDecoder`,
  which can cap a frame and counts the blocks it drops as malformed.
  `max_stuffed_len` is the longest block a payload can stuff to, for the cap.
