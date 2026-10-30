# wslib-framing

Framing codecs for byte streams, with no I/O and no dependency beyond
thiserror. Each decoder returns `Framed`: a frame's bytes and where in the
input it ended.

- `cobs`: COBS (Consistent Overhead Byte Stuffing), a payload rewritten to
  hold no `0x00` so `0x00` can mark where each frame ends.
  [`docs/cobs.md`](docs/cobs.md) specifies it.

```rust
use wslib_framing::cobs::{CobsDecoder, encode};

let wire = encode(&[0x11, 0x00, 0x22]); // 00 02 11 02 22 00
let frames = CobsDecoder::new().feed(&wire);
assert_eq!(frames[0].bytes, [0x11, 0x00, 0x22]);
```

A decoder has `feed`, a `flush` that ends a stream but not the decoder,
`bytes_fed`, and each frame's `end_offset`. `CobsDecoder` drops and counts a
malformed block, and `with_max_frame_len` caps a frame.

```toml
wslib-framing = { version = "0.1", registry = "wired-square" }
```
