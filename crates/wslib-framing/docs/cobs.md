# COBS (Consistent Overhead Byte Stuffing)

**Source:** S. Cheshire and M. Baker, "Consistent Overhead Byte Stuffing",
IEEE/ACM Transactions on Networking 7(2), 1999.

COBS rewrites a payload so it holds no `0x00`, at a cost of at most one byte in
254, which leaves `0x00` free to mark where each frame ends.

The [`cobs`](../src/cobs.rs) module implements it in both directions. What it
implements is [§4](#4-what-this-crate-implements).

---

## 1. Stuffing

The payload is cut at each `0x00`, and at every run of 254 non-zero bytes. Each
piece goes on the wire as a code byte, then the piece:

| Code | Meaning |
|------|---------|
| `0x01`–`0xFE` | `code − 1` data bytes follow, then a `0x00` that is not sent |
| `0xFF` | 254 data bytes follow, with no implied `0x00` after them |

The implied `0x00` after the last piece is dropped, so an empty payload stuffs
to `01`, `00` to `01 01`, and `11 22 00 33` to `03 11 22 02 33`. A run of 254
non-zero bytes stuffs to `FF`, the 254 bytes, then `01`.

---

## 2. Framing

```
00  <stuffed payload>  00
```

Only the trailing `0x00` is required. A leading one makes a receiver discard
any line noise before the frame as an empty block, so back-to-back `0x00`s frame
nothing and a receiver skips them.

---

## 3. Errors

A block between delimiters is malformed when it is empty, when a code byte is
`0x00`, or when a code promises more bytes than the block holds. COBS has no
length field, checksum or type; anything like that belongs to the payload.

---

## 4. What this crate implements

| | Item |
|---|---|
| One block | `stuff`, and `decode` → `CobsError` when malformed |
| Decode a stream | `CobsDecoder` → `Framed`, with `feed`, `flush`, `bytes_fed`, `abandoned_frames` and `malformed_frames` |
| Encode | `encode_into`, `encode`, both with the leading `0x00` |
| Constants | `DELIMITER` |

**Malformed blocks are dropped.** `CobsDecoder` skips a block that fails to
decode and counts it in `malformed_frames()`. Empty blocks are never released.

**Unbounded by default.** `CobsDecoder::new()` buffers until a `0x00` arrives.
`with_max_frame_len(max)` caps the stuffed block: one that grows past `max`
bytes is dropped, the bytes up to the next `0x00` are discarded with it, and
`abandoned_frames()` counts it once. A `flush` ends one too.

**Offsets.** A frame's `end_offset` counts the bytes fed through its trailing
`0x00`. A `flush` decodes what is buffered, ending at `bytes_fed()`; the decoder
carries on after it, and the count continues.
