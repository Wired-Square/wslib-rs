# FrameLink

**Version:** protocol 4, rule format 2, BLE manufacturer data schema 1.

FrameLink is how a host talks to a device that bridges CAN, CAN FD, RS-485,
RS-232 and LIN: it reads and writes the device's signals, streams its
interfaces' frames, and loads the rules the device runs on its own. It runs
over a byte stream, TCP on port 120 by default.

This crate implements the wire and every payload, with no I/O. What it
implements is [§9](#9-what-this-crate-implements).

---

## 1. Frame

```
00  COBS( header(5) payload(length) )  00
```

The header and payload are COBS-stuffed (wslib-framing's `docs/cobs.md`) so
they hold no `0x00`, and a `0x00` on each side marks the frame. There is no
CRC: the transport carries integrity.

The header, little-endian:

| offset | size | field | notes |
|---|---|---|---|
| 0 | 1 | `version_flags` | bits 7–4 the protocol version, 4; bits 3–0 the flags |
| 1 | 1 | `type` | the message type, [§3](#3-message-types) |
| 2 | 1 | `seq` | chosen by the requester |
| 3 | 2 | `length` | u16, the payload's length |

**A receiver unstuffs before it reads the version.** A block that fails to
unstuff is a COBS error, whatever its first byte; only a block that unstuffs
is checked for version 4, and any other version is refused. Then a block
shorter than 5 bytes is refused, as is one whose `length` disagrees with the
bytes after the header.

| Flag | Value | Meaning |
|---|---|---|
| `ACK_REQ` | `0x01` | the sender wants an ACK |
| `RESPONSE` | `0x02` | this frame answers a request |
| `ERROR` | `0x04` | |

---

## 2. Replies

A reply sets `RESPONSE` and **echoes its request's `seq`**, so a host matches
ACK, NACK and typed replies alike on the flag and `seq`, and an unsolicited
frame is never taken for a reply. An ACK's payload is empty. A NACK's starts
with the error code:

| Code | Name | | Code | Name |
|---|---|---|---|---|
| `0x00` | none | | `0x07` | persistence failure |
| `0x01` | unknown message type | | `0x08` | CRC failure |
| `0x02` | invalid payload | | `0x09` | write locked |
| `0x03` | resource full | | `0x0A` | read-only |
| `0x04` | not found | | `0x0B` | out of range |
| `0x05` | invalid interface | | `0x0C` | protocol version mismatch |
| `0x06` | invalid state | | | |

---

## 3. Message types

| Range | Messages |
|---|---|
| `0x01`–`0x07` | `PING`, `PONG`, `CAPABILITIES_REQ`, `CAPABILITIES_RESP`, `ACK`, `NACK`, `RESET` |
| `0x10`–`0x14` | `FRAME_RX`, `FRAME_TX`, `STREAM_START`, `STREAM_STOP`, `FRAME_TX_BATCH` |
| `0x20`–`0x22` | `IFACE_CONFIG_SET`, `_GET`, `_RESP` |
| `0x30`–`0x33` | `FRAME_DEF_ADD`, `_REMOVE`, `_LIST`, `_RESP` |
| `0x40`–`0x44` | `XFORM_ADD`, `_REMOVE`, `_LIST`, `_RESP`, `_ENABLE` |
| `0x48`–`0x4C` | `GEN_ADD`, `_REMOVE`, `_LIST`, `_RESP`, `_ENABLE` |
| `0x50`–`0x52` | `PERSIST_SAVE`, `_LOAD`, `_CLEAR` |
| `0x54`–`0x56` | `BOARD_DEF_UPLOAD`, `_DOWNLOAD`, `_CLEAR` |
| `0x57`–`0x59` | `FILE_BEGIN`, `FILE_DATA`, `FILE_END` |
| `0x5A`–`0x5C` | `USER_SIGNAL_ADD`, `_REMOVE`, `DSIG_SET_INTERVAL` |
| `0x60`–`0x64` | `DSIG_LIST`, `_LIST_RESP`, `_READ`, `_READ_RESP`, `_WRITE` |
| `0x68`–`0x6B` | `WRITE_CHALLENGE`, `_CHALLENGE_RESP`, `WRITE_UNLOCK`, `WRITE_LOCK` |
| `0x70`–`0x74` | `BRIDGE_ADD`, `_REMOVE`, `_LIST`, `_RESP`, `_ENABLE` |
| `0x78`–`0x7F` | `COUNTER_ADD`, `_REMOVE`, `_LIST`, `_RESP`, `EVENT_RULE_ADD`, `_REMOVE`, `_LIST`, `_RESP` |
| `0x80`–`0x84` | `FSM_ADD`, `_REMOVE`, `_LIST`, `_RESP`, `_ENABLE` |
| `0x85`–`0x89` | retired; never reallocated |
| `0x8A`–`0x8E` | reserved for sequences |
| `0x90`–`0x94` | `TX_GROUP_ADD`, `_REMOVE`, `_LIST`, `_RESP`, `TEMPLATE_SET` |

Every ENABLE is `id(u16) enabled(u8)`, every REMOVE `id(u16)`, and every
LIST empty, answered by one RESP per entry. All integers are little-endian.

---

## 4. Capabilities

`CAPABILITIES_RESP` describes structure and static facts, never signals:

```
num_device_meta(u8)  meta...
num_interfaces(u8)   [ index(u8) type(u8) num_meta(u8) meta... ]...
num_peripherals(u8)  [ index(u8) kind(u8) num_meta(u8) meta... ]...
```

A meta entry is `id(u8) quantity(u8) len(u8) value(len)`. The value is an
integer when `len` is 1, 2 or 4 and the quantity is not STRING; otherwise it
is bytes, as is `SUPPORTED_FUNCTIONS` (`0x0D`), a list of function ids.
`types::META_*` lists the ids; `MAX_FILE_CHUNK` (`0x20`) absent means the
device has no file transfer, and `RULE_FORMAT` (`0x16`) is 2.

Interface types: CAN `0x01`, CAN FD `0x02`, RS-485 `0x03`, RS-232 `0x04`,
LIN `0x05`. Peripheral kinds say dataflow only: sensor `0x01`, actuator
`0x02`, controller `0x03`, link `0x04`.

---

## 5. Device signals

A signal is identified by `(target_type, target_index, role, quantity,
aspect, channel)` and its WRITABLE flag; at most one writable and one
read-only signal share a tuple. `signal_id` is a handle the device renumbers
on reset, never identity. Ids `0xFF00`–`0xFFFE` are the device's own, owned by
its capabilities; lower ids are user signals, the outputs of rules.

`DSIG_LIST` is `offset(u16)`. `DSIG_LIST_RESP` is `total(u16) offset(u16)
count(u16)` and `count` 35-byte entries:

| offset | size | field |
|---|---|---|
| 0 | 2 | `signal_id` |
| 2 | 1 | `target_type`: interface 0, peripheral 1, device 2 |
| 3 | 1 | `target_index` |
| 4 | 1 | `role` |
| 5 | 1 | `quantity`; bit 7 makes it a rate per second |
| 6 | 1 | `aspect` |
| 7 | 1 | `channel`; `0xFF` is the whole target |
| 8 | 1 | flags: bit 0 writable, 1 persistable, 2 rule destination, 3 frame destination |
| 9 | 1 | `value_type`: unsigned 0, signed 1, float 2, bool 3, array 4 |
| 10 | 1 | `value_len` |
| 11 | 4 | `scale`, f32 |
| 15 | 4 | `offset`, f32: physical = raw × scale + offset |
| 19 | 8 | `min_raw`, i64 |
| 27 | 8 | `max_raw`, i64; equal bounds mean unbounded |

`DSIG_READ` is `signal_id(u16)`; `DSIG_READ_RESP` and `DSIG_WRITE` are
`signal_id(u16) value_len(u8) value(value_len)`, 1 to 8 bytes. A write is
sent in the fewest of 1, 2, 4 or 8 bytes that hold it. `DSIG_SET_INTERVAL` is
`signal_id(u16) interval(u16)`.

Writes are locked until unlocked: `WRITE_CHALLENGE` is answered by
`WRITE_CHALLENGE_RESP`, `nonce(u32)`, and `WRITE_UNLOCK` echoes the nonce. A
locked write is NACKed `0x09`.

The vocabularies of roles, quantities and aspects are closed, and
`types::*_slug` names each for the board TOML. A key's slug is
`<target>.<index>.<role>.<quantity>[.<aspect>][.ch<N>]`, the quantity suffixed
`_per_s` for a rate, the aspect omitted when default and the channel when
`0xFF`: `peripheral.0.setpoint.colour_rgb.ch5`.

---

## 6. Streams

`STREAM_START` is `iface(u8) config_len(u8) config`; an empty config takes the
device's defaults. CAN's is `count(u8)` and `can_id(u32) can_mask(u32)
flags(u8)` filters, bit 0 matching extended ids. RS-485's is `mode(u8)
param(u16)`, mode 0 idle line and 1 fixed chunk. `STREAM_STOP` is `iface(u8)`.

`FRAME_RX` is `count(u16)` and that many entries:

```
timestamp_us(u64) iface(u8) meta_len(u8) meta data_len(u16) data
```

The metadata is read by its length: 6 is CAN, `can_id(u32) dlc(u8)
flags(u8)`; 1 is RS-485, `framing_mode(u8)`. `FRAME_TX` is one entry without
the count, its timestamp 0. `FRAME_TX_BATCH` is `count(u16)` and entries
without timestamps.

---

## 7. Rules

**Frame definitions** say where signals sit in a frame:

```
frame_def_id(u16) interface_type(u8) header num_signals(u8)
[ signal_id(u16) start_bit(u16) bit_length(u16) byte_order(u8) value_type(u8)
  scale(f32) offset(f32) ]...
```

The header is `can_id(u32) dlc(u8) flags(u8)` for CAN and CAN FD, flag `0x80`
matching any id, and `framing_mode(u8)` for the serial types. Byte order 0 is
little-endian, contiguous bits from `start_bit`; 1 is Motorola, the MSB at
`start_bit` and bits running down each byte from 7 to 0, then on to the next
byte's bit 7. Frame definition `0xFFFF` is the device's signals and `0xFFFE`
the user's.

**Transformers** map signals from one frame definition into another, then
run functions:

```
transformer_id(u16) source_fd(u16) source_iface(u8) dest_fd(u16) dest_iface(u8)
enabled(u8) num_mappings(u8) mappings num_functions(u8) functions
```

A mapping is `source(u16) dest(u16) type(u8)` and its parameters: direct `0x00`
and invert `0x02` none, scale `0x01` `scale(f32) offset(f32)`, mask `0x03`
`mask(u32)`. A function is `id(u8) source(u16) dest(u16)` and its parameters:
palette `0x10` `start(u16) max(u16)`, clamp `0x11` `min(u32) max(u32)`,
threshold `0x12` `threshold(u32) above(u32) below(u32)`, gate `0x13`
`guard(u16) op(u8) pad(u8) value(u32) fail(u32)`, the op one of `!=` `==` `>`
`<` `>=` `<=` from 0. A response without the function block has no
functions.

**Generators** send frames of their own:

```
generator_id(u16) frame_def_id(u16) iface(u8) period_ms(u32) trigger(u8)
enabled(u8) num_mappings(u8) mappings
```

with a transformer's mappings, triggered periodically 0, on change 1 or once
2.

**Bridges** forward frames between interfaces:

```
bridge_id(u16) source_iface(u8) dest_iface(u8) interface_type(u8) enabled(u8)
default_action(u8) num_filters(u8) [ type(u8) ide(u8) a(u32) b(u32) ]...
```

Default action 0 passes a frame no filter matches, so the filters list what
to drop; 1 blocks it, so they list what to pass. A mask filter (0) matches
`(id & b) == (a & b)`, a range (1) `a <= id <= b`; IDE 0 is either, 1
standard only, 2 extended only. `a` and `b` carry CAN ids; bits above 29 are
reserved.

**Counters** are `counter_id(u16) modulo(u16) init(u16)`, and their RESP adds
`value(u16)`. `PERSIST_SAVE`, `_LOAD` and `_CLEAR` are empty and need the
write unlock; `PERSIST_LOAD` replaces the live rules with the stored ones.

---

## 8. Transfers, CAN ids and BLE

**Files.** `FILE_BEGIN` is `target(u8) size(u32) crc32(u32)`, the CRC-32
(ISO-HDLC, zlib's) of the whole file, which the device checks at commit;
targets belong to the product. `FILE_DATA` is `offset(u32)` and at most
`MAX_FILE_CHUNK` bytes, never none. `FILE_END` is 1 to commit, 0 to abort.

**Board definitions.** `BOARD_DEF_UPLOAD` is `offset(u32) total(u32)
len(u16) data`; `BOARD_DEF_DOWNLOAD` asks `offset(u32) max_len(u16)` and is
answered in the upload's shape.

**CAN ids.** Over CAN, an id is bit 28 set for host-to-device, the device id
in bits 8–27 and a slot in bits 0–7; ISO-TP uses slot `0x40` towards the
device and `0x41` back.

**BLE.** A device advertises six bytes of manufacturer data under company
`0xFFFF`: `schema(u8) capabilities(u16) hw_rev(u8) fw_major(u8) fw_minor(u8)`.
Capability bits are Wi-Fi provisioning 0, SMP 1, FrameLink over BLE 2,
capabilities 3 and pairing required 4. The hardware revision's high nibble is
the major. A scanner refuses a schema newer than it knows and ignores bits it
doesn't.

---

## 9. What this crate implements

| | Item |
|---|---|
| Frames | `frame::build_frame`, `parse_frame` |
| Payloads | a builder and a parser per message, in the module of its range |
| Vocabularies | `types`, with names, slugs, `INTERFACE_NAMES` and `frame_def::VALUE_TYPE_NAMES` |
| Signal identity | `dsig::SignalKey`, `format_signal_key`, `parse_signal_key`, `semantic_signal_name` |
| BLE | `manufacturer_data` |
| Versions | `PROTOCOL_VERSION`, `RULE_FORMAT`, `SCHEMA_VERSION_MAX` |

**Version 4 only.** A frame of any other version is refused; there is no
fallback.

**Lenient lists.** `DSIG_LIST_RESP` stops at the last whole entry when the
count promises more. Every other truncated payload is refused.
