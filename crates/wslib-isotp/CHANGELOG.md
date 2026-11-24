# Changelog

## 0.2.1

- `Framing` sets the addressing (`Addressing::Normal`, `Extended` or `Mixed`,
  with the sent and expected byte apart), the `FrameFormat` (classic, or
  CAN FD at an `FdLength` of 8 to 64), padding, and `max_message`. Its
  default keeps 0.1's behaviour. `Segmenter::with_framing` and
  `Reassembler::with_framing` take one; `new` uses the default.
- CAN FD single frames over 7 bytes escape their length, and are read at any
  length their frame carries. Frames over 8 bytes are padded to a valid
  CAN FD length, with `Framing::FD_FILL` when no pad byte is set. A
  consecutive frame longer than its first frame is ignored.
- With `max_message` over 4095, messages over 4095 bytes take a first frame
  with a 32-bit length, and a first frame announcing more than
  `max_message` is answered with an overflow. No buffer is sized from an
  announced length beyond 4095 bytes.
- `Framing::classify`, `encode_flow_control` and `parse_flow_control` work
  through the address byte. `LengthError::TooLong` names the framing's limit.
- `link`: `LinkConfig::framing` and `brs`. A CAN FD link sends CAN FD frames
  and reads classic and CAN FD ones.
- `IsoTpTap` reassembles both sides of a conversation it watches, from
  `TimedFrame`s stamped in microseconds (`at_us`), with no clock of its own.
  It yields `TapMessage`s with their side, frame count, `_us` times and flow
  controls (64 kept, all counted), and `TapNotice`s for a dropped message, a
  wait, or a resynchronisation. A message times out after N_Cr with no
  sender frame and no flow control it was due, and one wait past
  `TapConfig::wait_limit` drops it. A flow control that is not due is
  recorded, but restarts nothing, drops nothing and counts no wait, as a
  sender ignores it. A frame stamped earlier never moves a message's timer
  or last frame time back. Frames on the conversation's ids with
  another address byte are not its own; `IsoTpTap::new` refuses, with
  `IndistinctSides`, a config whose sides cannot be told apart.
- `detect` reports, for a window of frames, each id's `IdEvidence` and the
  `Pair`s that completed a multi-frame exchange. An id carrying only single
  frames is never called ISO-TP. A flow control is a candidate answer to
  every open first frame in its window, which runs from the first frame and
  only a candidate's wait or first continue-to-send extends. Each sender's
  answering id is settled across its completed messages: the candidate in
  the most of them, a tie going to the one with fewer flow controls that
  answered no open first frame at all, when it is in more than half or no
  rival is in more than one; what cannot be settled, including a tie on
  both, is `ambiguous`. A flow control frame is credited once however
  many messages it settles. Each id is read with normal addressing and, with
  at most `MAX_ADDRESS_BYTES` leading bytes, addressed per byte, and keeps
  the reading under which more exchanges complete.
- `testing`: `Responder`, a clockless simulated peer that answers each
  request through `answer`, and `Conversation`, which runs a tester against
  it and stamps both sides' frames.
- `serde`: serde derives on the framing, flow control, tap and detection
  types. Fields and enum variants are camelCase.
- `ts`: their ts-rs declarations, named `IsoTp…`, with every `u64` declared
  `number`, as serde_json writes it.
- `docs/iso-tp.md` lists the wire facts the crate relies on, each pinned by
  a test.

## 0.2.0

- On wslib-can 0.2, whose `SendRefused` and `WriteFailed` `SendFailed`
  carries.
- `SendFailed::Io` is `SendFailed::Write`, carrying the adapter's
  `WriteFailed` in place of an `io::Error`, and `SendFailures::io` is
  `write`.
- `SendFailed::Refused` and `Write` name only their own layer, and return the
  `SendRefused` or `WriteFailed` from `source()`.

## 0.1.0

- A sans-IO ISO-TP (ISO 15765-2) codec for normal addressing on classic
  8-byte CAN frames, up to `MAX_MESSAGE` (4095) bytes a message.
- `Segmenter` cuts a message into unpadded frames. `LengthError` refuses an
  empty message or one over 4095 bytes.
- `Reassembler` turns frames, padded or not, into an `Outcome`: the message
  it aborted, if any, and the next `Step`. It ignores a first frame
  announcing fewer than 8 bytes.
- A `Step` is a message, a flow control to send, `Accepted` for a
  consecutive frame mid-message (restart N_Cr), or `Nothing` for a frame
  ignored or aborting. `Abort` says why a message was dropped: a consecutive
  frame out of sequence or truncated, or any single or first frame, valid
  or not, which a valid one follows by starting the next message.
- `FlowControl`, `FlowStatus` and `StMin` encode and parse flow controls.
  `FlowControlError` tells a frame to ignore from a reserved status. `StMin`
  decodes a reserved value as 127 ms and rounds a `Duration` up.
- `PciKind::classify` gives a frame's kind, to route flow control to the
  sender and the rest to the reassembler.
- `link`: `IsoTpLink`, an async link over a wslib-can adapter, with received
  messages on `Messages`. `new` takes a `CanWriter` and the caller's reads,
  and must not be sent on from the task that feeds it. `over` owns a
  `CanTask` and ends when that task does.
- `LinkConfig` defaults N_As, N_Bs and N_Cr to 1 s, block size to 0, STmin
  to 1 ms, the wait limit to 10 and the receive queue to 1024 frames.
- `send` fails with `SendFailed`. `AdapterTimeout` means the adapter's queue
  had no room within N_As. `Unconfirmed` means the adapter took a frame but
  didn't confirm it within N_As, so it may still reach the bus.
- `reset` drops both sides, and `close` ends the link for every handle.
  Either fails the send under way at once, handing the adapter no more
  frames. A frame the adapter already holds is waited for, and a send whose
  last frame it holds ends as that frame does.
- The receive side aborts a message when N_Cr runs out, and a consecutive
  frame at or after the deadline is a stray. A send ignores a flow control
  arriving at or after N_Bs.
- `stats` returns `LinkStats`, with `SendFailures` by kind, including
  unconfirmed and cancelled sends.
- On Windows a multi-frame send holds `timeBeginPeriod(1)` through
  windows-sys.
