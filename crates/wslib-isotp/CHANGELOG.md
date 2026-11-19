# Changelog

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
