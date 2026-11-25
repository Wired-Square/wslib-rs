# wslib-isotp

ISO-TP (ISO 15765-2) as a sans-IO codec. It turns a message into frames,
turns frames back into a message, and says which flow control to answer
with. The caller moves the frames and keeps the timers: N_Bs, N_Cr and STmin
pacing. `docs/iso-tp.md` lists the wire facts it relies on and the test that
pins each.

- A `Framing` sets normal, extended or mixed addressing (one leading byte,
  sent and expected bytes set apart), classic or CAN FD frames with a
  transmit data length of 8 to 64, optional padding, and the longest
  message.
- The default framing, which `Segmenter::new`, `Reassembler::new` and
  `LinkConfig::new` use, is normal addressing on classic frames, sent
  unpadded and read padded or not, at most 4095 bytes a message. A first
  frame announcing a 32-bit length is ignored under it.
- CAN FD single frames over 7 bytes escape their length, and CAN FD frames
  over 8 bytes are always padded to a valid length.
- With `max_message` over 4095, a message over 4095 bytes goes in a first
  frame with a 32-bit length, and a first frame announcing more than
  `max_message` is answered with an overflow.
- Any single or first frame, valid or not, aborts the message in progress,
  and a valid one starts the next. A consecutive frame out of sequence or
  too short aborts it too. A single frame shorter than its length, a first
  frame under 8 bytes, and a consecutive frame with no message open are
  ignored.
- `Step::Accepted` is a consecutive frame taken mid-message: restart N_Cr.
  `Step::Nothing` means the frame was ignored or aborted the message.

```rust
use wslib_isotp::{Outcome, Reassembler, Segmenter, StMin, Step};

let message = b"twelve bytes";
let segmenter = Segmenter::new(message).expect("1 to 4095 bytes");
let mut reassembler = Reassembler::new(0, StMin(0));

let mut outcome = reassembler.on_frame(&segmenter.first());
assert!(matches!(outcome.step, Step::SendFlowControl(_)));
for frame in segmenter {
    outcome = reassembler.on_frame(&frame);
}
assert_eq!(outcome, Outcome { aborted: None, step: Step::Message(message.to_vec()) });
```

`PciKind::classify` sorts a received frame: flow control goes to the sender,
the rest to the `Reassembler`. `FlowControl::parse` tells a frame to ignore
(`NotFlowControl`) from a reserved status that fails the send
(`ReservedStatus`). A `Reassembler` with a block size asks for a flow control
after each block but the last. With a framing, `Framing::classify`,
`encode_flow_control` and `parse_flow_control` do the same through the
address byte.

## Watching a conversation

`IsoTpTap` reassembles both sides of one conversation from the frames a
passive listener sees, `TimedFrame`s fed in bus order whatever their id. A
frame's `at_us` is microseconds from any fixed origin, and the tap's times
are on that scale, each in a `_us` field. The tap keeps no clock: N_Cr is
judged from frame times, so a capture replayed gives
what the live bus gave. It yields `TapEvent`s: each `TapMessage` with its
side, frame count, first and last frame times and the flow controls it drew
(the first 64 kept, all counted); and each `TapNotice`, a dropped message
(out of sequence, truncated, superseded, timed out, overflowed, too many
waits, a reserved flow status, a first frame over the cap), a wait, or a
resynchronisation after frames it could not place.

- A message times out after N_Cr with no sender frame and no flow control it
  was waiting for (after its first frame or at the end of a block). A flow
  control arriving when none is due restarts nothing and drops nothing, as a
  sender ignores it. A frame stamped earlier never moves a message's timer or
  last frame time back.
- One wait past `TapConfig::wait_limit` (10 by default) drops the message.
- A frame on the conversation's id with another address byte is ignored as
  a frame on another id is. One id both ways works when the address bytes
  differ; `IsoTpTap::new` refuses a config whose sides cannot be told apart
  (`IndistinctSides`).

`detect` takes a window of frames and says which ids carry ISO-TP, with the
counts by frame kind, the length and sequence faults, and the address byte it
infers, and which pairs of ids talk. An id is ISO-TP only once a first frame
on it, or on its partner, was answered by a flow control within the window
and finished by consecutive frames. An id carrying only single frames never
is: its first byte cannot be told from a signal's.

- A first frame is open to answers for the window from its own time; only a
  wait from a candidate, new or not, or its first continue-to-send, extends
  it. While several first frames are open, a flow control is a candidate
  answer to each, at most 4 ids a first frame.
- A sender's answering id is settled across all its completed messages: an
  id with non-ISO-TP frames loses, then the id that is a candidate for the
  most of them wins, provided it is a candidate for more than half or no
  rival is a candidate for more than one. A tie goes to the id with fewer
  flow controls that answered no open first frame at all, so a periodic
  look-alike, which also sends between exchanges, loses. Where nothing
  separates two ids, neither is paired and the messages count as
  `ambiguous`.
- Each id is read with normal addressing and, if its frames lead with at
  most `MAX_ADDRESS_BYTES` (8) distinct bytes, with that byte as an address,
  one entry per byte; it keeps the reading under which more exchanges
  complete, normal on a tie. A tester id addressing several targets gives
  one entry, and one pair, per target.
- It cannot call a single-frame-only id ISO-TP, separate two ECUs answering
  one functional request at the same time, tell apart two ids that both send
  a flow control inside every window and never outside one, pair more than
  the majority tester when two testers take turns on one ECU, find an
  addressed tester with more than 8 targets on one id, or find an exchange
  whose first flow control comes after the window.

## Features

None is on by default. The codec, the tap and detection need only thiserror.

- `serde`: serde derives on the framing, flow control, tap and detection
  types. Fields and enum variants are camelCase, and an enum whose variants
  carry data is tagged with `kind`: `{"kind":"fd","length":64}`. A
  `TapNotice`'s kind is its `notice` field.
- `ts`: ts-rs declarations for those types, each named `IsoTp…`. Implies
  `serde`.
- `testing`: `testing::Responder`, a clockless simulated peer that answers
  each request with `answer(&request)`'s messages, sends flow control (block
  size, STmin, and waits if asked), and honours the requester's flow control,
  reporting STmin as a delay per frame. `testing::Conversation` runs a tester
  against it and stamps both sides' frames for golden fixtures.

- `link`: `IsoTpLink`, an async link over a wslib-can adapter, on tokio.
  - `IsoTpLink::new` takes a `CanWriter`, and the caller feeds it every
    `CanRead`, so the adapter can carry other traffic. The task that feeds
    the link must never await its `send`, or the send's flow control is
    never fed.
  - `IsoTpLink::over` owns a `CanTask` and feeds the link itself, so any task
    may send. It resets the link on each disconnect. When the task ends, so
    does the link: sends fail and `Messages::recv` returns `None`. Dropping
    the last handle stops the task.
  - `close` ends a link however it is fed.
  - A link keeps only received data frames on its bus, rx id and id width,
    and CAN FD ones only when its framing is CAN FD. A frame fed to a full
    queue is dropped and counted. `LinkConfig::framing` sets its framing, and
    `brs` bit rate switching on the CAN FD frames it sends.
  - A send fails, and the peer gets no message, when no flow control comes
    within N_Bs, the receiver overflows, an 11th WAIT comes in a row, a flow
    status is reserved, the adapter refuses a frame or has no queue room
    within N_As, or the link is reset or closed. Ten WAITs then a CTS
    succeed.
  - A reset or close cuts short a wait for queue room or for STmin.
  - A frame the adapter took but didn't confirm within N_As fails the send
    as `Unconfirmed`. That frame may still reach the bus, as may a frame
    handed over by a send that is dropped. One N_As covers both the wait for
    queue room and the wait for confirmation.
  - A flow control reaches a send only while it waits for one and before
    N_Bs runs out, so a late CTS never starts the next message or revives a
    send.
  - Consecutive frames go at least STmin after the previous frame's send
    resolved, never in a burst to catch up. On Windows a multi-frame send
    holds a 1 ms multimedia timer period until it ends or is dropped.
  - The receive side answers a first frame and each block with a flow
    control, even while a send is under way. It aborts a message when N_Cr
    runs out, and a consecutive frame arriving at or after that deadline is
    a stray.
  - `Messages` holds 64 complete messages. One completed with it full is
    dropped and counted.
  - `stats()` reads the counters without blocking, including sends dropped
    before they finished.

```rust,ignore
use wslib_isotp::{IsoTpLink, LinkConfig};

let (link, mut messages) = IsoTpLink::over(can_task, LinkConfig::new(0, tx_id, rx_id));
link.send(b"request").await?;
let reply = messages.recv().await;
```

```toml
wslib-isotp = { version = "0.3", registry = "wired-square", features = ["link"] }
```
