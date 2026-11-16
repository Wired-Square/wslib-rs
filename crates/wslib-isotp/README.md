# wslib-isotp

ISO-TP (ISO 15765-2) on classic CAN as a sans-IO codec. It turns a message
into frames, turns frames back into a message, and says which flow control
to answer with. The caller moves the frames and keeps the timers: N_Bs,
N_Cr and STmin pacing.

- Normal addressing, 8-byte frames, at most 4095 bytes a message.
- Frames are sent unpadded and read padded or not.
- No CAN FD, extended or mixed addressing, or 32-bit first-frame length. A
  first frame announcing fewer than 8 bytes is ignored, including the 0 that
  starts a 32-bit length.
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
after each block but the last.

## Features

None is on by default. The codec needs only thiserror.

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
  - A link keeps only received classic data frames on its bus, rx id and id
    width. A frame fed to a full queue is dropped and counted.
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
wslib-isotp = { version = "0.1", registry = "wired-square", features = ["link"] }
```
