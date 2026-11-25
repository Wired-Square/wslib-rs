# wslib-uds

UDS (ISO 14229-1) for a tester and for a capture, sans-IO: it takes and returns
message bytes over whatever transport the caller runs (ISO-TP, DoIP), and the
caller supplies the time. No feature is needed to decode, encode, classify or
pair; `write` adds the client's path for requests that change the ECU.

```rust
use wslib_uds::{Request, Response, Safety, identify};

let request = Request::decode(&[0x22, 0xF1, 0x90])?;
assert_eq!(request.safety(), Safety::ReadOnly);
assert_eq!(identify(&[0x31, 0x01, 0x02, 0x03]).unwrap().to_string(),
           "RoutineControl routine 0x0203 start");
let response = Response::decode(&[0x7F, 0x22, 0x31])?; // requestOutOfRange
```

A client holds the session, the unlocked security level and the P2, P2* and
S3 timers. It hands back bytes to send and turns received bytes into events;
`poll` reports a timeout, S3's expiry or a due tester present, and
`next_deadline` says when to poll next. Nothing caps a server's
responsePending answers; `abandon` gives up on the outstanding request. A
session change or ECU reset that goes unanswered locks security and leaves
`session()` `None`, with no keep-alive, until an answer says which session it
is or S3 returns the server to the default one; so does a suppressed
SecurityAccess that draws no refusal, for security. No timing panics: a wait
too long for an `Instant` to hold never ends, and a keep-alive interval of
zero sends none.

```rust
use std::time::Instant;
use wslib_uds::{Client, Event, NonEmpty, ReadOnly, Request, Timing};

let mut client = Client::new(Timing::default());
let read = ReadOnly::new(Request::ReadDataByIdentifier { dids: NonEmpty::one(0xF190) })?;
link.send(&client.send_read_only(read, Instant::now())?)?;
match client.receive(&link.recv()?, Instant::now()) {
    Event::Positive(response) => println!("{response:?}"),
    Event::Pending { .. } => { /* poll at client.next_deadline() */ }
    other => println!("{other:?}"),
}
```

Without `write`, `send_read_only` is the only way to send, and `ReadOnly::new`
refuses any request that is not `Safety::ReadOnly`. With `write`, a client
built by `Client::up_to(timing, Safety::StateChanging)` sends up to that class
and refuses anything above it; `Client::new` still sends only read-only
requests. The crate docs carry the safety table.

Scans are plans the caller drives: take the next probe, send it, report the
final reply, or `None` for silence.

```rust
use wslib_uds::DidScan;

let mut scan = DidScan::new(0xF180..=0xF19F);
while let Some(probe) = scan.next_probe() {
    let reply = exchange(probe.request())?; // Option<Vec<u8>>
    scan.report(reply.as_deref());
}
for finding in scan.findings() {
    println!("0x{:04X}: {:?}", finding.did, finding.verdict);
}
```

- Codec: services 0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27, 0x28, 0x2E, 0x2F,
  0x31, 0x34, 0x35, 0x36, 0x37, 0x3E and 0x85 typed, any other kept as its
  service id and bytes; negative responses; the suppress-positive-response
  bit apart from the sub-function. A value that would not decode back to
  itself cannot be built: a DTC over 24 bits, an untyped report type that is
  a typed one, an empty DID list or write. `sid::name`, `Nrc::name` and
  `identify` label them.
- `answers(request, response)`: whether a response is the positive or
  negative answer to a request, by service id and the echoed DID, routine or
  sub-function. The client, the tracker and the scans all match this way.
- `Safety::of` and `ReadOnly`, available with no feature. A bare service id
  has its service's class.
- `Tracker` pairs a capture's requests and responses, counting
  responsePending answers and timing each; a keep-alive tester present does
  not disturb a request still owed a response, and a request that suppressed
  its positive response stays open to the timeout for a late refusal. A
  response goes to the newest open request it answers that is owed one, and
  at most `MAX_OPEN_REQUESTS` stay open.
- Scans: `AddressScan` (tester present per candidate id), `ServiceScan` (bare
  service ids: the read-only ones, or with `write` up to a class the caller
  names; it stops if a bare id above read-only is acted on),
  `ReadOnlyServiceScan` (the read-only one, whose probes are already
  `ReadOnly`, like `DidScan`'s, for `send_read_only`), `DidScan`, and
  with `write` `SessionScan`, which skips the programming session unless
  `SessionScan::up_to` is given a destructive ceiling,
  returns to the default session after any probe that may have left it, and
  stops if that return is not answered positively. No scan searches for a
  security key.
- `testing`: `testing::Ecu`, a simulated ECU with DIDs, sessions, one
  security level, DTCs, a routine and responsePending answers, whose
  `answer(&[u8]) -> Vec<Vec<u8>>` drives a transport's responder.
- `isotp`: `orient(frames, timing)`, the UDS conversations in a window of
  wslib-isotp `TimedFrame`s, each with its tester and ECU and the evidence:
  exchanges, negative and responsePending answers, and multi-frame messages
  paced by flow control each way. Single frames alone are enough, which
  ISO-TP detection cannot use. Only a request this crate decodes as a typed
  `Request` (not `Request::Other`) counts towards an exchange; an answer to a
  vendor, KWP, OBD or unmodelled ISO request counts for nothing either way.
  A pair is a `Conversation` only with two exchanges or more, or one paced by
  flow control, and only when every rival on either side, the ECU's messages
  answering nothing, the tester's unanswered requests, frames from either
  that ISO-TP ignores, and exchanges in single frames padded with varying
  bytes are each at most an eighth of its exchanges; when untyped traffic
  does not outnumber the typed; and when neither id is in another such pair
  in the other role. Every other id with an exchange is `Unsettled` with its
  candidates, at most `MAX_PARTNERS` (4): a single exchange, two ECUs
  answering one functional request, two testers whose requests every answer
  could answer, a periodic look-alike answering every request beside a real
  ECU, an ECU that pads with stale bytes. Limits: two periodic ids at about
  the same rate whose frames are a typed request and its answer, uniformly
  padded, cannot be told from a conversation, in step or not; ids read as
  addressed only where `wslib_isotp::detect` reads them so, which needs
  multi-frame exchanges, and mixed addressing reads as extended; a message
  over `MAX_MESSAGE_BYTES` (64 KiB) is not read.
  `Conversation::tap_config(frames)` is the `TapConfig` an `IsoTpTap` reads
  the conversation's messages with, the tester as side A.
- `ts`: TypeScript declarations for the data types, every name prefixed `Uds`.
  64-bit fields are declared `number`, so an address, size or block length
  above 2^53 loses precision in JavaScript.

`docs/uds.md` is the wire as this crate reads it, written from knowledge of
ISO 14229-1:2020 and not checked against the standard's text.
