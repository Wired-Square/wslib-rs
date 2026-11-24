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
is or S3 returns the server to the default one. No timing panics: a wait too
long for an `Instant` to hold never ends.

```rust
use std::time::Instant;
use wslib_uds::{Client, Event, ReadOnly, Request, Timing};

let mut client = Client::new(Timing::default());
let read = ReadOnly::new(Request::ReadDataByIdentifier { dids: vec![0xF190] })?;
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
  bit apart from the sub-function. `sid::name`, `Nrc::name` and `identify`
  label them.
- `answers(request, response)`: whether a response is the positive or
  negative answer to a request, by service id and the echoed DID, routine or
  sub-function. The client, the tracker and the scans all match this way.
- `Safety::of` and `ReadOnly`, available with no feature. A bare service id
  has its service's class.
- `Tracker` pairs a capture's requests and responses, counting
  responsePending answers and timing each; a keep-alive tester present does
  not disturb a request still owed a response, and a request that suppressed
  its positive response stays open to the timeout for a late refusal.
- Scans: `AddressScan` (tester present per candidate id), `ServiceScan` (bare
  service ids: the read-only ones, or with `write` up to a class the caller
  names; it stops if a bare id above read-only is acted on), `DidScan`, and
  with `write` `SessionScan`, which skips the programming session unless asked,
  returns to the default session after any probe that may have left it, and
  stops if that return is not answered positively. No scan searches for a
  security key.
- `testing`: `testing::Ecu`, a simulated ECU with DIDs, sessions, one
  security level, DTCs, a routine and responsePending answers, whose
  `answer(&[u8]) -> Vec<Vec<u8>>` drives a transport's responder.
- `ts`: TypeScript declarations for the data types, every name prefixed `Uds`.
  64-bit fields are declared `number`, so an address, size or block length
  above 2^53 loses precision in JavaScript.

`docs/uds.md` is the wire as this crate reads it, written from knowledge of
ISO 14229-1:2020 and not checked against the standard's text.
