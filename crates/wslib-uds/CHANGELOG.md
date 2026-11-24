# Changelog

## 0.1.0

- `Request` and `Response`: services 0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27,
  0x28, 0x2E, 0x2F, 0x31, 0x34, 0x35, 0x36, 0x37, 0x3E and 0x85 decoded and
  encoded, any other service kept as its id and bytes; negative responses;
  `SubFunction`, a value of at most 0x7F with the suppress-positive-response
  bit apart, which is recognised for every ISO service with a sub-function;
  `MemoryRange` and `BlockLength`, checked at construction so they always
  encode; several DIDs in one read; and ReadDTCInformation's report types
  0x01, 0x02, 0x04, 0x06 and 0x0A typed. Decoding never panics, and every
  message it accepts re-encodes byte for byte.
- `Dtc`, a DTC or group of DTCs that cannot be built, or deserialised, over
  24 bits.
- `OtherReportType`, the report type of `DtcRequest::Other`, refuses one over
  0x7F and one with its own variant, so that request always decodes back to
  itself.
- `OtherResponseReportType`, the report type of `DtcResponse::Other`, refuses
  0x01, 0x02 and 0x0A.
- `NonEmpty`, a list of at least one item serialised as an ordinary array:
  the DIDs of a ReadDataByIdentifier and the data of a WriteDataByIdentifier
  or InputOutputControlByIdentifier, so none of them can be empty.
- `Request::Other` and `Response::Other` are for services this crate does not
  model; with one it models, they decode as its own variant.
- `sid` names every ISO 14229-1 service id and says which carry a
  sub-function, `Nrc` names every negative response code, and `identify`
  names a request from its leading bytes: its DID, routine, session, memory
  range or DTC group, the last a `Dtc`.
- `answers(request, response)`: whether a response is a request's positive
  answer, by service id and the echoed DID, routine or sub-function, or its
  negative one with the code.
- `Safety` (read-only, state-changing, destructive) of a whole request, a bare
  service id included, with `ReadOnly`, a request checked to be read-only.
  ReadMemoryByAddress is state-changing.
- `Tracker` pairs a capture's requests with their final responses, counting
  responsePending answers and giving each a latency; suppressed, superseded,
  timed-out, malformed and unsolicited messages are reported as such, a
  timeout is judged by each message's own time, and a keep-alive tester
  present does not disturb a request still owed a response.
- A request that suppressed its positive response stays open to the timeout
  however many requests follow, so a late refusal pairs with it; `expire` and
  `finish` return every request they end.
- A response goes to the newest open request it answers that is owed one, or
  failing that to the newest suppressed one.
- At most `MAX_OPEN_REQUESTS` (32) requests stay open; a new one beyond it
  supersedes the oldest, so stamps that run backwards or an unbounded timeout
  cannot grow the tracker.
- `Client`, sans-IO: the session, the security level unlocked, P2 and P2*
  from the session-control response and back to the defaults on any other
  session change, a tester present to hold a non-default session with its
  refusal reported apart, and S3's expiry, counted from when the last request
  resolved. A reply that does not answer the outstanding request changes
  nothing; `abandon` gives up on it. Without `write` it sends only `ReadOnly`
  requests; `write` adds `Client::send`.
- `Client::up_to(timing, ceiling)` with `write`: `send` refuses any request
  above the ceiling with `SendError::AboveCeiling` and sends nothing.
  `Client::new`'s ceiling is read-only.
- A session change or ECU reset that times out or is abandoned locks security
  and leaves `session()` `None` until a session-control or reset answer, or
  S3; no keep-alive goes while it is unknown. An unanswered SecurityAccess
  locks security.
- A suppressed SecurityAccess that draws no refusal locks security.
- responsePending to the keep-alive is `Event::KeepAlivePending`, not a
  refusal, and its final answer may follow up to P2* later: a refusal, or a
  positive answer reported as `Event::KeepAliveAnswered`. A tester present
  sent by the caller after that responsePending ends the wait.
- A keep-alive interval of zero sends no keep-alive.
- No timing value panics: a wait too long for an `Instant` to hold never
  ends, and `Event::Pending`'s deadline is then `None`.
- Scan plans: `AddressScan`; `ServiceScan`, over the read-only bare ids, or
  with `write` `ServiceScan::up_to` a class, stopping if a bare id above
  read-only is acted on; `DidScan`; and with `write` `SessionScan`, which
  returns to the default session after any probe that may have left it and
  stops if that return fails. Each has its verdict function and progress.
- `testing`: `testing::Ecu`, a simulated ECU that refuses in the standard's
  order.
- `ts`: TypeScript declarations for the data types, 64-bit fields declared
  `number` as serde_json writes them.
- Serialised fields and variant values are camelCase.
