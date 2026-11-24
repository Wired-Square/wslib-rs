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
- `sid` names every ISO 14229-1 service id and says which carry a
  sub-function, `Nrc` names every negative response code, and `identify`
  names a request from its leading bytes: its DID, routine, session or memory
  range.
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
- `Client`, sans-IO: the session, the security level unlocked, P2 and P2*
  from the session-control response and back to the defaults on any other
  session change, a tester present to hold a non-default session with its
  refusal reported apart, and S3's expiry, counted from when the last request
  resolved. A reply that does not answer the outstanding request changes
  nothing; `abandon` gives up on it. Without `write` it sends only `ReadOnly`
  requests; `write` adds `Client::send`.
- Scan plans: `AddressScan`; `ServiceScan`, over the read-only bare ids, or
  with `write` `ServiceScan::up_to` a class, stopping if a bare id above
  read-only is acted on; `DidScan`; and with `write` `SessionScan`, which
  returns to the default session after any probe that may have left it and
  stops if that return fails. Each has its verdict function and progress.
- `testing`: `testing::Ecu`, a simulated ECU that refuses in the standard's
  order.
- `ts`: TypeScript declarations for the data types.
- Serialised fields and variant values are camelCase.
