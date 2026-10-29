# wslib-tcp

A TCP connect for a device link: the endpoint is resolved on every connect, so
a changed DNS record is picked up on the next reconnect, and each address it
resolves to is tried within one budget. Each address gets an equal share of
what is left, so one that silently drops the SYN cannot starve the rest.

```rust
use std::time::Duration;

let endpoint = wslib_tcp::tcp_endpoint("::1", 502); // "[::1]:502"
let stream = wslib_tcp::connect(&endpoint, Duration::from_secs(10)).await?;
```

`TransportError` covers the connect and what a protocol layered on the stream
reports afterwards (a timeout, a close, a malformed reply). Each message is one
short line.
