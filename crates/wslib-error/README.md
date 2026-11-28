# wslib-error

An error and its causes as one line, with no dependency.

A wslib error displays only its own layer and keeps its cause behind
`source()`. Whoever shows an error to a person, in a log, a terminal or a
response, wraps it in `Chain`:

```rust
use std::error::Error;

use wslib_error::Chain;

fn show(error: &(dyn Error + 'static)) {
    eprintln!("error: {}", Chain::new(error));
}
```

For a flash that failed because a port did not open, that prints
`error: the flash failed: the port did not open: permission denied`.

Some errors from other crates write their cause in their own `Display` and
return it from `source()` too. `Chain` leaves a cause out when the line so
far is that cause, or ends with `: ` and it, so those read once. A cause
that says nothing is left out as well.

`Chain` is `Display`, so it goes wherever one is taken: a `format!`, a
`tracing` field, or wslib-http-error's `ApiError::internal`.

```toml
wslib-error = { version = "0.1", registry = "wired-square" }
```
