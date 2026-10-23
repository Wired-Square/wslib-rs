# wslib-shutdown

How a service learns it is being stopped: `SIGTERM` and `SIGINT` on unix,
Ctrl-C on Windows, registered when you ask rather than when first polled.

```rust
use tokio_util::sync::CancellationToken;

let stop = CancellationToken::new();
tokio::spawn(wslib_shutdown::cancel_on_stop(stop.clone()));
serve(stop).await;

// Or, to act on which signal it was:
let which = wslib_shutdown::stop_signal().await;
```

## What's here

- **`stop_signal()`** resolves with the `Signal` that asked the process to
  stop. `SIGTERM` is what systemd and launchd send: a service that only
  handles `SIGINT` is killed rather than stopped. `Signal` displays as
  `SIGTERM`, `SIGINT` or `Ctrl-C`; log it as `signal = signal.as_str()`,
  which records a string field (`%signal` records it unquoted).
- **`cancel_on_stop(token)`** waits for the same, logs which at `info`, and
  cancels the token.
- **Both register their handlers at the call.** A signal that arrives after
  the call and before the first poll is still caught, so call it early in
  `main` and await it later.
- **A failed registration doesn't stop the process.** It is logged at
  `error` and that signal is never reported: a service that refuses to start
  over a signal handler is worse than one that has to be killed.
- **It logs under the target `wslib_shutdown`**: add it to a filter or a log
  ring that captures by target.

## Not covered

- Windows listens for Ctrl-C only. A console's close, logoff and shutdown
  events end the process as soon as the handler returns, so there's no time
  to drain, and a Windows service is stopped through the service control
  manager, not a console event.
- Once registered, a handler stays for the life of the process: a second
  `SIGTERM` doesn't kill it. Exit on your own deadline if the drain hangs.
