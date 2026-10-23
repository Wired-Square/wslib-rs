# Changelog

## 0.1.0

- `stop_signal()`: resolves with the `Signal` that asked the process to stop,
  `SIGTERM` or `SIGINT` on unix and Ctrl-C on Windows, with handlers
  registered at the call. A failed registration logs and never resolves.
- `cancel_on_stop(token)`: cancels a `CancellationToken` on that signal,
  logging which.
