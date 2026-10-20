# wslib-tailscale

A client for tailscaled's LocalAPI over its Unix socket: the node's status and
prefs, logout and reset-auth, typed, with errors that keep a tailscaled that
isn't running, one that doesn't answer and one that refuses apart. A fake
tailscaled for tests comes with the `testing` feature.

```rust
let api = wslib_tailscale::LocalApi::default();
match api.status().await {
    Ok(status) => println!("{:?}", status.enrolled()),
    Err(wslib_tailscale::Error::Absent) => println!("tailscaled is not running"),
    Err(e) => return Err(e.into()),
}
```

## What's here

- **`LocalApi`**: asks `/run/tailscale/tailscaled.sock`, or the socket
  `with_socket` names. `status` (without peers), `status_within` for a timeout
  of its own, `prefs`, `logout`, `reset_auth`, and `request` for any other
  path without a body, giving back a 2xx answer's body. A `GET` waits 5 s and
  anything else 30 s, since a logout waits on the control server; both are
  settable. HTTP/1.0 written by hand, so no hyper; answers over 1 MiB are
  refused.
- **`Status`**: the `BackendState`, with `Other` for a state newer than this
  crate; the own node's DNS and host names; its Tailscale addresses; health.
  Go's `null` for an empty list reads as empty. **`enrolled()`** is the node's
  name unless it is in `NoState` or `NeedsLogin`: only the control server
  names a node, and a logged-out one keeps the name it had.
- **`Prefs`**: the control URL, `None` when tailscaled has none.
- **`Error`**: `Absent` (no socket, or a stale one that refuses), `Silent`
  (the timeout passed), `Refused` (a status outside 2xx, with the first line
  of the body, up to 200 characters), `Malformed`, and `Io`. Nothing is
  logged; the caller logs with its own context.
- **`is_tailnet_address`**: `100.64.0.0/10` or `fd7a:115c:a1e0::/48`, taking an
  IPv4-mapped address as its IPv4 one, as a dual-stack listener reports it.
- **`testing::FakeTailscaled`** (feature `testing`): answers status, prefs,
  logout and reset-auth on a socket path the test picks. The node is enrolled
  or logged out, set at any time; a logout logs it out. It records each
  request line, stops (removing the socket) and starts again, and can be set
  to never answer or to refuse with a given status.

## What isn't

tailscaled on macOS and Windows, which listen on TCP with a token; off Unix
every call is `Absent`. Peers, login, `up` and prefs changes. Any policy over
when to enrol or log out, which stays with the app.
