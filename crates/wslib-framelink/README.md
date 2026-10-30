# wslib-framelink

A FrameLink device over TCP, on top of `wslib-framelink-protocol` and
`wslib-framelink-board`. `FrameLinkSession` serialises each request with its
reply under a timeout, unlocks a device that refuses a write as
WRITE_LOCKED, and hands the frames the device streams to `recv_stream_frame`.

```rust
use wslib_framelink::FrameLinkSession;

let session = FrameLinkSession::connect("192.168.1.42:120".parse()?).await?;
let identity = session.identify().await?;
println!("{} {}", identity.board_name, identity.board_revision);
```

- `FrameLinkSession`: `request`, `request_multi` and `send_batch`, the rule
  lists, `capabilities`, `list_all_signals`, streaming and transmit, file
  upload with resends, and `framing_stats`, the frames the link dropped as
  longer than any frame can be, as malformed COBS, or for want of room in the
  stream channel. A peer that hangs up ends the session.
- `identify`: the board's name and revision, device id, TX queue depth (4
  when the device reports none), its embedded `BoardDef` and live signals.
- `probe_version`: the protocol version a device replies in, after a
  session to it has failed. A device drops a frame of a version it does not
  speak, so a PING goes out at every version.
- `board`: the board TOML a device stores, up and down, and its signals for a
  picker.
- `Error`: one error for the crate.

It speaks protocol version 4 only.

## Features

None is on by default.

- `discovery`: `Discovery`, a running browse for `_framelink._tcp` and
  `_mcumgr._udp` over wslib-mdns in process, as a stream of `DiscoveryEvent`s
  (`Seen`, `Updated`, `Lost`, `Error`) of `Device`s; `discover`, a one-shot
  browse; and `registry`, devices pinned to an address in one JSON file under
  `$XDG_CONFIG_HOME`, `~/.config` or `%APPDATA%`, at `framelink/framelink.json`.
- `ble`: `ble::scan` and the FrameLink GATT UUIDs over btleplug. With
  `discovery`, `Discovery` scans BLE too, decoding each device's capabilities
  from its manufacturer data.
- `wifi-prov` (with `ble` and `discovery`): `Discovery::open_wifi_prov`, a
  session writing Wi-Fi credentials to a device over BLE and streaming its
  progress.

`Device`, `DiscoveryEvent`, the registry's records and the Wi-Fi types
serialise as they did before the move; `tests/goldens.rs` pins them.

```toml
wslib-framelink = { version = "0.1", registry = "wired-square" }
```
