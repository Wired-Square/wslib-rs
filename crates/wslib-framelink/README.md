# wslib-framelink

A FrameLink device over TCP, or over ISO-TP on CAN with `can`, on top of
`wslib-framelink-protocol` and `wslib-framelink-board`. `FrameLinkSession`
serialises each request with its reply under a timeout, unlocks a device that
refuses a write as WRITE_LOCKED, and hands the frames the device streams to
`recv_stream_frame`.

```rust
use wslib_framelink::FrameLinkSession;

let session = FrameLinkSession::connect("192.168.1.42:120".parse()?).await?;
let identity = session.identify().await?;
println!("{} {}", identity.board_name, identity.board_revision);
```

- `FrameLinkSession`: `request`, `request_multi` and `send_batch`, the rule
  lists, `capabilities`, `list_all_signals`, streaming and transmit, file
  upload with resends, and `framing_stats`, the frames the link dropped. A
  frame is dropped if it is longer than any frame can be, is malformed COBS,
  doesn't parse, finds the stream channel full, or, over ISO-TP, fails to
  send. A peer that hangs up ends the session.
- A peer that answers on another FrameLink protocol version fails the request
  at once with `Error::PeerVersion`. Each request is still sent, so a peer
  updated to this version answers the next one. `transmit_stream` fails the
  same way if such a frame arrives while it sends.
- `Peer`: what `addr` returns, written and parsed as a `SocketAddr` or as
  `can:<bus>@<device-id>`, e.g. `can:slcan=ttyACM0@028F08`. The bus is a
  `CanBus` and the device id a `CanDeviceId`, in hex up to 0FFFFF. Both are
  re-exported here, with wslib-can-bus' `BusConfig` and `CanMode`. `connect_peer` connects to either kind.
  `PeerParseError::Unrecognised` means the text doesn't start with `can:` and
  isn't a socket address, so a caller can try it as a name.
- `identify`: the board's name and revision, device id, TX queue depth (4
  when the device reports none), its embedded `BoardDef` and live signals.
- `probe_version`: the protocol version a device replies in, after a
  session to it has failed. A device drops a frame of a version it does not
  speak, so a PING goes out at every version. `probe` also tells a silent
  device from one whose reply no frame parses from.
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
- `can`: sessions over ISO-TP on CAN, one frame per ISO-TP message.
  - `FrameLinkSession::connect_isotp` takes a wslib-isotp link the caller
    opened. `can_link_config` gives the link's ids for a `CanDeviceId`.
  - `connect_can` opens the adapter with wslib-can-bus' `open`, and ends the
    session when the adapter goes.
  - `SessionConfig::can_bus` sets the bus's rate for an SLCAN, gs_usb or
    PEAK adapter, which needs one. The rate has no default, because FrameLink
    CAN buses run at different rates. `BusConfig::fd` opens the adapter for CAN
    FD, so it can share a bus where other nodes send FD frames. FrameLink's
    own frames stay classic.
  - A failed send is counted in `send_failures`. The request then waits for
    its timeout or a file step's resend, as after a lost reply on TCP.
  - A message received with the session's queue full is counted in
    `messages_dropped`.
  - `connect_can` opens only the adapters whose wslib-can-bus feature the
    build turns on:

    ```toml
    wslib-can-bus = { version = "0.3", registry = "wired-square", features = ["slcan"] }
    ```

- `smp` (with `discovery`): `Discovery::open_smp_udp` and `open_smp`, SMP
  sessions over wslib-mcumgr, and `ota_udp`, `ota` and `ota_udp_addr`, a
  firmware update as a stream of `OtaEvent`s: upload, test, reset,
  reconnect, verify the running image, confirm. With `ble`, `open_smp_ble`
  and `ota_ble` too.

`Device`, `DiscoveryEvent`, the registry's records and the Wi-Fi types
serialise as they did before the move; `tests/goldens.rs` pins them.

```toml
wslib-framelink = { version = "0.6", registry = "wired-square" }
```
