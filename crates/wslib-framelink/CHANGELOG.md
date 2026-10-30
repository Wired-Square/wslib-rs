# Changelog

## 0.1.1

- `smp`: SMP sessions and firmware updates over wslib-mcumgr.
  `Discovery::open_smp_udp`, `open_smp`, `ota_udp` and `ota`, and
  `ota_udp_addr`, streaming `OtaEvent`s; with `ble`, `open_smp_ble` and
  `ota_ble`. Their errors are `Error::Smp`, `SmpUnavailable` and
  `OtaVerifyMismatch`. `OtaEvent` is `#[non_exhaustive]`, and so are the
  re-exported `UploadProgress` and `ImageSlot`.
  Opens of one device's SMP session take turns without holding the other
  devices' sessions, and a cached session whose link has closed is opened
  again, over UDP as over BLE.
- `ota_ble` and `ota_udp` return `OtaStream`, as `ota` does, and
  `Discovery::open_smp_on` opens a seen device's session over a transport
  chosen at run time.
- Dropping an OTA stream stops its update at the next wait (the upload,
  a reply, the wait for the reset device) rather than at its next event,
  and never mid-frame.
- `WifiStatus::as_byte`, the inverse of `from_byte`.
- `probe` tells a device that answers in a version (`Probe::Answered`) from
  one that sends bytes no frame parses from (`Unparseable`) and one that
  says nothing (`Silent`). `probe_version` is unchanged.

## 0.1.0

- The FrameLink session, moved in with every serialised shape unchanged:
  `FrameLinkSession`, `Device`, `CapabilitySet`, `Discovery`, `registry`,
  `ble` and `ble::wifi_prov`.
- One `Error` for the crate, in place of `ClientError`, `FramelinkError`,
  `DiscoveryError`, `WifiProvError`, `BleScanError` and the `String` errors
  of the board transfer and the one-shot `discover`. The registry returns it
  too.
- The link unframes with wslib-framing's `CobsDecoder`, capped at the longest
  frame the header's length allows. `FrameLinkSession::framing_stats` counts
  the blocks it abandons or finds malformed, and the streamed frames dropped
  for a full stream channel, which were dropped silently before.
- `FrameLinkSession::request_reply` checks a reply's type: a NACK is
  `Error::Nack` with the device's code, another type
  `Error::UnexpectedReply`. Capabilities, the signal list, transmit, the
  file transfer and the board TOML go through it, so a NACK is no longer
  parsed as the reply it stood in for.
- `SessionConfig::connect_timeout`, 5 seconds by default.
- A peer that hangs up ends the session: its task exits instead of spinning,
  `is_alive` turns false, `recv_stream_frame` returns `None` and requests fail
  with `ConnectionClosed`.
- `FrameLinkSession::identify` and `DeviceIdentity`, with
  `DEFAULT_TX_QUEUE_DEPTH`.
- `probe_version`: the protocol version a device replies to a PING in.
- `board::upload_board_def` and `download_board_def` are the only way to move
  a board TOML; the session's own methods for it are gone.
  `board::list_selectable_signals` sits beside them.
- Discovery browses through wslib-mdns (mdns-sd 0.21) in place of mdns-sd
  0.13. BLE is btleplug 0.13.
- `Discovery::start_with` browses on a caller's `wslib_mdns::InProcess`
  responder instead of opening one of its own.
- `Capability`, `Transport`, `DiscoveryEvent`, `ErrorSource`, `Resolution`,
  `ConnectTarget`, `WifiStatus` and `ProvisioningEvent` are
  `#[non_exhaustive]`.
- `CapabilitySet` converts to and from the protocol crate's
  `CapabilityFlags` without the `ble` feature.
