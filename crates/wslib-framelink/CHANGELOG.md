# Changelog

## 0.6.0

- On wslib-can-bus 0.3, whose `OpenError` is `Error::CanOpen`'s and whose
  `BusConfig`, `CanMode` and `CanBus` it re-exports, and on wslib-can 0.2,
  wslib-isotp 0.2 and wslib-file-atomic 0.2, and on wslib-mdns 0.2, whose
  `Error` is `Error::Mdns`'s.

## 0.5.0

- `SessionConfig::can_bus: BusConfig` replaces `can_bitrate`.
  `BusConfig::classic(bitrate)` is the old setting.
- `BusConfig::fd(bitrate, data_bitrate)` opens the CAN adapter for CAN FD, so
  a session can share a bus where other nodes send FD frames. FrameLink's own
  frames stay classic.
- `BusConfig` and `CanMode` are re-exported from wslib-can-bus 0.2 beside
  `CanBus`, in every build.

## 0.4.0

- `FrameLinkSession::addr` returns a `Peer` by value, not a `SocketAddr`.
  `Peer::Tcp` holds the address it returned before, and `Peer::Can` a
  `CanBus` and a `CanDeviceId`.
- A `Peer` is written and parsed as a `SocketAddr`, or as
  `can:<bus>@<device-id>` with the device id in hex, e.g.
  `can:slcan=ttyACM0@028F08`. It is `Hash`.
- `PeerParseError` says why text is not a `Peer`. A bus that doesn't parse,
  including an empty one, is `Bus`, whose message names the buses
  wslib-can-bus opens. A device id over 0FFFFF is `DeviceIdTooLarge`.
- `PeerParseError::Unrecognised` is text that doesn't start with `can:` and
  isn't a socket address. That rule is stable, so a caller may fall back to a
  name lookup on it.
- `FrameLinkSession::connect_peer` connects to a `Peer` of either kind. A
  build without `can` refuses a CAN peer with `Error::NoCanTransport`.
- `CanBus` is re-exported from wslib-can-bus, now a public dependency, so a
  breaking wslib-can-bus release breaks wslib-framelink too.
- `CanDeviceId` and `CanDeviceIdError` re-export wslib-framelink-protocol's
  `can_id::DeviceId` and `DeviceIdError`, named apart from discovery's
  `DeviceId`. A caller needs no protocol dependency.
- `FramingStats` gains `send_failures`, the frames an ISO-TP link failed to
  send, and `messages_dropped`, the ISO-TP messages dropped with the
  session's queue full. Both stay 0 on TCP.
- `FramingStats` is `#[non_exhaustive]`, so a caller can no longer build one.
  Read its fields, or compare with `FramingStats::default()`.
- `can`: a session over ISO-TP on CAN, one frame per ISO-TP message.
  `FrameLinkSession::connect_isotp` takes an open wslib-isotp link and the
  bus and `CanDeviceId` it reaches, which `addr` reports unchecked.
  `can_link_config` gives a device's link ids from FrameLink's CAN id scheme.
- `connect_can` opens the adapter with wslib-can-bus' `open`, through the
  wslib-can-bus adapter features the build turns on. It never reopens the
  adapter, so the session ends when the adapter goes. An adapter that doesn't
  open is `Error::CanOpen`.
- `SessionConfig::can_bitrate` is the bus's bitrate, `None` by default.
  There is no default rate, because FrameLink CAN buses run at different
  rates. An SLCAN, gs_usb or PEAK adapter needs it. SocketCAN, GVRET and TCP
  ignore it.
- The new field breaks a `SessionConfig { .. }` literal written for 0.3. A
  literal must name `can_bitrate`, or end with `..SessionConfig::default()`.
- Over CAN a failed send is counted and the request sees silence, so a file
  step's resend or the request's timeout follows. The session ends when the
  link does.
- `SessionConfig::connect_timeout` also bounds a CAN adapter's opening.
- A frame on another FrameLink protocol version fails the request waiting
  for a reply at once, with `Error::PeerVersion`. It used to be dropped, and
  the request timed out. Each request is still sent, so a peer updated to
  this version answers the next one. `transmit_stream` fails the same way if
  such a frame arrives while it sends. This holds over TCP and CAN.
- `FramingStats` counts the frames that unstuff but don't parse.
  `other_version_frames` and `last_other_version` cover those on another
  protocol version, and `unparsed_frames` the rest.
- `upload_file` reports `FileUploadOutcome::Unknown` when a commit may have
  happened. A commit that was resent and then got anything but an ACK may
  have: any NACK, a failed unlock, a reply on another protocol version, or a
  timeout. A resend before or after an unlock both count. A commit answered
  on another protocol version may have too, even if it was sent once. The
  upload used to begin again on a device that may already run the new image.
  Otherwise a commit sent once, and begin, data and abort, keep their rules.
  A resent abort that meets WRITE_LOCKED or INVALID_STATE still ends the
  session, and one whose unlock fails is still `Error::WriteLocked`.

## 0.3.2

- `FrameLinkSession::upload_file` refuses a device that advertises a file
  chunk size of 0, as it refuses one that advertises none, before
  `FILE_BEGIN`. It had begun the file and sent an empty `FILE_DATA`, which
  the device refuses, leaving the device's file session open; a device that
  accepted it was sent empty `FILE_DATA` frames without end.
- `upload_file` caps a chunk at what one frame carries, 65 531 bytes. A
  larger advertised chunk had overflowed the frame's 16-bit length.
- `upload_file` refuses a file over 4 GiB, whose size `FILE_BEGIN`'s 32-bit
  field cannot hold, before it asks the device anything.

## 0.3.1

- tokio's floor is 1.53.3, where it meets wslib-mcumgr.

## 0.3.0

- On wslib-framelink-board 0.3, whose types it returns
  (`collect_active_rule_ids`, `Error::Board`, `DeviceIdentity`).

## 0.2.0

- On wslib-framelink-protocol 0.2 and wslib-framelink-board 0.2, whose
  types it returns: a frame definition's signal carries `quantity`.

## 0.1.2

- An update can be cancelled with its outcome reported:
  `Discovery::ota_cancellable` and `ota_on_cancellable`, and
  `ota_udp_addr_cancellable`, take the same arguments as `ota`, `ota_on` and
  `ota_udp_addr` and also return an `OtaCancel`. `OtaCancel::cancel` returns
  `CancelOutcome::Cancelled` if the update stopped before it asked the device
  to test the image, by which time the update has ended and its device id is
  free for the next; and `TooLate` once that request is out, whether or not
  `Activating` was read, leaving the update running until its stream is
  dropped. It works whether or not the stream is still held, and dropping an
  `OtaCancel` changes nothing. `CancelOutcome` is `#[non_exhaustive]` and
  serialises as `"cancelled"` or `"too-late"`. `OtaStream` and dropping it are
  unchanged.

## 0.1.1

- `smp`: SMP sessions and firmware updates over wslib-mcumgr.
  `Discovery::open_smp_udp`, `open_smp`, `ota_udp` and `ota`, and
  `ota_udp_addr`, streaming `OtaEvent`s; with `ble`, `open_smp_ble` and
  `ota_ble`. Their errors are `Error::Smp`, `SmpUnavailable` and
  `OtaVerifyMismatch`. `OtaEvent` is `#[non_exhaustive]`, and so are the
  re-exported `UploadProgress` and `ImageSlot`.
  Opens of one device's session, SMP or Wi-Fi provisioning, take turns
  without holding the other devices' sessions, and a cached session whose
  link has closed is opened again, over UDP as over BLE. A failed open
  removes the entry it made for the device.
- `ota_ble` and `ota_udp` return `OtaStream`, as `ota` does, and
  `Discovery::open_smp_on` opens a seen device's session over a transport
  chosen at run time. `Discovery::ota_on` updates one the same way.
- `OtaOptions` is `#[non_exhaustive]`, built from `default()` with
  `with_reconnect_timeout` and `with_upload`; its `upload` field takes the
  update's `UploadOptions`, now re-exported, for the image number and the
  chunk timeouts.
- Dropping an OTA stream stops its update at the next wait (the upload,
  a reply, the wait for the reset device) rather than at its next event,
  and never mid-frame. It cancels the update only before `Activating`.
  Dropped after `Activated` but before `Resetting`, no reset is sent and the
  device boots the test image at its next reset; dropped after `ResetSent`,
  nothing confirms the image, so swap-mode MCUboot reverts at the next boot.
- A second update under a device id whose update is running fails at once
  with `Error::OtaInProgress`. The guard is per id, so it spans neither
  transports, nor the device's other ids, nor `ota_udp_addr`.
- `OtaEvent` serialises, tagged by `kind` in kebab case as
  `DiscoveryEvent` is; a hash is an array of bytes, as in `UploadProgress`.
  `OtaEvent::UploadProgress` carries wslib-mcumgr's `UploadProgress`, so the
  two crates release together.
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
