# Changelog

## 0.1.0

- An SMP (mcumgr) client, its codec written to Zephyr's SMP Protocol
  Specification: `Header`, `Op`, `Group` and `Version`.
- `Session`: `list_images`, a pipelined `upload` that resumes from the
  device's offset and is cancelled by dropping its stream, `test`, `confirm`,
  `confirm_running`, `reset`, `echo` and `negotiate_params`. `upload` takes
  `UploadOptions`: the image number and the chunk timeouts. `reset` fails on
  a reply refusing it, and succeeds when the link goes or stays silent once
  the request is sent.
- One task per session reads every reply and routes it to its request by
  sequence number, so concurrent requests, uploads and file transfers keep
  their own replies; a receive error closes the session. A request
  dropped mid-write still writes its whole frame. A session is made
  within a tokio runtime.
- The file system group: `fs_upload`, `fs_download`, `fs_status`, `fs_hash`
  and `fs_verify`, which checks by SHA-256, CRC-32 or a read-back.
- `Transport`, dyn-safe, with `max_in_flight` and `max_chunk_size`, and
  `udp` (`UdpTransport`, chunks capped to one datagram) and `ble`
  (`BleTransport`, over btleplug 0.13 and a caller's notification stream,
  dropping bytes that start no reply and frames left unfinished).
- `Header::new`. `Header`, `UploadOptions`, `UploadProgress`, `ImageSlot`,
  `McumgrParams`, `FsProgress` and `FsHash` are `#[non_exhaustive]`.
