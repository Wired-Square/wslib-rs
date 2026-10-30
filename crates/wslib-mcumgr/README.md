# wslib-mcumgr

An SMP (mcumgr) client: the Zephyr protocol MCUboot devices take firmware
and files over. The codec follows Zephyr's SMP Protocol Specification; the
CBOR is ciborium's.

```rust
use std::sync::Arc;
use futures_util::StreamExt;
use wslib_mcumgr::Session;

let session = Session::connect_udp("192.168.1.42:1337".parse()?).await?;
let mut upload = session.upload(Arc::from(image), None);
let mut hash = None;
while let Some(progress) = upload.next().await {
    let progress = progress?;
    hash = progress.image_hash.or(hash);
}
session.test(&hash.unwrap()).await?;
session.reset().await?;
```

- `Session`: `list_images`; `upload`, pipelined to the device's buffers,
  resumed from the offset the device reports, one event per acknowledged
  chunk and cancelled by dropping the stream; `test`, `confirm`,
  `confirm_running`, `reset`, `echo` and `negotiate_params`.
- The file system group: `fs_upload`, `fs_download`, `fs_status`, `fs_hash`,
  and `fs_verify`, by SHA-256 or CRC-32 when the device offers one and by
  reading the file back when not.
- `Transport`: whole frames each way, and how many upload chunks may be
  unanswered. Implement it for a link of your own.
- `Header`, `Op`, `Group`: the 8-byte header.

## Features

None is on by default; without one there is no socket.

- `udp`: `Session::connect_udp`, binding the peer's address family.
- `ble`: `BleTransport` over btleplug, on a connected peripheral and the SMP
  characteristic's notifications, which the caller supplies.

```toml
wslib-mcumgr = { version = "0.1", registry = "wired-square" }
```
