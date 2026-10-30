# Changelog

## 0.1.0

- An SMP (mcumgr) client, its codec written to Zephyr's SMP Protocol
  Specification: `Header`, `Op`, `Group` and `Version`.
- `Session`: `list_images`, a pipelined `upload` that resumes from the
  device's offset and is cancelled by dropping its stream, `test`, `confirm`,
  `confirm_running`, `reset`, `echo` and `negotiate_params`.
- The file system group: `fs_upload`, `fs_download`, `fs_status`, `fs_hash`
  and `fs_verify`, which checks by SHA-256, CRC-32 or a read-back.
- `Transport`, dyn-safe, with `udp` (`UdpTransport`) and `ble`
  (`BleTransport`, over btleplug 0.13 and a caller's notification stream).
