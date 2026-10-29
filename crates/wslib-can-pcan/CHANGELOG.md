# Changelog

## 0.1.0

- `pcan_usb`: the classic PCAN-USB's commands, records and bit timing.
- `pcan_usb_fd`: the CAN FD family's uCAN commands, records and vendor
  requests, read from the kernel driver and untested on a device.
- `transport`: `devices`, `open` and `probe` over nusb on macOS and Windows,
  and on Windows through `PCANBasic.dll` for an adapter bound to PEAK's own
  driver.
