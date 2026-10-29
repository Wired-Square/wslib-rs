# Changelog

## 0.1.0

- The gs_usb codec: the host frame both ways, the vendor requests and their
  replies, and the bit timing search.
- `transport`: `devices`, `open` and `probe` over nusb on macOS and Windows;
  on Linux, `devices` from sysfs.
