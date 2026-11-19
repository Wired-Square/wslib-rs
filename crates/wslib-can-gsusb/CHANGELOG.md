# Changelog

## 0.1.1

- `transport`: a request the device refuses is wslib-can's
  `CanError::Request`, naming the request, with nusb's `io::Error` as its
  source, in place of `Read` with the request's name in the text.
  wslib-can's floor is 0.1.4.

## 0.1.0

- The gs_usb codec: the host frame both ways, the vendor requests and their
  replies, and the bit timing search.
- `transport`: `devices`, `open` and `probe` over nusb on macOS and Windows;
  on Linux, `devices` from sysfs.
