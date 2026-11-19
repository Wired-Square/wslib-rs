# Changelog

## 0.2.0

- `transport`: a request the device refuses now arrives as wslib-can's
  `CanError::Request`, naming the request, with nusb's `io::Error` as its
  source, not as `Read` with the request's name in the text. wslib-can's
  floor is 0.1.4.
- An adapter bound to a driver other than WinUSB keeps nusb's `io::Error`
  as the source of the open's `io::Error`, which names the driver and the
  remedy.

## 0.1.0

- The gs_usb codec: the host frame both ways, the vendor requests and their
  replies, and the bit timing search.
- `transport`: `devices`, `open` and `probe` over nusb on macOS and Windows;
  on Linux, `devices` from sysfs.
