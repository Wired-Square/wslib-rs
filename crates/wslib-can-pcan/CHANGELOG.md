# Changelog

## 0.2.0

- On wslib-can 0.2.
- `transport`: a request the device refuses is wslib-can's
  `CanError::Request`, naming the request, with nusb's `io::Error` as its
  source, in place of `Read` with the request's name in the text.
- An adapter bound to a driver other than WinUSB keeps nusb's `io::Error`
  as the source of the open's `io::Error`, which names the driver and the
  remedy.
- An FD adapter that doesn't identify as it is claimed fails with that
  `CanError`, not `CanError::Open` holding its text.
- Through PEAK's driver, a refused call is `CanError::Request`, naming the
  call, with the status as its `io::Error`, in place of `Read`. A
  refused write is that `io::Error`, the adapter gone being
  `ConnectionAborted`. A wait for the receive event that panics is
  `CanError::Panicked`, the task's `Disconnected`, after which the task
  reopens, where before the panic went unreported. One the runtime cancels
  before it runs is `CanError::Cancelled`.
- A `PCANBasic.dll` that doesn't load keeps libloading's error as the source
  of the open's `io::Error`.
- A send the adapter doesn't take answers with `WriteFailed::Io` and its
  `io::Error`.

## 0.1.0

- `pcan_usb`: the classic PCAN-USB's commands, records and bit timing.
- `pcan_usb_fd`: the CAN FD family's uCAN commands, records and vendor
  requests, read from the kernel driver and untested on a device.
- `transport`: `devices`, `open` and `probe` over nusb on macOS and Windows,
  and on Windows through `PCANBasic.dll` for an adapter bound to PEAK's own
  driver.
