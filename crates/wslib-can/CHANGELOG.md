# Changelog

## 0.2.0

- `CanError::Open` and `Read` name only their own layer. The `io::Error`
  comes only through `source()`, which `Read` now returns too.
- `CanError::Request`: a request the device didn't take, named, with its
  `io::Error` as the source.
- `serial`: `CanError::Serial`, carrying wslib-serial's `SerialError`. On
  iOS, which has no wslib-serial, the feature adds nothing.
- `CanError::Panicked`: a transport's blocking call panicked. The task
  reports it as a disconnect and reopens, as for any loss.
- `CanError::Cancelled` and `WriteFailed::Cancelled`: the runtime cancelled
  a transport's blocking call, or its blocking write, before it ran.
- `Device::write` returns `Result<(), WriteFailed>`, and `CanWriter`'s
  `send`, `submit` and `send_when_ready` answer with a `WriteFailed`, in
  place of an `io::Error`. `Io` holds the device's `io::Error`, `Panicked` a
  blocking write that panicked, and, with `serial`, `Serial` a `SerialError`.
- `CanError::Write` carries the `WriteFailed` of a write outside a send,
  such as a probe's or a handshake's.
- `CanError::Connect`, `Serial` and `Write`, and `WriteFailed::Serial`, each
  name their own layer and return the `TransportError`, `SerialError` or
  `WriteFailed` from `source()`, in place of passing its message and source
  through.
- `testing`: `LoopbackPort::fail_next_write`, the port's next write failing
  with a given `WriteFailed`.

## 0.1.3

- `testing`: `loopback`, an in-memory bus for tests. A `LoopbackBus` hands
  out `LoopbackPort`s, each opening a task on a `Loopback` device. Every
  frame written to a port reaches every port open on the bus, the writer as
  a `Tx` read.
- A `Loopback` device delivers frames on buses 0 and 1, and reports those
  two as `DeviceInfo::buses`.
- A port can stall its next write, lose the next write a matcher picks so
  that no port reads it, or be unplugged. It counts its closes.

## 0.1.2

- thiserror's floor is 2.0.20.

## 0.1.1

- `CanWriter::submit` and `send_when_ready` hand back a future that no
  longer borrows the writer, so it can be spawned or boxed as `'static`.

## 0.1.0

- `CanFrame`, `CanFlags`, `Direction`, `ErrorState` and `ErrorFrame`, and the
  id masks `ARB_MASK_EXT` and `ARB_MASK_STD`.
- `dlc`: the CAN FD length code table both ways.
- `bittiming`: the kernel's `can_calc_bittiming`.
- `candump` and `savvycan`: the log line and the CSV, written and read.
- `task`: `Device`, `open`, `CanTask`, `CanWriter` and the events, with the
  device clock mapped by the lower envelope of its offset, and reopens backing
  off from `reopen` to `reopen_max`.
- `tcp`: `CanError::Connect(wslib_tcp::TransportError)`.
