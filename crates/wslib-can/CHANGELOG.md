# Changelog

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
