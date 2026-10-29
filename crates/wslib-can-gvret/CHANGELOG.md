# Changelog

## 0.1.0

- The GVRET codec, both ends: `Decoder` and the reply encoders for the device,
  `DeviceDecoder` and `encode_transmit` for the host, in the trailing-byte
  dialect the field speaks.
- `transport`: `open` and `probe` over TCP, through wslib-tcp.
- `serial`: `Link::Serial`, through wslib-serial.
