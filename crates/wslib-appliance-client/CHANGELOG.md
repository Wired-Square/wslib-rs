# Changelog

## 0.1.2

- `ConnectError::Io` says the pipe could not be opened or checked, and gives
  the `io::Error` through `source()`, rather than being that error.

## 0.1.1

- windows-sys's floor is 0.61.2.

## 0.1.0

Moved from `appliance-client` 0.17.1 in wslib-appliance-rs. Its behaviour is
unchanged; it takes the service's account and the pipe's owner from
`wslib-host` 0.1.1.
