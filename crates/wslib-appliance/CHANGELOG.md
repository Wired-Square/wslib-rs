# Changelog

## 0.1.7

- Pins `wslib-appliance-auth` at 0.1.2, and `-backup`, `-core`, `-https`,
  `-server`, `-service` and `-store` at 0.1.3.

## 0.1.6

- Pins `wslib-appliance-types` at 0.1.3.

## 0.1.5

- Pins `wslib-appliance-config` and `wslib-appliance-store` at 0.1.2.

## 0.1.4

- Pins `wslib-appliance-core`, `-service`, `-backup`, `-server` and `-https` at 0.1.2.
- Pins `wslib-appliance-client` at 0.1.1.

## 0.1.3

- Pins `wslib-appliance-types` at 0.1.2.

## 0.1.2

- Pins `wslib-appliance-core`, `-server`, `-https`, `-service` and `-backup`
  at 0.1.1.

## 0.1.1

- `core`: `wslib-appliance-core` 0.1.0, pinned exactly, behind the `core`
  feature, off by default, which turns on `auth`.
- `server`: `wslib-appliance-server` 0.1.0, pinned exactly, behind the
  `server` feature, off by default, which turns on `core`.
- `https`: `wslib-appliance-https` 0.1.0, pinned exactly, behind the `https`
  feature, off by default, which turns on `core`.
- `service`: `wslib-appliance-service` 0.1.0, pinned exactly, behind the
  `service` feature, off by default, which turns on `core`.
- `backup`: `wslib-appliance-backup` 0.1.0, pinned exactly, behind the
  `backup` feature, off by default, which turns on `core`.
- `client`: `wslib-appliance-client` 0.1.0, pinned exactly, behind the
  `client` feature, off by default.
- `wslib-appliance-types`, `-config`, `-store` and `-auth` 0.1.1, pinned
  exactly.
- Each member now keeps its own version, and this crate pins each exactly.

## 0.1.0

- `types`, `config` and `store`: `wslib-appliance-types`,
  `wslib-appliance-config` and `wslib-appliance-store` 0.1.0, pinned exactly.
  `store` is behind the `store` feature, off by default; `ts` turns on the
  types' `ts` feature.
- `auth`: `wslib-appliance-auth` 0.1.0, pinned exactly, behind the `auth`
  feature, off by default, which turns on `store`.
