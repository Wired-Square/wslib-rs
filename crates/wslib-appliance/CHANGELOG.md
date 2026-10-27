# Changelog

## 0.1.1

- `core`: `wslib-appliance-core` 0.1.1, pinned exactly, behind the `core`
  feature, off by default, which turns on `auth`.
- `server`: `wslib-appliance-server` 0.1.1, pinned exactly, behind the
  `server` feature, off by default, which turns on `core`.
- `https`: `wslib-appliance-https` 0.1.1, pinned exactly, behind the `https`
  feature, off by default, which turns on `core`.
- `service`: `wslib-appliance-service` 0.1.1, pinned exactly, behind the
  `service` feature, off by default, which turns on `core`.
- `backup`: `wslib-appliance-backup` 0.1.1, pinned exactly, behind the
  `backup` feature, off by default, which turns on `core`.
- `client`: `wslib-appliance-client` 0.1.1, pinned exactly, behind the
  `client` feature, off by default.
- Every other crate of the family moves to 0.1.1 with them, pinned exactly.

## 0.1.0

- `types`, `config` and `store`: `wslib-appliance-types`,
  `wslib-appliance-config` and `wslib-appliance-store` 0.1.0, pinned exactly.
  `store` is behind the `store` feature, off by default; `ts` turns on the
  types' `ts` feature.
- `auth`: `wslib-appliance-auth` 0.1.0, pinned exactly, behind the `auth`
  feature, off by default, which turns on `store`.
