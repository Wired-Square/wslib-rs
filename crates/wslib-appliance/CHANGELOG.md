# Changelog

## 0.1.1

- `core`: `wslib-appliance-core`, pinned exactly, behind the `core` feature,
  off by default, which turns on `auth`.
- `server`: `wslib-appliance-server`, pinned exactly, behind the `server`
  feature, off by default, which turns on `core`.
- `https`: `wslib-appliance-https`, pinned exactly, behind the `https`
  feature, off by default, which turns on `core`.

## 0.1.0

- `types`, `config` and `store`: `wslib-appliance-types`,
  `wslib-appliance-config` and `wslib-appliance-store` 0.1.0, pinned exactly.
  `store` is behind the `store` feature, off by default; `ts` turns on the
  types' `ts` feature.
- `auth`: `wslib-appliance-auth` 0.1.0, pinned exactly, behind the `auth`
  feature, off by default, which turns on `store`.
