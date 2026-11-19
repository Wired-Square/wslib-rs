# Changelog

## 0.2.0

- `PasswordError::Hash` holds argon2's or the OS random source's error,
  boxed, as its `source()`, and its message no longer repeats it.
  `PasswordError` no longer derives `Clone`, `PartialEq` or `Eq`.
- The `tokio` wrappers answer `PasswordError::Cancelled` when the runtime
  shut down before the hashing ran, and `PasswordError::Panicked` when it
  panicked, in place of a `Hash` with text and a resumed panic. `verify` and
  `verify_absent` answer false for either.
- `why_unreadable` answers an `UnreadableHash`, whose `source()` is argon2's
  reason, in place of that reason's text.

## 0.1.3

- tokio's floor is 1.47.

## 0.1.2

- `why_unreadable`: why a stored hash is not a readable PHC string, for a
  log line, so a caller needs no `argon2` of its own.

## 0.1.1

- `needs_rehash` is true only when a parameter is below the pin; a hash made
  at stronger parameters is no longer re-hashed down.

## 0.1.0

- `Policy`: the minimum length in characters (12 by default) and a 1024-byte
  maximum, then an Argon2id PHC string at m=19456, t=2, p=1, pinned.
- `verify`, false on an unreadable hash; `verify_absent` for unknown accounts;
  `needs_rehash` for a hash made at other parameters, and `rehash` to upgrade
  one that just verified, under the maximum but not the minimum.
- `tokio` feature: the same calls on `spawn_blocking`.
- Moved from the chassis's `appliance-auth`.
