# Changelog

## 0.1.0

- `Policy`: the minimum length in characters (12 by default) and a 1024-byte
  maximum, then an Argon2id PHC string at m=19456, t=2, p=1, pinned.
- `verify`, false on an unreadable hash; `verify_absent` for unknown accounts;
  `needs_rehash` for a hash made at other parameters.
- `tokio` feature: the same calls on `spawn_blocking`.
- Moved from the chassis's `appliance-auth`.
