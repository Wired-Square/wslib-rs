# Changelog

## 0.1.0

Moved from `appliance-auth` 0.17.1 in wslib-appliance-rs; what differs:

- `ring` is gone. A pending sign-in's token comes from the OS through
  `getrandom`, and the password-hash digest it keeps from `sha2`, the same
  SHA-256. No crypto provider is needed.
- The `sessions` feature is gone, and `Sessions` is always built: the store
  already carries `wslib-auth`'s session store.
- `CodeAttempts` is built on `wslib-auth`'s `Attempts`, at the same five
  wrong codes per fifteen minutes, with the same `TooManyCodes` message.
- `secrets_match` is gone: `wslib_secret::Secret::matches` is the same
  constant-time comparison.
