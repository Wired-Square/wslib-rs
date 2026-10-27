# Changelog

## 0.1.1

- Released in lockstep with the rest of the `wslib-appliance` family; no
  change to the API.
- Dependency floor: `wslib-secret` 0.1.1, the floor the rest of the family
  takes.

## 0.1.0

Moved from `appliance-auth` 0.17.1 in wslib-appliance-rs; what differs:

- `ring` is gone. A pending sign-in's token comes from the OS through
  `getrandom`, and the password-hash digest it keeps from `sha2`, the same
  SHA-256. No crypto provider is needed.
- The `sessions` feature is gone, and `Sessions` is always built: the store
  already carries `wslib-auth`'s session store. A manifest naming the feature
  fails to resolve; drop it.
- Events, the `audit` refusals included, are logged under the
  `wslib_appliance_auth` target (was `appliance_auth`): a subscriber or log
  capture filtering on `appliance_*` no longer sees them, and nothing fails.
- `CodeAttempts` is built on `wslib-auth`'s `Attempts`, at the same five
  wrong codes per fifteen minutes, with the same `TooManyCodes` message.
- `secrets_match` is gone: `wslib_secret::Secret::matches` is the same
  constant-time comparison.
