# Changelog

## 0.1.0

Moved from `appliance-auth` 0.17.1 in wslib-appliance-rs; what differs:

- No crypto provider is enabled, and `ring` is gone. A pending sign-in's
  token comes from `wslib-crypto`'s `random_default` over the process's
  default rustls `CryptoProvider`; with none installed, `PendingSignIns::begin`
  is the new `AuthError::NoProvider` ("no default crypto provider is
  installed"). The password-hash digest a pending sign-in keeps is
  `wslib-crypto`'s `Fingerprint`, the same SHA-256.
- The `sessions` feature is gone, and `Sessions` is always built: the store
  already carries `wslib-auth`'s session store.
- `CodeAttempts` is built on `wslib-auth`'s `Attempts`, at the same five wrong codes
  per fifteen minutes, with the same `TooManyCodes` message.
- `secrets_match` is gone: `wslib_secret::Secret::matches` is the same
  constant-time comparison.
