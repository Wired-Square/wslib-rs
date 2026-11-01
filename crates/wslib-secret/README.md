# wslib-secret

A `Secret`: a string whose `Debug` and `Display` render `set` or `unset`,
never the value. `expose()` names every place it becomes an ordinary string,
`matches` compares two in constant time, and the buffer is zeroed on drop.
`Secret::from_env("NAME")` reads `NAME`, or the file named by `NAME_FILE`, and
refuses both being set.

The `serde` and `ts` features are opt-in. In TypeScript a secret is `string`.

## Tokens

The `token` feature, off by default, is for a random secret kept at rest only
as its hash: a session token, a pairing code, a recovery code.

```rust
use wslib_secret::{Encoding, Secret, TokenHash};

let token = Secret::random::<32>(Encoding::Base64Url)?; // or Base32, for people
store(token.hash().as_str());

// Later, a token presented:
let presented = Secret::new(cookie);
if presented.hash() == TokenHash::from_stored(stored) { /* admitted */ }
```

- **`Secret::random::<N>(encoding)`**: `N` bytes from the OS (`getrandom`),
  as unpadded base64url or upper-case RFC 4648 base32.
- **`TokenHash`**: the SHA-256 of the token's text, as unpadded base64url.
  `Secret::hash()` or `TokenHash::of(text)`, for text normalised first;
  `from_stored` reads one back, and `==` compares in constant time. It is
  `wslib-auth`'s session token hash, byte for byte.

## Stores

The `store` feature, off by default, is for a secret kept between launches,
such as a bearer token. `SecretStore` loads, saves and deletes one by service
and account; `save` replaces what is there, a missing item loads as `None`,
and a refused or cancelled prompt is `StoreError::Denied`. A store that is
absent or unreachable is an error, never a fallback. On a platform with no
store here, implement the trait over the app's own backend.

The `os` feature turns on all three platform stores, and `OsStore` names
whichever one the target has: an app names one type and writes no `cfg`. On
any other target `OsStore` does not exist, so the build fails rather than the
first call.

- **`Keychain`**, with the `keychain` feature: a generic-password item in the
  keychain, on macOS and iOS (`security-framework`).
- **`CredentialManager`**, with the `credential-manager` feature: a generic
  credential in the Windows Credential Manager, named `account.service`, with
  the value as UTF-16 (`windows-sys`).
- **`SecretService`**, with the `secret-service` feature: an item in the
  desktop's Secret Service over D-Bus, found by its `service` and `username`
  attributes and created in the default collection; a locked item or
  collection is unlocked through the service's prompt (`secret-service`, pure
  Rust, with an encrypted session). Loading or saving where several items match
  is an error; deleting removes them all.
- **`MemoryStore`**: in memory, on every platform, for tests that must not
  touch the OS.

The platform stores' calls block and can wait on a prompt, so hold no lock
across them. `CredentialManager` and `SecretService` read and overwrite the
items keyring 3 writes for the same service and account, with its
`windows-native` and `sync-secret-service` features.
