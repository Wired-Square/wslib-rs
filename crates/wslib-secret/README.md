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

The `keychain` feature, off by default, is for a secret kept between launches,
such as a bearer token. `SecretStore` loads, saves and deletes one by service
and account; `save` replaces what is there, and a missing item loads as `None`.

- **`Keychain`**: a generic-password item in the user's default keychain, on
  macOS only (`security-framework`).
- **`MemoryStore`**: in memory, on every platform, for tests that must not
  touch the OS.
