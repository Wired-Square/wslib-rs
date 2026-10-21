# wslib-auth-password

Argon2id password hashes as PHC strings, at parameters pinned in the crate
(m=19456 KiB, t=2, p=1) so a dependency bump cannot move them. Storage-free:
the app keeps the string.

```rust
use wslib_auth_password::{Policy, needs_rehash, rehash, verify, verify_absent};

// Setting a password:
let stored = Policy::default().hash(&new_password)?; // PasswordError::TooShort / TooLong

// Signing in; every path costs one argon2 verify:
let stored = account.as_ref().map(|a| a.password_hash.as_str());
let verified = match stored {
    Some(stored) => verify(stored, &password),
    None => verify_absent(&password),
};
if verified && stored.is_some_and(needs_rehash) {
    /* store rehash(&password)? */
}
```

## What's here

- **`Policy`**: the minimum length, in characters rather than bytes (12 by
  default; `Policy::with_min_chars` to set it), and the maximum of
  `MAX_BYTES` (1024), always enforced. `check` alone, or `hash`, which checks
  first: an overlong password is refused before argon2 runs.
- **`verify(stored, password)`**: `false` for a wrong password, an unreadable
  PHC string and an overlong password alike; it never panics. Hashes from
  argon2 0.5's `Argon2::default()` verify, since they are the same parameters.
- **`verify_absent(password)`**: the cost of a `verify`, always `false`, for a
  name no account has, so it answers no faster than a wrong password. Its
  hash is made once, by the same hasher.
- **`needs_rehash(stored)`**: true when the string was made with another
  algorithm, version or parameters, or cannot be read.
- **`rehash(password)`**: a hash at today's parameters for a password that
  has just verified. It enforces `MAX_BYTES` but not the policy's minimum, so
  a password set under an older, shorter minimum still upgrades; never use it
  to set a new password.
- **Blocking.** `hash`, `rehash`, `verify` and `verify_absent` take tens of
  milliseconds. With the `tokio` feature, `wslib_auth_password::tokio` has
  async versions that run on `spawn_blocking`.

argon2 is slow in a debug build. A consumer whose tests hash a lot can set
`[profile.dev.package.argon2] opt-level = 3` in its own workspace.

## What isn't

Storage, sessions and attempt limits: see `wslib-auth`. Peppers, and
algorithms other than Argon2id.
