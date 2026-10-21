# wslib-auth-totp

TOTP (RFC 6238) as authenticator apps run it: HMAC-SHA1, six digits,
thirty-second steps, a 160-bit key in unpadded base32. Keys, the `otpauth://`
URI for a QR code, the code check, and the check that the server's clock and
the browser's agree.

```rust
let key = wslib_auth_totp::Key::generate()?;
let uri = key.otpauth_uri("Pump House", &username); // QR code
store(key.to_base32());                              // a Secret

// Later, a code typed at sign-in:
let key = wslib_auth_totp::Key::from_base32(stored.expose()).ok_or(Refused)?;
match key.accepted_step(&code, SystemTime::now()) {
    Some(step) if step > last_step_spent => { /* signed in; keep `step` */ }
    Some(_) => { /* that code has been used */ }
    None => {
        wslib_auth_totp::check_clocks(browser_time, SystemTime::now())?; // ClockSkew
        /* wrong code */
    }
}
```

## What's here

- **`Key`**: `generate`, `from_base32` (exactly 160 bits, upper case, so a
  stored key that isn't one signs nobody in), `to_base32` and
  `otpauth_uri(issuer, account)`, both as `wslib_secret::Secret`. Its `Debug`
  prints nothing of it.
- **`Key::accepted_step(code, now)`**: the latest step within one of `now`'s
  whose code matches, spaces ignored, every candidate compared in constant
  time. **A code is good once:** keep the last step spent and refuse a step no
  later than it.
- **`Key::code_at(time)`**: the code an app shows, for tests.
- **Recovery codes**: `generate_recovery_codes()` gives ten codes of 80 bits,
  as `XXXX-XXXX-XXXX-XXXX` in base32, to show once, and the hash to keep of
  each. `recovery_code_hash(typed)` is how to find the one typed: case,
  separators and whitespace are ignored, and 0, 1 and 8 read as O, I and B.
  Spend a code by deleting its hash.
- **`check_clocks(browser, now)`**: `Err(ClockSkew)` when the browser's clock
  and the server's are more than two steps apart, in signed minutes. The
  browser's clock stands in for the phone's beside it: check it before a first
  code, and in place of "wrong code" when a code misses.
- **Features:** `codes`, on by default, is `Key` and its dependencies; with
  `default-features = false` only `ClockSkew` and `check_clocks` are left, for
  a types crate. `serde` and `ts` (ts-rs 11) for `ClockSkew`.

## What isn't

Storage, attempt limits and sessions: the app's. HOTP
counters, SHA-256 or SHA-512 keys, and codes other than six digits.
