# wslib-appliance-auth

An appliance's sign-in, against its
[`wslib-appliance-store`](../wslib-appliance-store): passwords, TOTP,
recovery codes and passkeys, the sign-ins waiting for a second step, and
sessions with the three checks that make revocation immediate.

```rust
use wslib_appliance_auth::{Awaiting, PendingSignIns, Proof, Sessions, authenticate};

let proof = Proof::begin();
let account = authenticate(&store, "admin", &password).await?;
if totp_is_on {
    let begun = pending.begin(&account.user.id, account.password_hash.expose(), Awaiting::Code)?;
    // hand begun.token to the browser for the code step
} else {
    let token = sessions
        .issue(&store, &account.user, account.sessions_valid_from, proof)
        .await?;
}
```

## What it holds

- **Passwords**: argon2id through `wslib-auth-password`. `authenticate` runs
  it on `spawn_blocking`, the dummy verification for an unknown name
  included; `hash_password` and `verify_password` block. An unknown name, a
  wrong password and a disabled account are one `AuthError::Refused` at one
  cost, each logged as an `audit` event. A hash at weaker parameters is
  re-hashed at the next sign-in.
- **TOTP and recovery codes** through `wslib-auth-totp`. TOTP codes are
  matched one step either side of the box's clock; when the browser's clock
  is more than a minute from the box's, a confirmation is refused unchecked
  and a sign-in's wrong code answers `AuthError::ClockSkew`. TOTP and
  recovery codes share a limit of five wrong per account per fifteen minutes
  (`CodeAttempts`).
- **Passkeys** through `wslib-auth-passkey`'s ceremonies, kept in the store,
  with a counter that did not move refused as a possible clone.
- **Pending sign-ins**, in memory for five minutes, a few per account.
- **Sessions**: `wslib-auth`'s rows in the store's `SESSIONS_TABLE`. Each
  request re-reads the account, and a session is refused once its account is
  deleted or disabled, or if it was proved before the account's sessions were
  ended. `bind` mints a second secret beside the cookie, for the page to send
  as a header, and `resolve_bound` then refuses the session without one of
  its secrets, so a browser sending the cookie to another app on the host, or
  a same-site page, is not signed in; the secrets end with the session.
