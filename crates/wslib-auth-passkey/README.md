# wslib-auth-passkey

Passkeys: the WebAuthn registration (§7.1) and authentication (§7.2)
ceremonies, checked step by step. `none` attestation only; ES256 and EdDSA
keys; the user verified (a PIN or a biometric) every time; discoverable
credentials, so a sign-in needs no username. The app keeps the passkeys.

```rust
let rp = RelyingParty::for_host(host)?;                // the Host header
let ceremonies = Ceremonies::default();                  // one per process

// Registration
let options = ceremonies.begin_registration(&rp, "Pump House", &user.id, &user.name, existing_ids)?;
let new = ceremonies.finish_registration(&rp, &user.id, &credential)?;
keep(new.credential_id, new.public_key, new.sign_count, rp.id());

// Sign-in
let options = ceremonies.begin_sign_in(&rp)?;
let assertion = ceremonies.read_sign_in(&rp, &credential)?;
let stored = find(assertion.credential_id()).ok_or(Refused)?;
let count = assertion.verify(&StoredPasskey { user_id, rp_id, public_key })?;
if !sign_count_moved(stored.sign_count, count) { /* refuse: possibly cloned */ }
```

## Setting it up

- **The RP ID is the host the browser reached the server by**, so a passkey
  signs in on the name it was made on and no other. `RelyingParty::for_host`
  refuses an IP address (browsers won't run WebAuthn on one) and takes the
  origin as `https://` with the port. A certificate the browser doesn't trust
  fails in the browser, with a `SecurityError`.
- **One `Ceremonies` per process**, shared by every route; `Clone` shares it.
  Its challenges live in memory: a sign-in's two minutes, a registration's or
  reauthentication's five. Each is spent by the first answer naming it,
  whatever that answer then says. An account holds one of each kind at a
  time; sign-ins, which anybody may begin, are capped at 1024, oldest dropped.
- **The app keeps the passkeys**, and refuses a credential ID registered
  before (§7.1 step 26). It stores the count `verify` returns only when
  `sign_count_moved`, ideally as a compare-and-swap.

## What's here

- **`Ceremonies`**: `begin_registration` and `finish_registration`;
  `begin_sign_in` and `read_sign_in`; `begin_reauthentication` (the account's
  credential IDs on this host) and `read_reauthentication`. A `read_*` checks
  the client data and spends the challenge; the `Assertion` it returns names
  its passkey with `credential_id()`, and `verify` checks the account, the
  user handle, the host, the flags and the signature, then answers the count.
- **The JSON types** `navigator.credentials.create()` and `.get()` take and
  `toJSON()` gives back, with every byte string base64url. A credential's
  `Debug` prints only its type. The `ts` feature derives ts-rs 11.
- **`Refused`**: `Response` (the answer failed a check) or `StoredKey` (the
  kept public key is unreadable). `reason()` names the check for the log; show
  users a fixed message. Nothing is logged.
- **`claimed_user_id`**: an answer's unverified user handle, for an audit log.
- **The `ceremonies` feature**, on by default, is everything but the JSON
  types; with `default-features = false` the crate is those types on serde
  alone, for a types crate.
- **The `testing` feature**: `SoftPasskey`, an ES256 passkey that answers
  options as a browser would; `SoftPasskey::counterless()` signs every answer
  with a count of zero.

## What isn't

Attestation other than `none`, and so authenticator models or AAGUID policy.
RSA and other algorithms. Storage, account state, names for passkeys and
sessions. Conditional UI and hybrid transports are the browser's.
