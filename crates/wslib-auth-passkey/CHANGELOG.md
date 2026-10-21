# Changelog

## 0.1.0

- `RelyingParty::for_host`: the RP ID and origin from the Host header, IP
  addresses refused.
- `Ceremonies`: registration, sign-in and reauthentication, each begun with
  options and finished against an in-memory challenge spent on first use.
  `none` attestation, ES256 and EdDSA, user verification required.
- `Assertion::verify` against a `StoredPasskey`, and `sign_count_moved`.
- The WebAuthn JSON types, with ts-rs behind `ts`; `SoftPasskey` behind
  `testing`.
- Moved from the chassis's `appliance-auth`, on RustCrypto rather than ring.
  An Ed25519 key not on the curve is now refused at registration, and Ed25519
  signatures are checked strictly.
