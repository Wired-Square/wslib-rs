# Changelog

## 0.1.2

- `token` feature, off by default: `Secret::random` draws bytes from the OS as
  unpadded base64url or base32, and `TokenHash` keeps the SHA-256 of a token's
  text as unpadded base64url, compared in constant time. The hash is
  `wslib-auth`'s session token hash.

## 0.1.1

- Deserialising a non-string fails with a message that never quotes the value.
  A format that prints the failing source line, as `toml` does, still shows it.
- `from_file` strips every trailing CR and LF, as `initdb --pwfile` does; it
  stripped one line ending.

## 0.1.0

- Promoted from `Secret` in `appliance-types` in wslib-appliance-rs.
- `Secret::matches` compares in constant time; it was `appliance-auth`'s
  `secrets_match`.
- `Secret::from_env` reads `NAME`, or the file named by `NAME_FILE`, and refuses
  both being set. `Secret::from_file` reads one file, less a trailing newline.
- `serde` and `ts` are opt-in features. In TypeScript a secret is `string` with
  no annotation at the field.
