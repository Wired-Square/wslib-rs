# Changelog

## 0.1.0

- Promoted from `Secret` in `appliance-types` in wslib-appliance-rs.
- `Secret::matches` compares in constant time; it was `appliance-auth`'s
  `secrets_match`.
- `Secret::from_env` reads `NAME`, or the file named by `NAME_FILE`, and refuses
  both being set. `Secret::from_file` reads one file, less a trailing newline.
- `serde` and `ts` are opt-in features. In TypeScript a secret is `string` with
  no annotation at the field.
