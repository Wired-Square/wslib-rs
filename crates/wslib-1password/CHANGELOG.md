# Changelog

## 0.1.0

- `Op` for one account, `--account` on every call, `Op::unscoped` to leave
  it off; `sign_in`, `whoami`, `current_user`. `accounts` and `find_account`.
- Vaults: `vaults`, `create_vault`, `delete_vault_permanently`,
  `open_vault`. `Vault` items: `item_exists`, `item`, `item_json`, `items`,
  `items_titled`, `item_count`, `create_item` (values on stdin as a
  template), `edit_item`,
  `rename_item`, `delete_item` (archives), `delete_item_permanently`,
  `reference`. Documents byte for byte: `document`, `create_document`,
  `edit_document`.
- `read` byte for byte and `inject`; `is_reference`, `resolve` and
  `ReadReference`, moved from `wslib-cli`'s `op` feature.
- `ItemRef`: an item by id, never matched as a title, or by title, which
  two items sharing it makes `Error::Ambiguous` with their ids.
- `Assignment` in `op`'s v2 syntax, never printing its value.
- `Error` mapped from `op`'s output by `map_cli_error`, with
  `NoAccountsConfigured` and `NotApproved` kept apart from `NotSignedIn`.
- `ShellRunner` with concurrent pipes and a 30 s timeout; the `Runner` seam;
  `cli_path`.
- `tokio` feature: `tokio::blocking`. `testing` feature: `FakeRunner`.
- Moved from a consumer's own wrapper around `op`.
