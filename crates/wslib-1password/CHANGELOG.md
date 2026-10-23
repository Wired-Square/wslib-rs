# Changelog

## 0.1.0

- `Op` for one account, `--account` on every call, `Op::unscoped` to leave
  it off; `sign_in`, `whoami`, `current_user`. `accounts` and `find_account`.
- `Op::call` for any other `op` command, scoped and mapped like the rest;
  `including_archive` on `Op` and `Vault` for listings and gets.
- Vaults: `vaults`, `create_vault`, `delete_vault_permanently`,
  `open_vault`. `Vault` items: `item_exists`, `item`, `item_json`, `items`,
  `items_titled`, `item_count`, `create_item` (values on stdin as a
  template), `edit_item`,
  `rename_item`, `delete_item` (archives), `delete_item_permanently`,
  `reference`. Documents byte for byte: `document`, `create_document`,
  `edit_document`.
- `ItemSummary::created_at` and `updated_at`, RFC 3339 as `op` prints them; a
  listing may round them to whole seconds in UTC.
- `Item::created_at` and `updated_at`, at `op item get`'s full precision.
- `read` byte for byte and `inject`; `is_reference`, `resolve` and
  `ReadReference`, moved from `wslib-cli`'s `op` feature.
- `ItemRef`: an item by id, never matched as a title, or by title, which
  two items sharing it makes `Error::Ambiguous` with their ids.
- `is_item_id`; `Item::field_in`, a field by section id or label;
  `Field::text`, a value only when not empty.
- `Assignment` in `op`'s v2 syntax, never printing its value.
- `Error` mapped from `op`'s output by `map_cli_error`, with
  `NoAccountsConfigured` and `NotApproved` kept apart from `NotSignedIn`.
- `Error::WriteConflict` for the server's 409, and `Error::is_retryable`,
  true only for it.
- `ShellRunner` with concurrent pipes and a 30 s timeout; the `Runner` seam;
  `cli_path`.
- A failed call logs at `warn` with `op`'s stderr, values redacted.
- `tokio` feature: `tokio::blocking`. `testing` feature: `FakeRunner`.
- `FakeRunner` is `Debug`; an unscripted call is `Error::Unscripted`, naming it.
- Moved from a consumer's own wrapper around `op`.
