# wslib-1password

The 1Password CLI, `op`, typed: sign-in, accounts, vaults, items and
documents byte for byte, `op://` references and `op inject`, with `op`'s
failures as errors. A fake `op` for tests comes with the `testing` feature.

```rust
use wslib_1password::{Assignment, FieldType, ItemRef, Op, ShellRunner};

let op = Op::new(ShellRunner::new(), "my.1password.com");
op.sign_in()?;
let vault = op.open_vault("Deploy")?;
match vault.items_titled("Signing key")?.as_slice() {
    [] => {
        vault.create_item("Signing key", "Secure Note", &[
            Assignment::set("private_key", FieldType::Password, pem),
        ])?;
    }
    [one] => vault.edit_item(&one.into(), &[Assignment::parse("expires[text]=2027-01-01")?])?,
    _ => return Err("two items are titled Signing key".into()),
}
let db = vault.document(&ItemRef::title("Database"))?; // SecretBytes, as stored
```

## What's here

- **`Op`** for one account: every call carries `--account`. `Op::unscoped`
  is the one way to leave it off, letting `op` pick, which with several
  accounts signed in can prompt for a locked one. `sign_in` runs `whoami`,
  and `signin` then `whoami` again when that fails; nothing else checks the
  session, so each method is one `op` call. `call` runs any other `op`
  command the same way, answering its stdout, and `including_archive` makes
  item listings and gets (on `Op` or `Vault`) find archived items too.
- **Accounts**: `accounts` (`op account list`, works signed out) and
  `find_account`, which lets `op account get` resolve a shorthand, address or
  UUID that the list can't match. `whoami` and `current_user`. Every `WhoAmI`
  field defaults, and its `url` is a bare host like `AccountInfo::url`,
  though `op whoami` says `https://host/`.
- **Vaults**: `vaults`, `create_vault`, `delete_vault_permanently` (`op` has
  no vault archive), `open_vault` (one `op vault get`) or `vault` from a
  `VaultInfo` already in hand. `VaultInfo::is_named` checks for a name in
  use, since `op` allows two vaults one.
- **`Vault`**, naming itself by id on every call: `item_exists` (`false` only
  for not found), `item` (typed `Item`, `Field`, `Section`), `item_json` for
  keeping an item whole, `items`, `items_titled` and `item_count` (each
  `ItemSummary` with `op`'s RFC 3339 `created_at` and `updated_at`, which a
  listing may round to whole seconds; `Item` carries them at full precision),
  `create_item` (answering the new item's `ItemSummary`), `edit_item`,
  `rename_item`, `delete_item` (archives) and `delete_item_permanently`,
  `document`, `create_document`, `edit_document`, and `reference` for an
  `op://` path, any `[type]` dropped. An "exists, then create or edit" is
  the caller's two calls.
- **`ItemRef`**: every call on an existing item takes one, `Id` or `Title`.
  `op` never refuses a title in use, so a create can make a duplicate; a
  title two items share then fails as `Error::Ambiguous` with their ids, and
  `items_titled` finds them. An `Id` never falls back to a title: one that
  is not 26 lowercase letters and digits (`is_item_id`) is refused unsent,
  and an `item` `op` answers with another id is `ItemNotFound`.
- **Fields**: `Item::field` takes the first match across sections,
  `Item::field_in` looks in one section by id or label, and `Field::text`
  answers a value only when it is not empty.
- **`Assignment`**: one field in `op`'s v2 syntax, built (`set`, `untyped`,
  `delete`, `in_section`) or `parse`d, which refuses `--field` and a token
  without `=` other than `label[delete]`. `create_item` sends the values as a
  JSON template on stdin; `edit_item` has to put them in argv, where other
  local processes can see them.
- **Bytes and secrets**: `document` and `read` answer `SecretBytes`, exactly
  what `op` printed (`read` passes `--no-newline`); documents are written
  from a temporary file, which `op` reads whole. Field values, `item_json`
  and `inject` are `wslib_secret::Secret`s. No `Debug`, log line or error
  shows a value: `Call` and `Assignment` print `<redacted>`, an echoed value
  is cut from `op`'s message, and a parse error gives only a line and column.
- **`Error`**, read from `op`'s stderr (stdout when that is empty):
  `Ambiguous`, `NotSignedIn`, `NoAccountsConfigured` (also what an app that can't reach
  the desktop integration hears), `NotApproved` (a prompt nobody answered),
  `PermissionDenied`, `VaultNotFound`, `ItemNotFound`, `ItemConflict`,
  `WriteConflict` (the server's 409, the one `is_retryable` error: nothing
  here retries), else `Cli` with the exit code; `TimedOut` and `CliNotFound`
  from the runner.
  `map_cli_error` is the mapping on its own.
- **`ShellRunner`**: drains stdout and stderr on their own threads, kills
  `op` after 30 s (`with_timeout`), and closes its stdin unless it is
  `interactive`, for a terminal tool where `op` may ask to unlock.
  `cli_path` finds `op` on `PATH`. `Runner` is the seam. Each call logs
  its redacted command line through `tracing`: at `debug`, or at `warn`
  with `op`'s stderr when it fails.
- **`op://` values**: `is_reference`, and `resolve`, which passes a plain
  value through and reads a reference through a `ReadReference`: an `Op`, or
  a closure in tests.
- **Blocking.** Every call waits for `op`. With the `tokio` feature,
  `wslib_1password::tokio::blocking` runs one on `spawn_blocking`.
- **`testing::FakeRunner`** (feature `testing`): answers from a script in
  order, fails a call nothing was scripted for with `Error::Unscripted`
  naming it, and records each call's argv, stdin and environment, and the
  contents of any file it named. Its `Debug` shows the calls, not the files.

## What isn't

Item naming, layouts and locks built on items: those are the app's. `op item
create` never refuses a title in use, so nothing here can create-if-absent. Binary file fields, item sharing, users, groups,
Connect servers and service accounts.
