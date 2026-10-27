# Changelog

## 0.1.0

- `AppLink { name, href }`, one entry of an app switcher's listing.
- Moved from `appliance-types` 0.17.1 in wslib-appliance-rs, wire shapes
  unchanged, and the TypeScript generated for them unchanged but for its doc
  comments and `constants.ts`'s generated-by line: `Role` and its ladder,
  `Availability`, `User`, `ListedUser`, `AppRole`, `Page`, and the modules
  `about`, `account`, `audit`, `backup`, `branding`, `console`, `hooks`,
  `host`, `log`, `manifest`, `passkey`, `pending`, `session`, `tls`, `totp`
  and `trust`.
- `ThemeError::Name` reads "only tokens the appliance defines can be themed".
- `ApiErrorBody` is `wslib-http-error`'s, `ClockSkew` `wslib-auth-totp`'s and
  the passkey JSON `wslib-auth-passkey`'s, re-exported.
- `ts` feature: every type a browser reads or sends derives ts-rs 11's `TS`; a
  test run writes them and `constants.ts` into `TS_RS_EXPORT_DIR`.
