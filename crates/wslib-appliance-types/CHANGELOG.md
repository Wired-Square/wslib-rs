# Changelog

## 0.1.3

- `account::EnabledChange` carries `proof`, defaulted when absent, so
  `{"enabled":true}` still reads.
- `account::AppRoleChange { role, proof }`, the body of a host's
  `PUT /api/users/{id}/apps/{app}`; a `None` role removes the app role.

## 0.1.2

- `AppManifest::devices`: the hotplugged `DeviceClass`es the console passes in,
  USB ones optionally by `UsbVendorId`. `MANIFEST_SCHEMA` is 2; a manifest is
  written at `oldest_schema()`, 1 unless it declares devices.

## 0.1.1

- Dependency floors: `wslib-auth-totp` 0.1.1, `wslib-http-error` 0.1.1 and
  `wslib-telemetry` 0.1.9 (were 0.1.0), the floors the rest of the family
  takes. No change to the API.

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
