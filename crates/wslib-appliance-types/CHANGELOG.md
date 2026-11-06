# Changelog

## 0.1.7

- `Chosen::items`: the items chosen within a section in `app`; a chosen
  section missing from it restores all of its items, so a choice without
  `items` reads as before. `carried_by` keeps only the items of sections it
  keeps, and `Chosen::restores_item(section, item)` answers the rule.
- `Inspection::items` and `AppInspection::items`: each section's choosable
  `SectionItem`s, a `name` and a `label`; a section absent has none.

## 0.1.6

- `AppManifest::min_applianceos` and `AppLabel::min_applianceos`: the oldest
  ApplianceOS release that runs the app, a plain `MAJOR.MINOR.PATCH`, else
  `ManifestError::MinApplianceos`. `MANIFEST_SCHEMA` is 4; a manifest setting
  it is written at schema 4.
- `AppManifest::needs_newer_host(running)`: the minimum release when a host
  running `running` is older, by semver precedence, or either does not parse.

## 0.1.5

- `AppManifest::options` and `AppLabel::options`: the `AppOption`s an app
  reads, each a `String`, `Integer`, `Boolean` or `Strings` `AppOptionKind`,
  required or with an optional default. `MANIFEST_SCHEMA` is 3; a manifest
  declaring options is written at schema 3.
- `AppManifest::check_options(values)`: fills defaults, and in
  `CheckedOptions` lists the keys it dropped for naming no option and the
  required options missing; a value of the wrong kind is
  `OptionsError::WrongKind`.
- `serde_json` is a dependency, no longer a dev-dependency.

## 0.1.4

- `ConsoleIdentity::reauthenticated_within(window, now)`: whether the
  header's `reauth` falls within `window` before `now`; false with none.

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
