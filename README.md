# wslib-rs

Shared Rust crates for Wired Square projects: the building blocks under the
appliance chassis and every app beside it.

| Crate                    | What it does                                                  |
| ------------------------ | ------------------------------------------------------------- |
| `wslib-1password`        | The `op` CLI typed: vaults, items, documents, `op://` reads   |
| `wslib-appliance`        | The appliance family in one crate, each member a feature      |
| `wslib-appliance-auth`   | Sign-in: passwords, TOTP, recovery codes, passkeys, sessions  |
| `wslib-appliance-backup` | Sealed backups, their routes and schedule, on any backend     |
| `wslib-appliance-client` | A Windows app's connection to its service's control pipe      |
| `wslib-appliance-config` | An appliance's bootstrap settings: flags, env and files       |
| `wslib-appliance-core`   | The appliance chassis: roles, routes, state, control sockets  |
| `wslib-appliance-https`  | The self-served backend: TLS, sign-in, its own accounts       |
| `wslib-appliance-server` | The backend behind a console, on the app socket it proxies    |
| `wslib-appliance-service` | The desktop backend, on control sockets and named pipes      |
| `wslib-appliance-store`  | An appliance's tables, in one SQLite file its product shares  |
| `wslib-appliance-types`  | An appliance's wire contract, shared by daemon and browser    |
| `wslib-appliance-xtask`† | A product's packaging, CI gates and a stand-in console        |
| `wslib-auth`             | Server-side sessions and their cookie, re-auth, attempts      |
| `wslib-auth-oidc`        | OIDC ID-token checks against a cached, rotation-aware JWKS    |
| `wslib-auth-passkey`     | WebAuthn passkey ceremonies, none attestation, ES256/EdDSA    |
| `wslib-auth-password`    | Argon2id password hashes, a dummy verify, rehash, policy      |
| `wslib-auth-totp`        | TOTP keys, the otpauth URI, code and clock-skew checks        |
| `wslib-backoff`          | Capped exponential backoff, reset on success                  |
| `wslib-bits`             | Payload fields by bit and order, word swaps, hex and readings |
| `wslib-build-id`         | Stamps the commit an artefact was built from into it          |
| `wslib-can`              | CAN frames, length codes, logs, and the task transports share |
| `wslib-can-gsusb`        | gs_usb (candleLight), a task over nusb, a listing on Linux    |
| `wslib-can-gvret`        | GVRET, both ends, and a task over TCP or a serial port        |
| `wslib-can-pcan`         | PCAN-USB and the FD family, a task over nusb or PCAN-Basic    |
| `wslib-can-slcan`        | SLCAN with Elmue's CAN FD, and a task over a serial port      |
| `wslib-can-socketcan`    | SocketCAN frame layouts, and a raw-socket task on Linux       |
| `wslib-checksum`         | Checksum algorithms, and finding or solving a link's checksum |
| `wslib-cli`              | Tables or JSON, exit codes and config lookup                  |
| `wslib-crypto`           | Keys via a rustls provider: generate, sign, fingerprint       |
| `wslib-crypto-ca`        | A CA: requests, issuing under a profile, revocation lists     |
| `wslib-crypto-jose`      | ACME's JWS: flattened JSON, JWK thumbprints, verify only      |
| `wslib-crypto-x509`      | Certificates read, examined, chain-checked and self-signed    |
| `wslib-db-sqlite`        | One SQLite database: WAL, migration chains, settings          |
| `wslib-dns`              | DNS lookups that keep NXDOMAIN, NODATA and failures apart     |
| `wslib-dns-mail`         | SPF, DMARC, DKIM, BIMI, MTA-STS and TLS-RPT records in DNS    |
| `wslib-file-atomic`      | Crash-safe whole-file writes, readers set from creation       |
| `wslib-framelink`        | A FrameLink session over TCP, discovery, BLE Wi-Fi setup      |
| `wslib-framelink-board`  | FrameLink board TOML: parse, edit, scaffold, display names    |
| `wslib-framelink-protocol` | FrameLink's wire, sans-io: frames, messages, signal identity |
| `wslib-framing`          | Framing codecs for byte streams: COBS, with a capped decoder  |
| `wslib-homeassistant`    | Home Assistant Ingress: peer check, caller and base path      |
| `wslib-host`             | Hostname, uptime, kernel, OS and an app-specific machine id   |
| `wslib-http-error`       | One HTTP error body, the axum error and extractors for it     |
| `wslib-http-scaffold`    | SPA fallback, health and version routes, standard layers      |
| `wslib-http-server`      | HTTP, TLS and a redirect listener, bounded and drained        |
| `wslib-instruments`      | Blocking bench-instrument probes: a 121GW, a WiredReflow      |
| `wslib-mcp`              | Hosting layer for tools-only MCP servers over rmcp            |
| `wslib-mcu-flash`        | ESP32 and STM32 flashing: tty lookup, images, six backends    |
| `wslib-mcumgr`           | SMP (mcumgr): image upload, test and confirm, files, UDP, BLE |
| `wslib-mdns`             | DNS-SD adverts and browsing, in process or through avahi      |
| `wslib-modbus`           | Modbus register maps, poll schedules, RTU framing, TCP poller |
| `wslib-networkmanager`   | NetworkManager over D-Bus: devices, Wi-Fi, checkpoints        |
| `wslib-pairing`          | A one-time pairing code and the URI carrying the key pin      |
| `wslib-quantity`         | A value and its unit: parse, convert, auto-scale, precision   |
| `wslib-secret`           | A credential that never prints, loaded from env or file       |
| `wslib-serial`           | Serial line settings, SLIP and delimiters, a reopening port   |
| `wslib-serial-console`   | A shared serial console: its wire, monitor and `/ws/serial`   |
| `wslib-service`          | A service under launchd, systemd or Windows, from one call    |
| `wslib-ssh-keys`         | authorized_keys lines as sshd reads them, and fingerprints    |
| `wslib-systemd`          | systemd, hostnamed, timedated and logind over D-Bus, typed    |
| `wslib-systemd-journal`  | The journal through journalctl's JSON, bounded and parsed     |
| `wslib-systemd-notify`   | Ready, status and watchdog pings to systemd, no libsystemd    |
| `wslib-tailscale`        | tailscaled's LocalAPI: status, logout, and a fake for tests   |
| `wslib-tasks`            | One task per row of a desired set, reconciled on change       |
| `wslib-tauri`            | Tauri desktop pieces: a quit that waits for in-flight work    |
| `wslib-tcp`              | A TCP connect that tries each resolved address in one budget  |
| `wslib-telemetry`        | One tracing setup, and an in-memory ring of a service's log   |
| `wslib-tls`              | Outbound trust, live and typed; the serving pair kept         |
| `wslib-wiretap-catalogue` | Device catalogues: parse, validate, decode, edit, frame, DBC |
| `wslib-wiretap-gateway`  | A capture gateway's HTTP API, as serde types                  |
| `wslib-wiretap-protocol` | Capture vocabulary; the ingest, import and link-test wires    |

† marks a crate that ships non-Rust sources, and says so at the top of its own
README. `wslib-appliance-xtask` ships shell build scripts, Debian maintainer
scripts, a systemd unit and a Dockerfile, as templates it renders into a
product.

## Using a crate

Crates are published to the private Cargo registry on Forgejo, never to
crates.io. Name it once, machine-wide, in `~/.cargo/config.toml`:

```toml
[registry]
global-credential-providers = ["cargo:token"]

[registries.wired-square]
index = "sparse+https://forge.wiredsquare.com/api/packages/wired-square/cargo/"
```

Without `global-credential-providers`, Cargo refuses the registry with
"authenticated registries require a credential-provider to be configured",
even when a token is stored. Then store a `read:package` Forgejo token for it
in `~/.cargo/credentials.toml`:

```sh
cargo login --registry wired-square
```

given as `Bearer <token>`.

Set no per-registry or `[registry]` `credential-provider`, in a repo or your
own config: Cargo refuses to merge a string provider with an array one, so
setting one breaks every checkout that sets the other.
`global-credential-providers` is a different key and doesn't clash. The host
must trust the CA that signs `forge.wiredsquare.com`. Then:

```toml
[dependencies]
wslib-build-id = { version = "0.1", registry = "wired-square" }
```

### From GitHub Actions

GitHub Actions can't reach Forgejo, so it reads the read-only mirror at
`mirror.wiredsquare.com/cargo/` instead, with its own read token; so can any other
machine off the network, though not to release. In that machine's `~/.cargo/config.toml`:

```toml
[registry]
global-credential-providers = ["cargo:token"]

[source.wired-square-forge]
registry = "sparse+https://forge.wiredsquare.com/api/packages/wired-square/cargo/"
replace-with = "wired-square-mirror"

[registries.wired-square-mirror]
index = "sparse+https://mirror.wiredsquare.com/cargo/"
```

with its read token stored by `cargo login --registry wired-square-mirror`.
`Cargo.lock` still records Forgejo, so the same lockfile builds either way.
In Actions, supply the token from a repository secret as
`CARGO_REGISTRIES_WIRED_SQUARE_MIRROR_TOKEN`, with
`CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS=cargo:token` in place of the
`[registry]` table.

## Working here

Each crate has its own `version` and `CHANGELOG.md`. Crates depend on each
other by `path`, `version` and `registry = "wired-square"`; without the
registry, the published crate looks for its sibling on crates.io. A
dependency is published before the crate that needs it: name both to one
`scripts/release.sh` run, which orders them. No crate enables a rustls
provider by default; the app installs one.

`scripts/ci.sh` is the CI definition: text gates, fmt and a workspace check,
then clippy, tests and each feature for the crates changed since their last
release plus their reverse dependencies. `--tag` runs every crate, docs, the
MSRV check and a build at each crate's dependency floors, which needs
nightly. It needs `cargo-hack`, `jq` and, off Windows, the
`x86_64-pc-windows-msvc` target, which `--tag` needs on nightly too. A
crate's checks are skipped when
its files, its workspace dependencies' files, the locked packages it builds,
the toolchains and `ci.sh` match a run that passed (stamps under `target/ci-passed/`);
`--no-cache` reruns them. `--dry-run` lists the crates changed since their tag,
those selected with their dependants, those already passed and those it would
check, then stops before any check.

Run it before every push, once per clone:

```sh
git config core.hooksPath scripts/hooks
```

### Moving a crate in from another repo

The old repo's last release re-exports the crate from here, so a project
still on it keeps building but is told to move. It has to warn: a
`#[deprecated] pub use` is silent, so add `#[deprecated]` type aliases or
wrapper fns for the items every consumer names, with a note naming the crate
and the registry. A project that sees the warning moves to the crate here; it
doesn't stop at the old repo's tag.

## Releasing a crate

Bump the crate's `version` and give its `CHANGELOG.md` a heading for it in
the PR. Once that is merged, on `main`, with the release settings in `.env`
(below):

```sh
scripts/release.sh <crate> ... [--execute] [--no-mirror]
```

It releases only the crates named; with none it lists the crates whose
version the registry lacks. It runs `scripts/ci.sh --tag`, tags each
`<crate>-v<version>` and pushes the tags, then publishes dependencies first
and runs `scripts/mirror.sh`, which copies the registry to the mirror
consumers read from. Nothing is published without its tag on `main`: a failed
push publishes nothing, and a failed publish withdraws the tags of the crates
not yet published. Without `--execute` it stops before tagging, and with
`--no-mirror` after publishing. The tag records what was published; consumers
pin the registry version, not the tag.

Release from a machine that reads Forgejo directly. With the mirror's source
replacement (`replace-with = "wired-square-mirror"`) in its Cargo config,
packaging resolves workspace dependencies from the mirror, which lacks a
version not yet published, so a crate released with a new version of its
dependency fails at `cargo package`.

### Release settings

`release.sh` and `mirror.sh` read `.env` at the repo root, whose keys
`.env.example` lists:

| Key                    | Value                                                                     |
| ---------------------- | ------------------------------------------------------------------------- |
| `WSLIB_REGISTRY_TOKEN` | A Forgejo `write:package` token, bare: `release.sh` adds `Bearer `        |
| `WSLIB_FORGE_URL`      | `https://forge.wiredsquare.com`                                           |
| `WSLIB_FORGE_OWNER`    | `wired-square`                                                            |
| `WSLIB_MIRROR_DEST`    | `mirror@miranda.wiredsquare.com:cargo/`                                   |

`WSLIB_MIRROR_DEST` is an rsync destination ending in `:` or `/`. The
`mirror` account on miranda accepts the sync users' own SSH keys and confines
them to `/srv/mirror` with rrsync, so the path after the colon is relative to
that, and `cargo/` is the Cargo mirror's directory. Both scripts also read the
registry index with the read token in `~/.cargo/credentials.toml`, set up as
in [Using a crate](#using-a-crate).

**From a 1Password Environment**, which keeps the publish token off disk
(1Password for Mac or Linux; an owner or administrator turns Environments on
under **Policies** › **Sharing and permissions** › **Developer
permissions**):

1. In the desktop app's main window (not Settings), select **Developer** in
   the sidebar, then **View Environments**. **Developer** shows only once
   **Settings** › **Developer** › **Show 1Password Developer experience** is
   on. Select **New environment**, name it (for example `wslib-rs`) and
   **Save**.
2. Select **Edit**, then **New variable** for each key above. Values are
   hidden unless **Show value by default** is checked; leave it unchecked for
   `WSLIB_REGISTRY_TOKEN`.
3. Under **Connect to**, select **Connect** next to **Local .env file**,
   **Choose file path**, pick `.env` in this checkout, then **Mount .env
   file**. Remove any plain `.env` there first.

1Password serves the file each time it is read, and asks you to **Authorize**
the first read after it unlocks; the authorisation lasts until it locks again.

**As a plain file**, copy `.env.example` to `.env`, fill it in and
`chmod 600 .env`. The publish token then sits on disk in the clear.
