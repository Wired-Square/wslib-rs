# wslib-rs

Shared Rust crates for Wired Square projects: the building blocks under the
appliance chassis and every app beside it.

| Crate                    | What it does                                                  |
| ------------------------ | ------------------------------------------------------------- |
| `wslib-build-id`         | Stamps the commit an artefact was built from into it          |
| `wslib-secret`           | A credential that never prints, loaded from env or file       |
| `wslib-backoff`          | Capped exponential backoff, reset on success                  |
| `wslib-telemetry`        | One tracing setup, and an in-memory ring of a service's log   |
| `wslib-mcp`              | Hosting layer for tools-only MCP servers over rmcp            |
| `wslib-dns`              | DNS lookups that keep NXDOMAIN, NODATA and failures apart     |
| `wslib-dns-mail`         | SPF, DMARC, DKIM, BIMI, MTA-STS and TLS-RPT records in DNS    |
| `wslib-cli`              | Tables or JSON, exit codes and config lookup                  |
| `wslib-http-error`       | One HTTP error body, the axum error and extractors for it     |
| `wslib-http-scaffold`    | SPA fallback, health and version routes, standard layers      |
| `wslib-http-server`      | HTTP, TLS and a redirect listener, bounded and drained        |
| `wslib-systemd-notify`   | Ready, status and watchdog pings to systemd, no libsystemd    |
| `wslib-tailscale`        | tailscaled's LocalAPI: status, logout, and a fake for tests   |
| `wslib-file-atomic`      | Crash-safe whole-file writes, readers set from creation       |
| `wslib-systemd`          | systemd, hostnamed, timedated and logind over D-Bus, typed    |
| `wslib-auth-oidc`        | OIDC ID-token checks against a cached, rotation-aware JWKS    |
| `wslib-auth-totp`        | TOTP keys, the otpauth URI, code and clock-skew checks        |
| `wslib-auth-passkey`     | WebAuthn passkey ceremonies, none attestation, ES256/EdDSA    |
| `wslib-auth-password`    | Argon2id password hashes, a dummy verify, rehash, policy      |
| `wslib-auth`             | Server-side sessions and their cookie, re-auth, attempts      |
| `wslib-crypto`           | Keys via a rustls provider: generate, sign, fingerprint       |
| `wslib-crypto-x509`      | Certificates read, examined, chain-checked and self-signed    |
| `wslib-tls`              | Outbound trust, live and typed; the serving pair kept         |
| `wslib-crypto-ca`        | A CA: requests, issuing under a profile, revocation lists     |
| `wslib-systemd-journal`  | The journal through journalctl's JSON, bounded and parsed     |
| `wslib-ssh-keys`         | authorized_keys lines as sshd reads them, and fingerprints    |
| `wslib-networkmanager`   | NetworkManager over D-Bus: devices, Wi-Fi, checkpoints        |
| `wslib-mdns`             | DNS-SD adverts and browsing, in process or through avahi      |
| `wslib-1password`        | The `op` CLI typed: vaults, items, documents, `op://` reads   |
| `wslib-db-sqlite`        | One SQLite database: WAL, migration chains, settings          |
| `wslib-host`             | Hostname, uptime, kernel, OS and an app-specific machine id   |
| `wslib-tasks`            | One task per row of a desired set, reconciled on change       |
| `wslib-homeassistant`    | Home Assistant Ingress: peer check, caller and base path      |
| `wslib-mcu-flash`        | ESP32 and STM32 flashing: tty lookup, images, five backends   |
| `wslib-service`          | A service under launchd, systemd or Windows, from one call    |
| `wslib-tauri`            | Tauri desktop pieces: a quit that waits for in-flight work    |
| `wslib-pairing`          | A one-time pairing code and the URI carrying the key pin      |
| `wslib-wiretap-protocol` | Capture vocabulary; the ingest, import and link-test wires    |
| `wslib-bits`             | Payload fields by bit and order, word swaps, hex and readings |
| `wslib-checksum`         | Checksum algorithms, and finding or solving a link's checksum |
| `wslib-tcp`              | A TCP connect that tries each resolved address in one budget  |
| `wslib-modbus`           | Modbus register maps, poll schedules, RTU framing, TCP poller |
| `wslib-serial`           | Serial line settings, SLIP and delimiters, a reopening port   |
| `wslib-framing`          | Framing codecs for byte streams: COBS, with a capped decoder  |
| `wslib-can`              | CAN frames, length codes, logs, and the task transports share |
| `wslib-can-socketcan`    | SocketCAN frame layouts, and a raw-socket task on Linux       |
| `wslib-can-gvret`        | GVRET, both ends, and a task over TCP or a serial port        |
| `wslib-can-slcan`        | SLCAN with Elmue's CAN FD, and a task over a serial port      |
| `wslib-can-gsusb`        | gs_usb (candleLight), a task over nusb, a listing on Linux    |
| `wslib-can-pcan`         | PCAN-USB and the FD family, a task over nusb or PCAN-Basic    |
| `wslib-wiretap-catalogue` | Device catalogues: parse, validate, decode, edit, frame, DBC |
| `wslib-wiretap-gateway`  | A capture gateway's HTTP API, as serde types                  |
| `wslib-framelink-protocol` | FrameLink's wire, sans-io: frames, messages, signal identity |
| `wslib-framelink-board`  | FrameLink board TOML: parse, edit, scaffold, display names    |
| `wslib-appliance-types`  | An appliance's wire contract, shared by daemon and browser    |
| `wslib-appliance-config` | An appliance's bootstrap settings: flags, env and files       |
| `wslib-appliance-store`  | An appliance's tables, in one SQLite file its product shares  |
| `wslib-appliance-auth`   | Sign-in: passwords, TOTP, recovery codes, passkeys, sessions  |
| `wslib-appliance-core`   | The appliance chassis: roles, routes, state, control sockets  |
| `wslib-appliance-server` | The backend behind a console, on the app socket it proxies    |
| `wslib-appliance-https`  | The self-served backend: TLS, sign-in, its own accounts       |
| `wslib-appliance-service` | The desktop backend, on control sockets and named pipes      |
| `wslib-appliance-backup` | Sealed backups, their routes and schedule, on any backend     |
| `wslib-appliance-client` | A Windows app's connection to its service's control pipe      |
| `wslib-appliance-xtask`† | A product's packaging, CI gates and a stand-in console        |
| `wslib-appliance`        | The appliance family in one crate, each member a feature      |

† marks a crate that ships non-Rust sources, and says so at the top of its own
README. `wslib-appliance-xtask` ships shell build scripts, Debian maintainer
scripts, a systemd unit and a Dockerfile, as templates it renders into a

## Using a crate

Crates are published to the private Cargo registry on Forgejo, never to
crates.io. Name it once, machine-wide, in `~/.cargo/config.toml`:

```toml
[registries.wired-square]
index = "sparse+https://forge.wiredsquare.com/api/packages/wired-square/cargo/"
```

and store a `read:package` Forgejo token for it in `~/.cargo/credentials.toml`:

```sh
cargo login --registry wired-square
```

given as `Bearer <token>`.

Set no `credential-provider`, in a repo or your own config: Cargo refuses to
merge a string provider with an array one, so setting one breaks every
checkout that sets the other. The host must trust the CA that signs
`forge.wiredsquare.com`. Then:

```toml
[dependencies]
wslib-build-id = { version = "0.1", registry = "wired-square" }
```

### From GitHub Actions

GitHub Actions can't reach Forgejo, so it reads the read-only mirror at
`mirror.wiredsquare.com/cargo/` instead, with its own read token; so can any other
machine off the network. In that machine's `~/.cargo/config.toml`:

```toml
[source.wired-square-forge]
registry = "sparse+https://forge.wiredsquare.com/api/packages/wired-square/cargo/"
replace-with = "wired-square-mirror"

[registries.wired-square-mirror]
index = "sparse+https://mirror.wiredsquare.com/cargo/"
```

with its read token stored by `cargo login --registry wired-square-mirror`.
`Cargo.lock` still records Forgejo, so the same lockfile builds either way.
In Actions, supply the token from a repository secret as
`CARGO_REGISTRIES_WIRED_SQUARE_MIRROR_TOKEN`.

## Working here

Each crate has its own `version` and `CHANGELOG.md`. Crates depend on each
other by `path`, `version` and `registry = "wired-square"`; without the
registry, the published crate looks for its sibling on crates.io. Publish the
dependency and run `scripts/mirror.sh` before the crate that needs it, since
lookups go through the mirror. No crate enables a rustls provider by default;
the app installs one.

`scripts/ci.sh` is the CI definition: text gates, fmt and a workspace check,
then clippy, tests and each feature for the crates changed since their last
release plus their reverse dependencies. `--tag` runs every crate, docs, the
MSRV check and a build at each crate's dependency floors, which needs
nightly. It needs `cargo-hack` and `jq`. A crate's checks are skipped when
its files, its workspace dependencies' files, the lockfile, the toolchains and
`ci.sh` match a run that passed (stamps under `target/ci-passed/`);
`--no-cache` reruns them.

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
the PR. Once that is merged, on `main`, with `.env` filled in from
`.env.example`:

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
`--no-mirror` after publishing. The `write:package` token is read from 1Password
(`WSLIB_OP_ACCOUNT`, `WSLIB_REGISTRY_TOKEN_REF`), so it never sits on disk;
`credentials.toml` holds only the read token. The tag records what was
published; consumers pin the registry version, not the tag.
