# wslib-rs

Shared Rust crates for Wired Square projects: the building blocks under the
appliance chassis and every app beside it.

| Crate                  | What it does                                                |
| ---------------------- | ----------------------------------------------------------- |
| `wslib-build-id`       | Stamps the commit an artefact was built from into it        |
| `wslib-secret`         | A credential that never prints, loaded from env or file     |
| `wslib-backoff`        | Capped exponential backoff, reset on success                |
| `wslib-telemetry`      | One tracing setup, and an in-memory ring of a service's log |
| `wslib-mcp` †          | Hosting layer for tools-only MCP servers over rmcp          |
| `wslib-dns`            | DNS lookups that keep NXDOMAIN, NODATA and failures apart   |
| `wslib-dns-mail`       | SPF, DMARC, DKIM, BIMI, MTA-STS and TLS-RPT records in DNS  |
| `wslib-cli`            | Tables or JSON, exit codes, config lookup and `op://`       |
| `wslib-http-error`     | One HTTP error body, the axum error and extractors for it   |
| `wslib-http-scaffold`  | SPA fallback, health and version routes, standard layers    |
| `wslib-http-server`    | HTTP, TLS and a redirect listener, bounded and drained      |
| `wslib-systemd-notify` | Ready, status and watchdog pings to systemd, no libsystemd  |
| `wslib-tailscale`      | tailscaled's LocalAPI: status, logout, and a fake for tests |
| `wslib-file-atomic`    | Crash-safe whole-file writes, readers set from creation     |
| `wslib-systemd`        | systemd, hostnamed, timedated and logind over D-Bus, typed  |
| `wslib-auth-oidc`      | OIDC ID-token checks against a cached, rotation-aware JWKS  |
| `wslib-auth-totp`      | TOTP keys, the otpauth URI, code and clock-skew checks      |
| `wslib-auth-passkey`   | WebAuthn passkey ceremonies, none attestation, ES256/EdDSA  |
| `wslib-auth-password`  | Argon2id password hashes, a dummy verify, rehash, policy    |
| `wslib-auth`           | Server-side sessions and their cookie, re-auth, attempts    |
| `wslib-crypto`         | Keys via a rustls provider: generate, sign, fingerprint     |
| `wslib-crypto-x509`    | Certificates read, examined, chain-checked and self-signed  |

† Not pure Rust: it carries TypeScript in `js/` that apps vendor into their
frontend. Every crate that ships other languages is marked here, and says so
at the top of its own README.

## Using a crate

Crates are published to the private Cargo registry on Forgejo, never to
crates.io. In the consuming repo's `.cargo/config.toml`:

```toml
[registries.wired-square]
index = "sparse+https://forge.wiredsquare.com/api/packages/wired-square/cargo/"
credential-provider = ["cargo:token-from-stdout", "sh", "-c", 'printf "Bearer %s" "$(op read "$WSLIB_REGISTRY_TOKEN_REF")"']
```

`WSLIB_REGISTRY_TOKEN_REF` is the `op://` reference of your Forgejo token
(`read:package` is enough), and the host must trust the CA that signs
`forge.wiredsquare.com`. Then:

```toml
[dependencies]
wslib-build-id = { version = "0.1", registry = "wired-square" }
```

### From GitHub Actions

GitHub Actions can't reach Forgejo, so it reads the read-only mirror at
`crates.wiredsquare.com` instead, with its own read token; so can any other
machine off the network. In that machine's `~/.cargo/config.toml`:

```toml
[source.wired-square-forge]
registry = "sparse+https://forge.wiredsquare.com/api/packages/wired-square/cargo/"
replace-with = "wired-square-mirror"

[registries.wired-square-mirror]
index = "sparse+https://crates.wiredsquare.com/"
credential-provider = ["cargo:token-from-stdout", "sh", "-c", 'printf "Bearer %s" "$(op read "$WSLIB_CRATES_TOKEN_REF")"']
```

`Cargo.lock` still records Forgejo, so the same lockfile builds either way.
In Actions, use `credential-provider = "cargo:token"` and supply the token
from a repository secret as `CARGO_REGISTRIES_WIRED_SQUARE_MIRROR_TOKEN`.

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
nightly. It needs `cargo-hack` and `jq`.

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
`.env.example` (`WSLIB_REGISTRY_TOKEN_REF` is the `op://` reference of a
`write:package` token, which Cargo reads from 1Password only when it
publishes):

```sh
cargo release -p wslib-build-id --execute
git push origin wslib-build-id-v<version>
scripts/mirror.sh
```

`cargo release` runs `scripts/ci.sh --tag`, publishes to the registry and
tags `<crate>-v<version>`; `scripts/mirror.sh` copies the registry to the
mirror consumers read from. The tag records what was published; consumers
pin the registry version, not the tag.
