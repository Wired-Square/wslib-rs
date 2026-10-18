# wslib-rs

Shared Rust crates for Wired Square projects: the building blocks under the
appliance chassis and every app beside it.

| Crate             | What it does                                                |
| ----------------- | ----------------------------------------------------------- |
| `wslib-build-id`  | Stamps the commit an artefact was built from into it        |
| `wslib-secret`    | A credential that never prints, loaded from env or file     |
| `wslib-backoff`   | Capped exponential backoff, reset on success                |
| `wslib-telemetry` | One tracing setup, and an in-memory ring of a service's log |

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
other by `path` plus `version`. No crate enables a rustls provider by
default; the app installs one.

`scripts/ci.sh` is the CI definition: text gates, fmt and a workspace check,
then clippy, tests and each feature for the crates changed since their last
release plus their reverse dependencies. `--tag` runs every crate, docs and
the MSRV check. It needs `cargo-hack` and `jq`.

Run it before every push, once per clone:

```sh
git config core.hooksPath scripts/hooks
```

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
