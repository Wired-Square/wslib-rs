# wslib-rs

Shared Rust crates for Wired Square projects: the building blocks under the
appliance chassis and every app beside it.

| Crate            | What it does                                            |
| ---------------- | ------------------------------------------------------- |
| `wslib-build-id` | Stamps the commit an artefact was built from into it    |

## Using a crate

Crates are published to the private Cargo registry on Forgejo, never to
crates.io. In the consuming repo's `.cargo/config.toml`:

```toml
[registries.wired-square]
index = "sparse+https://forge.wiredsquare.com/api/packages/wired-square/cargo/"
credential-provider = ["cargo:token"]
```

Supply a Forgejo access token (scope `read:package`) as
`CARGO_REGISTRIES_WIRED_SQUARE_TOKEN="Bearer <token>"`, then:

```toml
[dependencies]
wslib-build-id = { version = "0.1", registry = "wired-square" }
```

The host must trust the CA that signs `forge.wiredsquare.com`.

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
the PR. Once that is merged, on `main` with a `write:package` token in
`CARGO_REGISTRIES_WIRED_SQUARE_TOKEN`:

```sh
cargo release -p wslib-build-id --execute
git push origin wslib-build-id-v<version>
```

`cargo release` runs `scripts/ci.sh --tag`, publishes to the registry and
tags `<crate>-v<version>`. The tag records what was published; consumers
pin the registry version, not the tag.
