# wslib-appliance-xtask

The build-host tool for an appliance: it renders a product's packaging from one
`appliance.toml`, so the system name is written once and every unit, Debian
file, Dockerfile and build script is a function of that file. It also stands in
for a console while the app is developed.

**Not pure Rust.** `templates/` ships shell build scripts, Debian maintainer
scripts, a systemd unit and a Dockerfile, as templates.

```sh
cargo install wslib-appliance-xtask --registry wired-square --locked
```

It renders for `wslib-appliance-config` 0.1.2, `wslib-appliance-store` 0.1.3
and `wslib-appliance-server` 0.1.5: the `/usr/share/<name>` layout, the
`config.toml` keys and the store's directory are theirs.

## Verbs

- **`packaging render`** writes every file the tool owns into `./scaffold` from
  `./appliance.toml`, overwriting whatever is there, and warns about a file an
  earlier version or a dropped target left behind.
- **`packaging diff`** names every owned file in `./scaffold` that is not what
  this version renders. It exits `1` on drift; run `render`, then read the diff
  in git.
- **`build-id [--deb-version BASE]`** names the commit of the product being
  built in this directory, or the Debian snapshot version for `BASE`. It refuses
  a build with no commit to name. `--version` names this tool's version
  instead, and the commit when it was built from a checkout; a registry
  install prints `(unknown)` for the commit.
- **`erratum-843419 BIN`** prints each Cortex-A53 erratum 843419 site an
  aarch64 linker left unpatched, and exits `1` if there is one.
- **`dev-console --app-socket PATH`** (Unix) serves plain HTTP on loopback,
  at `--listen` (default `127.0.0.1:8080`), and proxies every request to the
  app socket as one account (`--user`, `--role`, `--reauthenticated`), replacing any identity
  the client sent. It refuses a non-loopback listener, and a request whose
  `Host` or `Origin` is not loopback. Run it as the uid the app was given as
  `<PREFIX>_CONSOLE_UID`.
- **`gates [--release]`** checks the repository in this directory against
  the rules of this version: see [Gates](#gates).

Exit codes: `0` clean, `1` drift, an unpatched site or a failed gate, `2` the
tool could not run, or a gate could not run and none failed.

## Gates

A product's CI installs one exact version and runs it in the directory that
holds its `Cargo.lock` and `appliance.toml`. Every path below is relative to
that directory, and the greps read only beneath it:

```sh
cargo install wslib-appliance-xtask --locked --version =0.2.1 --registry wired-square
wslib-appliance-xtask gates
```

Cache `~/.cargo/bin` keyed by that version. A product is held to the rules of
the version it installs, and a new rule reaches it only when it bumps.

The default run compiles nothing and takes seconds:

- **forbidden names**: nothing in the tree matches a line of the product's own
  `scripts/forbidden-names.txt` (`git grep -iE`), skipped when it is missing
  or empty.
- **sqlx query macros**: no `sqlx::query!` or its siblings, which need a live
  database or a `.sqlx` cache to build.
- **lock**: every `wslib-appliance*` crate in `Cargo.lock` comes from a
  registry, not git or a path, so a tag can be rebuilt; and not crates.io,
  where a family crate is not ours. One locked at a version
  other than the one this tool renders for is a warning naming both.
- **rustls provider**: exactly one of `ring` and `aws-lc-rs` in the normal
  dependency graph on any target (`cargo tree`, which resolves without
  compiling), or a process default cannot be chosen. Skipped with no rustls.
- **packaging**: `packaging diff`, skipped with no `appliance.toml`.

`--release`, for a tag, adds the builds a product's own CI may not run:
`cargo clippy` for `aarch64-unknown-linux-musl` and for the host, both with
`-D warnings`, and `cargo test --workspace --locked`. The cross clippy needs
the target installed and a C compiler and archiver for it, found as cc-rs
finds them and checked before it starts; with zig, as shims:

```sh
mkdir -p "$HOME/.cross"
cat >"$HOME/.cross/cc" <<'SHIM'
#!/bin/sh
n=$#
while [ "$n" -gt 0 ]; do
  a="$1"; shift; n=$((n - 1))
  case "$a" in --target=*) ;; *) set -- "$@" "$a" ;; esac
done
exec zig cc -target aarch64-linux-musl "$@"
SHIM
printf '#!/bin/sh\nexec zig ar "$@"\n' >"$HOME/.cross/ar"
chmod +x "$HOME/.cross/cc" "$HOME/.cross/ar"
export CC_aarch64_unknown_linux_musl="$HOME/.cross/cc" AR_aarch64_unknown_linux_musl="$HOME/.cross/ar"
```

The `cc` shim drops cc-rs's `--target=<rust triple>`, which `zig cc` refuses.

Each gate prints one line, `ok`, `skipped` with why, `could not run` with
why, or `failed` with every hit beneath it; warnings go to stderr and never
fail the run.

## What it owns, and what a product owns

Every file it writes is rewritten unconditionally, with no merge. A hand-edit
to one is a missing knob in `appliance.toml`; a product's own additions go in
files the tool never writes.

| Artefact | The tool owns | A product owns |
| --- | --- | --- |
| systemd unit | `targets/deb/systemd/<name>.service` | `systemd/<name>.service.d/*.conf`, shipped by `make-deb.sh` |
| maintainer scripts | `targets/deb/debian/`: `control.in`, `postinst`, `prerm`, `postrm` | `postinst.d/*` and `prerm.d/*` under `hooks_dir`, run by `run-parts` |
| `<config_dir>/config.toml` | `targets/deb/debian/config.toml`, a conffile, every key commented | the operator's edit, which dpkg keeps |
| `/usr/share/<name>/config.toml` | `targets/deb/debian/package-config.toml`, from `[targets.deb]` | nothing: the operator's file overrides it |
| shipped files | the roots and the conffile rule | `[package.files]`, each `0644` |
| `/usr/share/doc/<package>` | `changelog.gz`, from the build's version | `debian/copyright`, DEP-5 |
| the image | `targets/docker/Dockerfile` | `manifest.json`, its label |
| `packaging/*.sh` | all of them | nothing |

Paths in the last two columns are under `scaffold/` unless noted;
`manifest.json` sits beside `appliance.toml`, and `hooks_dir` and the sources
in `[package.files]` are relative to the repository root.

`make-deb.sh --target deb` builds the package into `target/debian/deb/`, and
`make-image.sh` builds the image, one architecture per run, into
`target/docker/`. Both take `CARGO_BUILD_TARGET` and call this tool by name, so
it must be on `PATH`. They build the binary's own package unless
`BINARY_PACKAGE` names another.

## The package

**Two `config.toml` files.** `<config_dir>/config.toml` is a dpkg conffile
with every listener and `[tls]` key commented, so dpkg keeps an operator's
edit and asks before replacing an edited file the upgrade changed.
`[targets.deb]`'s `bind_address` and `https_port` go in
`/usr/share/<name>/config.toml`, which is not a conffile, so every upgrade
replaces it. The unit points `<PREFIX>_PACKAGE_CONFIG` at that file and sets
no listener `Environment=`, which would outrank the operator: a key
uncommented in the conffile wins. `redirect_port` defaults to `0`, so there is
no plain-HTTP listener until an operator sets one. On every configure,
`postinst` takes world access off the conffile and sets its group to `group`
only while it is `root`'s, leaving an operator's group, a stricter mode and a
symlink alone.

**A renamed package.** With `[targets.deb] package`, the package conflicts
with and replaces `name`, so installing it over a system-named one keeps the
configuration, the state, the account and whether the unit is enabled. It
does not provide `name`: another package's `Depends: <name>` is met only by a
package called `name`. A purge leaves everything of the appliance's while
another of its packages (`name`, `package`, `<name>-image`) is installed, and
fails, removing nothing, when `dpkg-query` cannot say. A `package` is
permanent once shipped: rename it again and the old package's purge does not
know the new name, and takes the configuration and state from under it.

**What an operator has.** `apt install ./<package>_*.deb` runs the daemon as
`user`, holding `CAP_NET_BIND_SERVICE` and the declared `capabilities` and no
more; journald is left as the distribution set it. An upgrade keeps the state
and restarts a running daemon. A remove keeps the configuration directory,
the state and the account; a purge takes all three.

**What `make-deb.sh` refuses.**

- A `ui_dist` holding `.git`, `node_modules` or a `.env*` file: everything
  staged is served without a credential. Name the directory the bundler
  writes, not the one it reads.
- A `.gz` that no longer holds the file beside it. A file with a `.gz` beside
  it is sent as that copy to a browser that takes gzip.
- A hook in `hooks_dir` that `run-parts` would skip: a name with anything but
  letters, digits, `_` and `-` (so no `.sh`), or no executable bit.
- The example's `package.maintainer` placeholder, which also signs the
  changelog.

**Files an earlier version read.** A retired key in `appliance.toml`
(`[targets.image]`, `[upgrade]`, `privilege` and the others) is refused,
saying what became of it, and `packaging render` names a leftover
`scaffold/image/` or `scaffold/targets/image/` to delete. It never deletes a
file itself.

## The image

The image is distroless and runs as `10001:0`. Each socket is `0660` in group
0, so a console runs it as `--user <uid>:0`, which is how a root console with
no capabilities reaches the sockets. The image cannot carry a stop timeout:
the console's must exceed the daemon's 22 s grace, or Docker's default of
10 s kills the drain.

A declared capability is set on the binary `+ep`, since the image runs as
any non-root uid. The container's bounding set must hold it or the exec fails
with `EPERM`: Docker's default set holds `NET_RAW` and `NET_BIND_SERVICE`, and
`NET_ADMIN` needs `--cap-add`. The `setcap` stage installs it from Debian, so
that build needs network, and a rootful builder: a user-namespaced `setcap`
writes an attribute a rootful runtime ignores.

## Cross-building

`build-binary.sh` links a real binary, so cargo needs the target's linker, not
only a C compiler. For `aarch64-unknown-linux-musl` the linker is Rust's own
`rust-lld`, with `--fix-cortex-a53-843419`, which patches every site of
Cortex-A53 erratum 843419 (the Pi 3 and the Zero 2 W); `zig cc` refuses that
flag:

```sh
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-arg=--fix-cortex-a53-843419" \
CARGO_BUILD_TARGET=aarch64-unknown-linux-musl scaffold/packaging/make-deb.sh --target deb
```

- `CC_<triple>` and `AR_<triple>` are for a dependency's build script; cargo
  takes the linker from `CARGO_TARGET_<TRIPLE>_LINKER` alone.
- The per-target `…_RUSTFLAGS`, not `RUSTFLAGS`, so an x86_64 build is
  untouched. It replaces `[build] rustflags` from `.cargo/config.toml`, so a
  product with some adds them here. A `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`
  in the environment, even empty, replaces it in turn: the link then succeeds
  without the fix, and `erratum-843419` refuses the binary.
- `make-deb.sh` needs GNU coreutils (`install -D`, `du --exclude`, `date -R`):
  on macOS, put Homebrew's `coreutils` `libexec/gnubin` first on `PATH`.

## `appliance.toml`

`appliance.toml.example` is the full file, every key explained. In short:

```toml
name = "widget"
binary = "widget-server"
user = "widget"
group = "widget"
config_dir = "/etc/widget"
state_dir = "/var/lib/widget"
runtime_dir = "/run/widget"
socket = "/run/widget/widget.sock"
env_prefix = "WIDGET"
address_families = []
capabilities = []

[package]
section = "admin"
maintainer = "Widget Team <widget@example.com>"
description = "Widget appliance daemon"
depends = ["init-system-helpers (>= 1.54)", "adduser", "ca-certificates"]
suggests = []
ui_dist = "ui/dist"
min_binary_bytes = 2_500_000

[targets.deb]
bind_address = "0.0.0.0"
https_port = 8443

[targets.docker]
repository = "ghcr.io/example/widget"
source = "https://github.com/example/widget"
```

A field that does not follow from `name` is a warning, so a half-finished
rename shows. A file that could not produce a working box is refused, with
every problem named at once.

## A crypto provider

The tool itself serves no TLS. The daemon it packages is a family app, which
installs its own rustls provider before serving; nothing rendered here
installs one.
