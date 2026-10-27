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

It renders for `wslib-appliance-config` 0.1.1, `wslib-appliance-store` 0.1.1
and `wslib-appliance-server` 0.1.0: the `/usr/share/<name>` layout, the
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

Exit codes: `0` clean, `1` drift or an unpatched site, `2` the tool could not
run.

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
it must be on `PATH`.

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
