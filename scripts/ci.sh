#!/usr/bin/env bash
# The CI definition. A future Actions workflow calls this rather than restating it.
# Everyday: workspace-wide cheap gates, then per-crate checks on crates changed
# since their last release tag plus their reverse dependencies. --tag: every crate,
# once per clean commit. A crate whose inputs already passed in this mode is
# skipped; --no-cache reruns it.
#
#   scripts/ci.sh [--tag] [--no-cache]
set -euo pipefail
cd "$(dirname "$0")/.."

die() { printf 'ci: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
normal_tree() { cargo tree -e normal --prefix none --locked -p "$@"; }

all=false
cache=true
for arg; do
  case $arg in
    --tag) all=true ;;
    --no-cache) cache=false ;;
    *) die "usage: scripts/ci.sh [--tag] [--no-cache]" ;;
  esac
done
mode=default
! $all || mode=tag
target=${CARGO_TARGET_DIR:-target}

stamp=
if $all && [[ -z $(git status --porcelain) ]]; then
  stamp="$target/ci-tag-passed/$(git rev-parse HEAD)"
  [[ ! -e $stamp ]] || { printf 'ci: --tag already passed at %s\n' "$(git rev-parse --short HEAD)"; exit 0; }
fi

command -v cargo-hack >/dev/null || die "cargo-hack missing: cargo install cargo-hack"
! $all || cargo +nightly --version >/dev/null 2>&1 || die "nightly missing: rustup toolchain install nightly"
win=x86_64-pc-windows-msvc
cross_windows=false
[[ $(rustc -vV | sed -n 's/^host: //p') == *windows* ]] || cross_windows=true
! $cross_windows || rustup target list --installed | grep -qx $win || die "$win missing: rustup target add $win"
! $cross_windows || ! $all || rustup +nightly target list --installed | grep -qx $win \
  || die "nightly $win missing: rustup +nightly target add $win"
msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Clippy and check need no object code, and sqlite3.c cannot be cross-compiled for msvc off Windows.
if $cross_windows; then
  # shellcheck disable=SC2016
  printf '#!/bin/sh\nfor a; do case $a in -out:*) touch "${a#-out:}";; esac; done\n' >"$tmp/ar"
  chmod +x "$tmp/ar"
  export CC_x86_64_pc_windows_msvc=true AR_x86_64_pc_windows_msvc="$tmp/ar"
fi

step "No consumer is named"
names=scripts/forbidden-names.txt
! git grep -nIiE --untracked -f "$names" -- ":!$names" || die "a consumer is named in the tree"
! git log --format=%B | grep -nIiE -f "$names" || die "a consumer is named in a commit message"

step "No reference to the project dossier"
! git grep -nIE --untracked '\[\[[A-Za-z][^]]*\]\]' -- ':!scripts/ci.sh' ':!*.toml' ':!*.lock' || die "the dossier is cited; state the constraint here"

# A consumer's clean checkout has neither a live database nor a .sqlx cache.
step "No compile-time-checked sqlx query"
! git grep -nE --untracked 'sqlx::(query|query_as|query_scalar|query_file)[a-z_]*!' -- '*.rs' \
  || die "a sqlx query! macro needs a database to build; use the runtime sqlx::query API"

# Shared crates take no rustls provider; the app installs one.
step "No rustls provider by default"
graph=$(cargo tree --workspace -e normal --prefix none)
! grep -E '^(aws-lc-rs|ring) ' <<<"$graph" || die "a rustls provider is in the default graph"

step "wslib-telemetry's setup-core has no regex engine"
graph=$(normal_tree wslib-telemetry --no-default-features --features setup-core)
! grep -E '^(regex|regex-automata|matchers) ' <<<"$graph" || die "setup-core pulls in a regex engine"

# A desktop app takes wslib-appliance-client alone, or the facade with only
# `client`; --target all covers the Windows graph.
step "wslib-appliance-client carries no server stack"
for graph in "wslib-appliance-client" "wslib-appliance --no-default-features --features client"; do
  read -ra args <<<"$graph"
  tree=$(normal_tree "${args[@]}" --target all)
  ! grep -qE '(^|[-_])(axum|sqlx|rustls)([-_][a-z0-9_]+)* v[0-9]' <<<"$tree" \
    || die "cargo tree $graph pulls in axum, sqlx or rustls"
done

step "The appliance facade pins each library member at its version"
metadata=$(cargo metadata --format-version 1 --no-deps --locked)
jq -e '(.packages
  | map(select(all(.targets[].kind[]; IN("bin", "test", "bench", "example", "custom-build")) | not))
  | map({key: .name, value: .version}) | from_entries) as $version
  | .packages[] | select(.name == "wslib-appliance") | .dependencies as $pins
  | $version | keys | map(select(startswith("wslib-appliance-")))
  | all(. as $member | any($pins[]; .name == $member and .req == "=" + $version[$member]))' \
  <<<"$metadata" >/dev/null || die "wslib-appliance does not pin every member at its version"

step "The appliance family pins core exactly"
jq -e '[.packages[].dependencies[] | select(.name == "wslib-appliance-core") | .req]
  | all(startswith("="))' <<<"$metadata" >/dev/null \
  || die "a dependency on wslib-appliance-core is not an = pin"

# SessionAdmin and HostAdmin refuse a control socket, so it satisfies every role, never every rung.
step "No control socket reaches every rung"
! git grep -nIiE --untracked 'satisf[a-z_]*[ _]every[ _]rung' -- 'crates/wslib-appliance*' \
  || die "the claim that a control socket meets every rung is false; see wslib-appliance-core's extract.rs"

step "Format"
cargo fmt --all --check

if $all; then
  step "Docs"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
  step "Check on the stated rust-version"
  cargo "+$msrv" check --workspace --locked
fi

# A crate counts as changed if its directory differs from its newest release tag,
# or it has never been released.
changed=()
for dir in crates/*/; do
  name=$(basename "$dir")
  tag=$(git tag --list "$name-v*" --sort=-v:refname | head -n1)
  if [[ -z $tag ]] || ! git diff --quiet "$tag" -- "$dir"; then
    changed+=("$name")
  fi
done
export CHANGED="${changed[*]:-}"
selected=$(jq -r --argjson all "$all" '
  .packages as $p
  | ($p | map(.name)) as $names
  | def changed($n): $all or ($n | IN($ENV.CHANGED | split(" ")[]));
    def rdeps($n): [$p[] | select(any(.dependencies[]; .name == $n)) | .name];
    def dependants: (. + map(rdeps(.)[]) | unique) as $next
      | if $next == . then . else $next | dependants end;
    [$names[] | select(changed(.))] | unique | dependants | .[]' <<<"$metadata")

# A crate's key covers its own tree and every workspace crate it reaches through
# any dependency kind, taken from the working tree so a dirty tree counts as it stands.
index=$tmp/index
cp "$(git rev-parse --git-path index)" "$index"
GIT_INDEX_FILE=$index git add -A
worktree=$(GIT_INDEX_FILE=$index git write-tree)
inputs=$({
  echo "$mode"
  rustc -vV
  ! $all || { rustc +nightly -vV; rustc "+$msrv" -vV; }
  cargo hack --version
  git rev-parse "$worktree:Cargo.lock" "$worktree:Cargo.toml" "$worktree:.cargo" \
    "$worktree:scripts/ci.sh" "$worktree:scripts/floor-pins.txt"
} | git hash-object --stdin)
passed=$target/ci-passed/$mode
pending=
skipped=0
closures=$(jq -r --arg trees "$(git ls-tree "$worktree" crates/)" --arg selected "$selected" '
  ($trees | split("\n") | map(select(. != "") | split("\t")
    | {key: (.[1] | ltrimstr("crates/")), value: (.[0] | split(" ")[2])}) | from_entries) as $tree
  | (.packages | map({key: .name, value: [.dependencies[].name]}) | from_entries) as $deps
  | def closure: (. + map($deps[.][] | select($deps[.])) | unique) as $next
      | if $next == . then . else $next | closure end;
  .packages[] | .name | select(IN($selected | split("\n")[]))
  | "\(.) \([.] | closure | map("\(.)=\($tree[.] // error("no crates/\(.)"))") | join(" "))"' <<<"$metadata")
while read -r name closure; do
  [[ -n $name ]] || continue
  key="$passed/$name-$(git hash-object --stdin <<<"$inputs $closure")"
  if $cache && [[ -e $key ]]; then
    skipped=$((skipped + 1))
  else
    pending+="$name $key"$'\n'
  fi
done <<<"$closures"
todo=$(cut -d' ' -f1 <<<"$pending")
((skipped == 0)) || printf '\nci: %d crates already passed with these inputs; skipping their checks\n' "$skipped"

packages=()
for crate in $todo; do packages+=(-p "$crate"); done
if [[ -n $todo ]]; then
  step Clippy: "${todo//$'\n'/ }"
  cargo clippy "${packages[@]}" --all-targets --all-features --locked -- -D warnings
fi

# A build on this host skips cfg(windows) code, and a crate breaks on Windows without
# any Windows-only dependency.
if $cross_windows && [[ -n $todo ]]; then
  step "Clippy for $win:" "${todo//$'\n'/ }"
  cargo clippy "${packages[@]}" --target $win --all-features --locked -- -D warnings
fi

# A read-only build takes `tcp` or `task` without `write`; wslib-modbus's
# compile_fail doctests fail if a write path is compiled into either. A sans-io
# consumer takes its RTU side with no features.
if grep -qx wslib-modbus <<<"$todo"; then
  step "wslib-modbus without write has no write path"
  for features in tcp task; do
    cargo test -p wslib-modbus --no-default-features --features "$features" --doc --locked
  done
  step "wslib-modbus without features has no tokio"
  tree=$(normal_tree wslib-modbus --no-default-features)
  ! grep -E '^tokio(-modbus)? ' <<<"$tree" || die "wslib-modbus pulls in tokio without a feature"
  step "wslib-modbus without features has no serial port on Windows"
  tree=$(normal_tree wslib-modbus --no-default-features --target x86_64-pc-windows-msvc)
  ! grep -E '^(wslib-serial|serialport) ' <<<"$tree" || die "wslib-modbus pulls in a serial port on Windows"
fi

# A read-only port on Linux needs neither serialport nor libudev.
if grep -qx wslib-serial <<<"$todo"; then
  step "wslib-serial's task has no serialport on Linux"
  tree=$(normal_tree wslib-serial --no-default-features --features task --target x86_64-unknown-linux-gnu)
  ! grep -E '^(serialport|libudev(-sys)?) ' <<<"$tree" || die "wslib-serial's task pulls in serialport on Linux"
fi

if grep -qx wslib-framing <<<"$todo"; then
  step "wslib-framing depends on thiserror alone"
  tree=$(normal_tree wslib-framing --target all)
  ! grep -vE '^(wslib-framing|thiserror|thiserror-impl|proc-macro2|quote|syn|unicode-ident) ' <<<"$tree" \
    || die "wslib-framing depends on more than thiserror"
fi

# The FrameLink wire and board crates are sans-io on every target.
for crate in wslib-framelink-protocol wslib-framelink-board; do
  if grep -qx $crate <<<"$todo"; then
    step "$crate has no serial port, tokio or btleplug"
    tree=$(normal_tree $crate --target all)
    ! grep -E '^(serialport|tokio|btleplug) ' <<<"$tree" || die "$crate pulls in serialport, tokio or btleplug"
  fi
done

# The session crate's default build is TCP alone, and its mDNS is wslib-mdns's.
if grep -qx wslib-framelink <<<"$todo"; then
  step "wslib-framelink has no btleplug or mdns-sd by default, and mdns-sd only through wslib-mdns"
  tree=$(normal_tree wslib-framelink --target all)
  ! grep -E '^(btleplug|mdns-sd) ' <<<"$tree" || die "wslib-framelink's default build pulls in btleplug or mdns-sd"
  tree=$(normal_tree wslib-framelink --features discovery --target all --depth 1)
  ! grep -E '^mdns-sd ' <<<"$tree" || die "wslib-framelink depends on mdns-sd other than through wslib-mdns"
  step "wslib-framelink's smp has no btleplug without ble"
  tree=$(normal_tree wslib-framelink --features smp --target all)
  ! grep -E '^btleplug ' <<<"$tree" || die "wslib-framelink's smp pulls in btleplug"
  ios=aarch64-apple-ios
  if [[ -d $(rustc --print target-libdir --target $ios 2>/dev/null) ]]; then
    step "wslib-framelink's BLE for $ios"
    cargo check -p wslib-framelink --features ble,wifi-prov,smp --target $ios --locked
  else
    step "wslib-framelink's BLE for $ios skipped: its std is missing (rustup target add $ios)"
  fi
fi

# A default build of the instrument readers has no backend.
if grep -qx wslib-instruments <<<"$todo"; then
  step "wslib-instruments has no btleplug, tokio or CAN backend by default"
  tree=$(normal_tree wslib-instruments --target all)
  ! grep -E '^(btleplug|tokio|wslib-can[a-z-]*) ' <<<"$tree" || die "wslib-instruments' default build pulls in a backend"
fi

# mio is tokio's socket layer.
if grep -qx wslib-mcumgr <<<"$todo"; then
  step "wslib-mcumgr has no btleplug or socket by default"
  tree=$(normal_tree wslib-mcumgr --target all)
  ! grep -E '^(btleplug|mio) ' <<<"$tree" || die "wslib-mcumgr's default build pulls in btleplug or a socket"
fi

if grep -qx wslib-mcu-flash <<<"$todo"; then
  step "wslib-mcu-flash's mcumgr has no btleplug or socket without a transport"
  tree=$(normal_tree wslib-mcu-flash --features mcumgr --target all)
  ! grep -E '^(btleplug|mio) ' <<<"$tree" || die "wslib-mcu-flash's mcumgr pulls in btleplug or a socket"
fi

# The gateway's types are serde-only, a Windows client's included.
if grep -qx wslib-wiretap-gateway <<<"$todo"; then
  step "wslib-wiretap-gateway on Windows has no serial port or SQLite"
  tree=$(normal_tree wslib-wiretap-gateway --target x86_64-pc-windows-msvc)
  ! grep -E '^(serialport|sqlx[a-z_-]*|rusqlite|libsqlite3-sys) ' <<<"$tree" \
    || die "wslib-wiretap-gateway pulls in a serial port or SQLite on Windows"
  step "wslib-wiretap-gateway has no HTTP stack without client, and no TLS backend with it"
  tree=$(normal_tree wslib-wiretap-gateway --target all)
  ! grep -E '^(reqwest|hyper|tokio) ' <<<"$tree" || die "wslib-wiretap-gateway pulls in an HTTP stack without client"
  tree=$(normal_tree wslib-wiretap-gateway --features client --target all)
  ! grep -E '^(ring|aws-lc-rs|openssl) ' <<<"$tree" || die "wslib-wiretap-gateway's client pulls in a TLS backend"
fi

# gs_usb is the kernel's on Linux and nusb's elsewhere, never libusb's.
if grep -qx wslib-can-gsusb <<<"$todo"; then
  step "wslib-can-gsusb has no libusb, and no nusb on Linux"
  tree=$(normal_tree wslib-can-gsusb --features transport --target all)
  ! grep -E '^(rusb|libusb[a-z0-9-]*) ' <<<"$tree" || die "wslib-can-gsusb pulls in libusb"
  tree=$(normal_tree wslib-can-gsusb --features transport --target x86_64-unknown-linux-gnu)
  ! grep -E '^nusb ' <<<"$tree" || die "wslib-can-gsusb pulls in nusb on Linux"
fi

# PEAK's adapters are peak_usb's on Linux; only Windows loads PCANBasic.dll.
if grep -qx wslib-can-pcan <<<"$todo"; then
  step "wslib-can-pcan has no libusb, no nusb on Linux, and libloading only on Windows"
  tree=$(normal_tree wslib-can-pcan --features transport --target all)
  ! grep -E '^(rusb|libusb[a-z0-9-]*) ' <<<"$tree" || die "wslib-can-pcan pulls in libusb"
  tree=$(normal_tree wslib-can-pcan --features transport --target x86_64-unknown-linux-gnu)
  ! grep -E '^(nusb|libloading) ' <<<"$tree" || die "wslib-can-pcan pulls in nusb or libloading on Linux"
  tree=$(normal_tree wslib-can-pcan --features transport --target aarch64-apple-darwin)
  ! grep -E '^libloading ' <<<"$tree" || die "wslib-can-pcan pulls in libloading on macOS"
fi

if $all && [[ -n $todo ]]; then
  # A Windows-only dependency's floor is resolved only for Windows.
  windows_deps=$(! $cross_windows || jq -r '.packages[]
    | select(any(.dependencies[]; .target // "" | test("windows"))) | .name' <<<"$metadata")
  # One fixed workspace path and target dir for every crate and run, so each floor build
  # reuses what the others compiled; tar keeps mtimes, so unchanged sources stay fresh.
  floors=$target/floors/workspace
  rm -rf "$floors"
  mkdir -p "$floors"
  floors_target=$(cd "$target/floors" && pwd)/target
  git ls-files -z -co --exclude-standard \
    | while IFS= read -r -d '' f; do [[ -e $f ]] && printf '%s\0' "$f"; done \
    | tar -c --null -T - | tar -x -C "$floors"
fi

# Per crate: one lock can't hold every crate's floors at once.
floor_check() {
  local name=$1 pins
  sed -i.bak "s|^members = .*|members = [\"crates/$name\"]|" "$floors/Cargo.toml"
  rm -f "$floors/Cargo.lock"
  pins=$(sed -n "s/^$name \([^ ]*\)@\([^ ]*\)$/\1 \2/p" scripts/floor-pins.txt 2>/dev/null)
  (cd "$floors" && export CARGO_TARGET_DIR=$floors_target \
    && cargo +nightly update -Z direct-minimal-versions -q \
    && while read -r package version; do
         [[ -z $package ]] || cargo +nightly update -q -p "$package" --precise "$version"
       done <<<"$pins" \
    && cargo +nightly check --workspace --all-features --all-targets -q \
    && { ! grep -qx "$name" <<<"$windows_deps" \
         || cargo +nightly check --target $win --workspace --all-features -q; }) \
    || die "$name does not build at its dependency floors"
}

# Per crate: built together, features unify, so a sibling's can mask a missing one
# or add a second rustls provider that a test's process default can't choose between.
# A key is written only here, after the crate's last check has passed.
mkdir -p "$passed"
while read -r crate key <&3; do
  [[ -n $crate ]] || continue
  step "$crate: test"
  cargo test -p "$crate" --all-features --locked
  step "$crate: each feature"
  cargo hack check -p "$crate" --each-feature --locked
  if $all; then
    step "$crate: dependency floors"
    floor_check "$crate"
  fi
  touch "$key"
done 3<<<"$pending"

[[ -z $stamp ]] || { mkdir -p "$(dirname "$stamp")" && touch "$stamp"; }
printf '\nci: ok\n'
