#!/usr/bin/env bash
# The CI definition. A future Actions workflow calls this rather than restating it.
# Everyday: workspace-wide cheap gates, then per-crate checks on crates changed
# since their last release tag plus their reverse dependencies. --tag: every crate,
# once per clean commit.
#
#   scripts/ci.sh [--tag]
set -euo pipefail
cd "$(dirname "$0")/.."

all=false
[[ ${1:-} == --tag ]] && all=true

die() { printf 'ci: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

stamp=
if $all && [[ -z $(git status --porcelain) ]]; then
  stamp="${CARGO_TARGET_DIR:-target}/ci-tag-passed/$(git rev-parse HEAD)"
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
# Clippy and check need no object code, and sqlite3.c cannot be cross-compiled for msvc off Windows.
stubs=
if $cross_windows; then
  stubs=$(mktemp -d)
  trap 'rm -rf "$stubs"' EXIT
  printf '#!/bin/sh\nfor a; do case $a in -out:*) touch "${a#-out:}";; esac; done\n' >"$stubs/ar"
  chmod +x "$stubs/ar"
  export CC_x86_64_pc_windows_msvc=true AR_x86_64_pc_windows_msvc="$stubs/ar"
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
graph=$(cargo tree -p wslib-telemetry --no-default-features --features setup-core -e normal --prefix none)
! grep -E '^(regex|regex-automata|matchers) ' <<<"$graph" || die "setup-core pulls in a regex engine"

# A desktop app takes wslib-appliance-client alone, or the facade with only
# `client`; --target all covers the Windows graph.
step "wslib-appliance-client carries no server stack"
for graph in "-p wslib-appliance-client" "-p wslib-appliance --no-default-features --features client"; do
  read -ra args <<<"$graph"
  tree=$(cargo tree "${args[@]}" --target all -e normal --prefix none --locked)
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

crates() {
  cargo metadata --format-version 1 --no-deps --locked \
    | jq -r --argjson all "$all" '
        .packages as $p
        | ($p | map(.name)) as $names
        | def changed($n): $all or ($n | IN($ENV.CHANGED | split(" ")[]));
          def rdeps($n): [$p[] | select(any(.dependencies[]; .name == $n)) | .name];
          def dependants: (. + map(rdeps(.)[]) | unique) as $next
            | if $next == . then . else $next | dependants end;
          [$names[] | select(changed(.))] | unique | dependants | .[]'
}

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

selected=$(crates)
if [[ -n $selected ]]; then
  step Clippy: $selected
  cargo clippy $(printf -- ' -p %s' $selected) --all-targets --all-features --locked -- -D warnings
fi

# Per crate: built together, features unify, so a sibling's can mask a missing one
# or add a second rustls provider that a test's process default can't choose between.
for crate in $selected; do
  step "$crate: test"
  cargo test -p "$crate" --all-features --locked
  step "$crate: each feature"
  cargo hack check -p "$crate" --each-feature --locked
done

# A read-only build takes `tcp` or `task` without `write`; wslib-modbus's
# compile_fail doctests fail if a write path is compiled into either. A sans-io
# consumer takes its RTU side with no features.
if grep -qx wslib-modbus <<<"$selected"; then
  step "wslib-modbus without write has no write path"
  for features in tcp task; do
    cargo test -p wslib-modbus --no-default-features --features "$features" --doc --locked
  done
  step "wslib-modbus without features has no tokio"
  tree=$(cargo tree -p wslib-modbus --no-default-features -e normal --prefix none --locked)
  ! grep -E '^tokio(-modbus)? ' <<<"$tree" || die "wslib-modbus pulls in tokio without a feature"
fi

# A read-only port on Linux needs neither serialport nor libudev.
if grep -qx wslib-serial <<<"$selected"; then
  step "wslib-serial's task has no serialport on Linux"
  tree=$(cargo tree -p wslib-serial --no-default-features --features task -e normal --prefix none \
    --target x86_64-unknown-linux-gnu --locked)
  ! grep -E '^(serialport|libudev(-sys)?) ' <<<"$tree" || die "wslib-serial's task pulls in serialport on Linux"
fi

windows_only() {
  cargo metadata --format-version 1 --no-deps --locked \
    | jq -r --arg among "$*" '.packages[] | select(.name | IN($among | split(" ")[]))
        | select(any(.dependencies[]; .target // "" | test("windows"))) | .name'
}

# A build on this host skips cfg(windows) code, and a crate breaks on Windows without
# any Windows-only dependency.
windows=
! $cross_windows || windows=$selected
if [[ -n $windows ]]; then
  step "Clippy for $win:" $windows
  cargo clippy $(printf -- ' -p %s' $windows) --target $win --all-features --locked -- -D warnings
fi

if $all; then
  step "Docs"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
  step "Check on the stated rust-version"
  msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)
  cargo "+$msrv" check --workspace --locked

  # Per crate: one lock can't hold every crate's floors at once.
  step "Dependency floors"
  # A Windows-only dependency's floor is resolved only for Windows.
  windows_deps=$(! $cross_windows || windows_only $selected)
  floors=$(mktemp -d)
  trap 'rm -rf "$floors" ${stubs:+"$stubs"}' EXIT
  git ls-files -z -co --exclude-standard \
    | while IFS= read -r -d '' f; do [[ -e $f ]] && printf '%s\0' "$f"; done \
    | tar -c --null -T - | tar -x -C "$floors"
  for dir in crates/*/; do
    name=$(basename "$dir")
    sed -i.bak "s|^members = .*|members = [\"crates/$name\"]|" "$floors/Cargo.toml"
    rm -f "$floors/Cargo.lock"
    pins=$(sed -n "s/^$name \([^ ]*\)@\([^ ]*\)$/\1 \2/p" scripts/floor-pins.txt 2>/dev/null)
    (cd "$floors" && cargo +nightly update -Z direct-minimal-versions -q \
      && while read -r package version; do
           [[ -z $package ]] || cargo +nightly update -q -p "$package" --precise "$version"
         done <<<"$pins" \
      && cargo +nightly check --workspace --all-features --all-targets -q \
      && { ! grep -qx "$name" <<<"$windows_deps" \
           || cargo +nightly check --target $win --workspace --all-features -q; }) \
      || die "$name does not build at its dependency floors"
  done
fi

[[ -z $stamp ]] || { mkdir -p "$(dirname "$stamp")" && touch "$stamp"; }
printf '\nci: ok\n'
