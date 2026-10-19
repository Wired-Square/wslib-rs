#!/usr/bin/env bash
# The CI definition. A future Actions workflow calls this rather than restating it.
# Everyday: workspace-wide cheap gates, then per-crate checks on crates changed
# since their last release tag plus their reverse dependencies. --tag: every crate.
#
#   scripts/ci.sh [--tag]
set -euo pipefail
cd "$(dirname "$0")/.."

all=false
[[ ${1:-} == --tag ]] && all=true

die() { printf 'ci: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

command -v cargo-hack >/dev/null || die "cargo-hack missing: cargo install cargo-hack"
! $all || cargo +nightly --version >/dev/null 2>&1 || die "nightly missing: rustup toolchain install nightly"

step "No consumer is named"
names=scripts/forbidden-names.txt
! git grep -nIiE --untracked -f "$names" -- ":!$names" || die "a consumer is named in the tree"
! git log --format=%B | grep -nIiE -f "$names" || die "a consumer is named in a commit message"

step "No reference to the project dossier"
! git grep -nIE --untracked '\[\[[A-Za-z][^]]*\]\]|wslib Plans' -- ':!scripts/ci.sh' ':!*.toml' ':!*.lock' || die "the dossier is cited; state the constraint here"

# Shared crates take no rustls provider; the app installs one.
step "No rustls provider by default"
# A package can be resolved without any edge to it, so look for a printed tree
# rather than trusting the exit status.
in_default_graph() { cargo tree --workspace -e normal -i "$1" 2>/dev/null | grep -q .; }
! in_default_graph aws-lc-rs || die "aws-lc-rs is in the default graph"
! in_default_graph ring || die "ring is in the default graph"

step "wslib-telemetry's setup-core has no regex engine"
! cargo tree -p wslib-telemetry --no-default-features --features setup-core -e normal --prefix none \
  | grep -qE '^(regex|regex-automata|matchers) ' || die "setup-core pulls in a regex engine"

step "Format"
cargo fmt --all --check

step "Check"
cargo check --workspace --all-targets --locked

crates() {
  cargo metadata --format-version 1 --no-deps --locked \
    | jq -r --argjson all "$all" '
        .packages as $p
        | ($p | map(.name)) as $names
        | def changed($n): $all or ($n | IN($ENV.CHANGED | split(" ")[]));
          def rdeps($n): [$p[] | select(any(.dependencies[]; .name == $n)) | .name];
          [$names[] | select(changed(.))] as $seed
          | [$seed, ($seed | map(rdeps(.)) | add // [])] | add | unique | .[]'
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

for crate in $(crates); do
  step "$crate: clippy"
  cargo clippy -p "$crate" --all-targets --all-features --locked -- -D warnings
  step "$crate: test"
  cargo test -p "$crate" --all-features --locked
  step "$crate: each feature"
  cargo hack check -p "$crate" --each-feature --locked
done

if $all; then
  step "Docs"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
  step "Check on the stated rust-version"
  msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)
  cargo "+$msrv" check --workspace --locked

  # Per crate: one lock can't hold every crate's floors at once.
  step "Dependency floors"
  floors=$(mktemp -d)
  trap 'rm -rf "$floors"' EXIT
  git ls-files -z -co --exclude-standard | tar -c --null -T - | tar -x -C "$floors"
  for dir in crates/*/; do
    name=$(basename "$dir")
    sed -i.bak "s|^members = .*|members = [\"crates/$name\"]|" "$floors/Cargo.toml"
    rm -f "$floors/Cargo.lock"
    (cd "$floors" && cargo +nightly update -Z direct-minimal-versions -q \
      && cargo +nightly check --workspace --all-features --all-targets -q) \
      || die "$name does not build at its dependency floors"
  done
fi

printf '\nci: ok\n'
