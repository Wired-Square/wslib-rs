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

step "No consumer is named"
names=scripts/forbidden-names.txt
! git grep -nIiE --untracked -f "$names" -- ":!$names" || die "a consumer is named in the tree"
! git log --format=%B | grep -nIiE -f "$names" || die "a consumer is named in a commit message"

step "No reference to the project dossier"
! git grep -nIE --untracked '\[\[[A-Za-z][^]]*\]\]|wslib Plans' -- ':!scripts/ci.sh' ':!*.toml' ':!*.lock' || die "the dossier is cited; state the constraint here"

# Shared crates take no rustls provider; the app installs one.
step "No rustls provider by default"
! cargo tree --workspace -e normal -i aws-lc-rs >/dev/null 2>&1 || die "aws-lc-rs is in the default graph"
! cargo tree --workspace -e normal -i ring >/dev/null 2>&1 || die "ring is in the default graph"

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
  cargo clippy -p "$crate" --all-targets --locked -- -D warnings
  step "$crate: test"
  cargo test -p "$crate" --locked
  step "$crate: each feature"
  cargo hack check -p "$crate" --each-feature --no-dev-deps --locked
done

if $all; then
  step "Docs"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
  step "Check on the stated rust-version"
  msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)
  cargo "+$msrv" check --workspace --locked
fi

printf '\nci: ok\n'
