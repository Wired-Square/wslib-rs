#!/bin/sh
# Tags the crates named <crate>-v<version>, pushes the tags, then publishes
# from main with the publish token from 1Password and mirrors the registry; the
# index is read with the read token in ~/.cargo/credentials.toml. With no crate
# named it lists those the registry lacks. Without --execute it stops before
# tagging, and with --no-mirror after publishing.
#
#   scripts/release.sh <crate> ... [--execute] [--no-mirror]
set -eu
cd "$(dirname "$0")/.."
die() { printf 'release: %s\n' "$*" >&2; exit 1; }
say() { printf 'release: %s\n' "$*"; }
# shellcheck source=/dev/null
[ -f .env ] && . ./.env

execute=false mirror=true names=
for arg; do
  case $arg in
    --execute) execute=true ;;
    --no-mirror) mirror=false ;;
    -*) die "unknown option $arg" ;;
    *) [ -f "crates/$arg/Cargo.toml" ] || die "no crate at crates/$arg"; names="$names $arg" ;;
  esac
done

[ "$(git branch --show-current)" = main ] || die "release from main, after the PR is merged"
[ -z "$(git status --porcelain)" ] || die "commit or stash first"
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main is not origin/main"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
umask 077

index=${WSLIB_FORGE_URL:?set in .env}/api/packages/${WSLIB_FORGE_OWNER:?set in .env}/cargo
# A header file rather than an argument, which `ps` would show.
awk '/^\[/ { here = $0 == "[registries.wired-square]" }
  here && /^token *=/ { sub(/^token *= *"/, ""); sub(/".*/, ""); print "Authorization: " $0; exit }' \
  "${CARGO_HOME:-$HOME/.cargo}/credentials.toml" >"$stage/auth" 2>/dev/null || true
[ -s "$stage/auth" ] || die "no wired-square read token in credentials.toml"

cargo metadata --no-deps --format-version 1 --locked >"$stage/meta"
version() { jq -r --arg n "$1" '.packages[] | select(.name == $n) | .version' "$stage/meta"; }
tag() { echo "$1-v$(version "$1")"; }
index_path() {
  n=$(printf %s "$1" | tr '[:upper:]' '[:lower:]')
  case ${#n} in
    1) echo "1/$n" ;;
    2) echo "2/$n" ;;
    3) echo "3/$(echo "$n" | cut -c1)/$n" ;;
    *) echo "$(echo "$n" | cut -c1-2)/$(echo "$n" | cut -c3-4)/$n" ;;
  esac
}
on_registry() {
  code=$(curl -sS -H "@$stage/auth" -o "$stage/entry" -w '%{http_code}' "$index/$(index_path "$1")") \
    || die "could not read the index for $1"
  case $code in
    200) jq -e --arg v "$(version "$1")" 'select(.vers == $v)' "$stage/entry" >/dev/null ;;
    404) return 1 ;;
    *) die "the index answered $code for $1" ;;
  esac
}

if [ -z "$names" ]; then
  unreleased=
  for name in $(jq -r '.packages[] | select(.publish != []) | .name' "$stage/meta"); do
    on_registry "$name" || unreleased="$unreleased $name"
  done
  die "name the crates to release; not on the registry:${unreleased:- none}"
fi

packages=
for name in $names; do
  version=$(version "$name")
  ! on_registry "$name" || die "$name $version is already on the registry"
  ! git rev-parse -q --verify "refs/tags/$(tag "$name")" >/dev/null || die "$(tag "$name") already exists"
  grep -qx "## $version" "crates/$name/CHANGELOG.md" || die "crates/$name/CHANGELOG.md has no heading for $version"
  packages="$packages -p $name"
done

# Dependencies first, one crate per publish, so a failure leaves a known set
# published.
names=$(jq -r --arg names "$names" '
  ($names | split(" ") | map(select(. != ""))) as $want
  | [.packages[] | select(.name | IN($want[]))
      | {name, deps: [.dependencies[] | select(.path != null) | .name | select(IN($want[]))]}]
  | def order($done):
      if length == 0 then $done[]
      else (map(select(.deps - $done == [])) | map(.name)) as $ready
        | if $ready == [] then error("the crates named depend on each other in a cycle")
          else map(select(.name | IN($ready[]) | not)) | order($done + $ready) end
      end;
    order([])' "$stage/meta" | sed 's/^/ /' | tr -d '\n')
[ -n "$names" ] || die "could not order the crates named"
tags=
for name in $names; do tags="$tags $(tag "$name")"; done

# Read before the CI run so a wrong setting fails at once. Never exported, so
# nothing the run starts sees it.
if $execute; then
  token=$(scripts/registry-token.sh) || die "could not read the publish token"
fi

log=$(mktemp "${TMPDIR:-/tmp}/release-ci.XXXXXX")
say "releasing$names; ci.sh --tag logs to $log"
scripts/ci.sh --tag >"$log" 2>&1 || { tail -n 40 "$log" >&2; die "ci.sh --tag failed; the full log is $log"; }

# Packaging builds each crate, so it runs here without the token and the
# publish skips its own build.
# shellcheck disable=SC2086
cargo package --locked --registry wired-square $packages >>"$log" 2>&1 \
  || { tail -n 40 "$log" >&2; die "cargo package failed; the full log is $log"; }
$execute || { say "dry run; would publish in order$names"; rm "$log"; exit 0; }

for name in $names; do
  git tag -s -m "$name $(version "$name")" "$(tag "$name")"
done
# Pushed before publishing, so nothing is ever published without its tag on
# main.
# shellcheck disable=SC2086
git push -q origin $tags >>"$log" 2>&1 || { git tag -d $tags >/dev/null; die "pushing$tags failed, so nothing is published; see $log"; }
say "pushed$tags"

pending=$tags
for name in $names; do
  if ! CARGO_REGISTRIES_WIRED_SQUARE_TOKEN=$token cargo publish --locked --no-verify --registry wired-square \
    -p "$name" >>"$log" 2>&1; then
    # shellcheck disable=SC2086
    git tag -d $pending >/dev/null
    # shellcheck disable=SC2086
    git push -q origin --delete $pending >>"$log" 2>&1 || say "withdrawing$pending from origin failed; delete them there"
    [ "$pending" = "$tags" ] || ! $mirror || scripts/mirror.sh
    die "publishing $name failed, so$pending are withdrawn; see $log"
  fi
  say "published $name $(version "$name")"
  pending=${pending#" $(tag "$name")"}
done
! $mirror || scripts/mirror.sh
rm "$log"
