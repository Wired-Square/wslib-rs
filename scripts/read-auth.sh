#!/bin/sh
# The wired-square read token from cargo's credentials.toml, as an
# Authorization header line for curl -H @file.
set -eu
line=$(awk '/^\[/ { here = $0 == "[registries.wired-square]" }
  here && /^token *=/ { sub(/^token *= *"/, ""); sub(/".*/, ""); print "Authorization: " $0; exit }' \
  "${CARGO_HOME:-$HOME/.cargo}/credentials.toml" 2>/dev/null) || true
[ -n "$line" ] || { printf 'no wired-square read token in credentials.toml\n' >&2; exit 1; }
printf '%s\n' "$line"
