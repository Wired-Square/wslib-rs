#!/bin/sh
# Cargo credential provider: the registry token straight from 1Password, so it
# is never in the environment of build scripts or tests.
set -eu
root=$(dirname "$0")/..
# shellcheck source=/dev/null
[ -f "$root/.env" ] && . "$root/.env"
token=$(op read "${WSLIB_REGISTRY_TOKEN_REF:?set to the op:// reference of your publish token}")
printf 'Bearer %s' "$token"
