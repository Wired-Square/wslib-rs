#!/bin/sh
# The publish token from 1Password as an Authorization value, so it never sits
# on disk.
set -eu
root=$(dirname "$0")/..
# shellcheck source=/dev/null
[ -f "$root/.env" ] && . "$root/.env"
token=$(op read --account "${WSLIB_OP_ACCOUNT:?set to the 1Password account that holds the publish token}" \
  "${WSLIB_REGISTRY_TOKEN_REF:?set to the op:// reference of your publish token}")
printf 'Bearer %s' "$token"
