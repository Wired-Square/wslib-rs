#!/bin/sh
# cargo release with the publish token from 1Password; reads elsewhere use
# the read token in ~/.cargo/credentials.toml.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
CARGO_REGISTRIES_WIRED_SQUARE_CREDENTIAL_PROVIDER="cargo:token-from-stdout $root/scripts/registry-token.sh" \
	exec cargo release "$@"
