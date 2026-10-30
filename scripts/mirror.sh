#!/usr/bin/env bash
# Copies every crate in a Forgejo Cargo registry to a read-only mirror. Index
# files are replaced; a .crate already on the mirror is never rewritten.
# Reads with the read token in ~/.cargo/credentials.toml; settings come from
# .env (see .env.example).
#
#   scripts/mirror.sh [--dry-run]
set -euo pipefail
cd "$(dirname "$0")/.."
die() { printf 'mirror: %s\n' "$*" >&2; exit 1; }

# shellcheck source=/dev/null
[[ -f .env ]] && . ./.env

forge=${WSLIB_FORGE_URL:?set in .env}
owner=${WSLIB_FORGE_OWNER:?set in .env}
dest=${WSLIB_MIRROR_DEST:?set in .env}
[[ $dest == *[:/] ]] || die "WSLIB_MIRROR_DEST must end in : or /"
index=$forge/api/packages/$owner/cargo
rsync_opts=(-rtp)
[[ ${1:-} == --dry-run ]] && rsync_opts+=(--dry-run --itemize-changes)

index_path() {
  local n
  n=$(tr "[:upper:]" "[:lower:]" <<<"$1")
  case ${#n} in
    1) echo "1/$n" ;;
    2) echo "2/$n" ;;
    3) echo "3/${n:0:1}/$n" ;;
    *) echo "${n:0:2}/${n:2:2}/$n" ;;
  esac
}

# Cargo appends /{crate}/{version}/download when `dl` has no placeholders.
crate_url() {
  if [[ $dl == *\{* ]]; then
    local url=${dl//\{crate\}/$1}
    echo "${url//\{version\}/$2}"
  else
    echo "$dl/$1/$2/download"
  fi
}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# A header file rather than an argument, which `ps` would show.
scripts/read-auth.sh >"$stage/auth"
get() { curl -fsS -H "@$stage/auth" "$@"; }

dl=$(get "$index/config.json" | jq -r .dl)
names=$(
  for page in $(seq 1 100); do
    batch=$(get "$forge/api/v1/packages/$owner?type=cargo&limit=50&page=$page" | jq -r '.[].name')
    [[ -z $batch ]] && break
    echo "$batch"
  done | sort -u
)
[[ -n $names ]] || die "the registry lists no crates"

for name in $names; do
  path=$(index_path "$name")
  mkdir -p "$stage/index/$(dirname "$path")" "$stage/crates/$name"
  get "$index/$path" -o "$stage/index/$path"
  while read -r vers cksum; do
    file=$stage/crates/$name/$name-$vers.crate
    get "$(crate_url "$name" "$vers")" -o "$file"
    [[ $(shasum -a 256 "$file" | cut -d' ' -f1) == "$cksum" ]] || die "$name $vers does not match its index checksum"
  done < <(jq -r '"\(.vers) \(.cksum)"' "$stage/index/$path")
  printf 'mirror: %s\n' "$name"
done

# Modes travel with -p, because the receiver otherwise makes new files 0600. openrsync has no --chmod.
chmod -R u=rwX,go=rX "$stage/crates" "$stage/index"
rsync "${rsync_opts[@]}" --ignore-existing "$stage/crates/" "${dest}crates/"
rsync "${rsync_opts[@]}" "$stage/index/" "$dest"
