#!/bin/sh
# Builds {{name}}'s container image as a tarball for `docker load`, from the
# files `wslib-appliance-xtask packaging render` wrote beside this one.
#
#     CARGO_BUILD_TARGET=aarch64-unknown-linux-musl scaffold/packaging/make-image.sh
#
# One architecture per run: a `docker load` tarball cannot hold a list of them.
# Owned by wslib-appliance-xtask, and rewritten unconditionally by every render;
# what the image is follows from appliance.toml and manifest.json.
set -eu

NAME='{{name}}'
BINARY='{{binary}}'
REPOSITORY='{{repository}}'
VERSION='{{version}}'
ARCHES='{{arches}}'

# The cargo package the `--bin` target lives in, as make-deb.sh takes it.
PACKAGE="${PACKAGE:-$BINARY}"

die() {
    echo "make-image: $1" >&2
    exit 1
}

[ "$#" = 0 ] || die "usage: CARGO_BUILD_TARGET=<triple> $0"
[ -n "${CARGO_BUILD_TARGET:-}" ] ||
    die "CARGO_BUILD_TARGET is not set: x86_64-unknown-linux-musl for amd64, aarch64-unknown-linux-musl for arm64"

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCAFFOLD=$(dirname -- "$HERE")
cd -- "$(dirname -- "$SCAFFOLD")"

DOCKERFILE="$SCAFFOLD/targets/docker/Dockerfile"
OUT="target/docker"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

for tool in cargo docker wslib-appliance-xtask; do
    command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
docker buildx version >/dev/null 2>&1 || die "docker buildx is not installed"
[ -f "$DOCKERFILE" ] || die "$DOCKERFILE is not there — run \`wslib-appliance-xtask packaging render\`"

# The tag, the OCI version label and the binary's --version are one version.
PKGID=$(cargo pkgid -p "$PACKAGE")
CRATE_VERSION=${PKGID##*[#@]}
[ "$VERSION" = "$CRATE_VERSION" ] ||
    die "the rendered version is $VERSION and $PACKAGE's is $CRATE_VERSION — set manifest.json's version to the crate's and run \`wslib-appliance-xtask packaging render\`"

. "$HERE/build-binary.sh"

{{ui_checks}}

binary_arch
case " $ARCHES " in
*" $ARCH "*) ;;
*) die "manifest.json does not list $ARCH among its arches ($ARCHES)" ;;
esac

build_binary

mkdir -p "$OUT"
IMAGE="$OUT/$NAME-$VERSION-$ARCH.tar"

# What the Dockerfile copies from: the binary, the bundle, and the empty
# directories each volume, its parent and the console's socket directory are
# made from.
CONTEXT=$(mktemp -d)
trap 'rm -rf "$CONTEXT" "$IMAGE.part"' EXIT
trap 'exit 1' INT TERM HUP
mkdir "$CONTEXT/bin"
cp "$BIN" "$CONTEXT/bin/$BINARY"
mkdir -p {{volume_dirs}} "$CONTEXT/sock/appliance" "$CONTEXT/empty"

{{ui_staging}}

# A builder of this script's own: the docker driver cannot write a `docker load`
# tarball on the classic image store.
BUILDER=appliance-image
docker buildx inspect "$BUILDER" >/dev/null 2>&1 ||
    docker buildx create --name "$BUILDER" --driver docker-container >/dev/null 2>&1 ||
    docker buildx inspect "$BUILDER" >/dev/null

docker buildx build --builder "$BUILDER" --platform "linux/$ARCH" --file "$DOCKERFILE" \
    --tag "$REPOSITORY:$VERSION" --output "type=docker,dest=$IMAGE.part" "$CONTEXT"
mv "$IMAGE.part" "$IMAGE"

echo "built $IMAGE"
