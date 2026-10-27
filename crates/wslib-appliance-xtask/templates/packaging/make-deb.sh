#!/bin/sh
# Builds {{name}}'s .deb, from the files `wslib-appliance-xtask packaging
# render` wrote beside this one.
#
#     CARGO_BUILD_TARGET=x86_64-unknown-linux-musl scaffold/packaging/make-deb.sh --target deb
#
# Chassis-owned, and rewritten unconditionally by every render. **There is no
# hook for the build itself, and that is deliberate**: this runs on a build host
# and has no deployment-time behaviour to extend. What a product ships beyond the
# binary is named in appliance.toml — `hooks_dir` and `[package.files]` — or
# placed where this script looks for it: the unit's `.service.d/*.conf`
# directory and the `debian/copyright` file. Anything else is a knob missing from
# appliance.toml.
set -eu

NAME='{{name}}'
BINARY='{{binary}}'

# The cargo package the `--bin` target lives in. The two are the same name in
# most products, and `cargo pkgid` fails loudly when they are not.
PACKAGE="${PACKAGE:-$BINARY}"

die() {
    echo "make-deb: $1" >&2
    exit 1
}

warn() {
    echo "make-deb: warning: $1" >&2
}

[ "$#" = 2 ] && [ "$1" = --target ] || die "usage: $0 --target deb"
TARGET=$2
[ "$TARGET" = deb ] || die "appliance.toml declares no target $TARGET — deb"

# The Rust target to build, and below, the Debian architecture it produces. It
# has no default: a host may be either architecture, so it is named. It takes
# cargo's environment variable name; `build.target` in a cargo config is not
# read.
[ -n "${CARGO_BUILD_TARGET:-}" ] ||
    die "--target deb needs CARGO_BUILD_TARGET set: x86_64-unknown-linux-musl for amd64, aarch64-unknown-linux-musl for arm64"

# Addressed from this script's own location, so it runs from anywhere:
# scaffold/packaging/make-deb.sh -> scaffold -> the repo root, which is where
# cargo is invoked.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCAFFOLD=$(dirname -- "$HERE")
cd -- "$(dirname -- "$SCAFFOLD")"

TARGET_SCAFFOLD="$SCAFFOLD/targets/$TARGET"
CONTROL_IN="$TARGET_SCAFFOLD/debian/control.in"
UNIT="$TARGET_SCAFFOLD/systemd/$NAME.service"
CONFIG="$TARGET_SCAFFOLD/debian/config.toml"
PACKAGE_CONFIG="$TARGET_SCAFFOLD/debian/package-config.toml"
# Under the product root, whatever `CARGO_TARGET_DIR` says.
OUT="target/debian/$TARGET"

# Passed to cargo rather than read back: a workspace member's default is the
# workspace's `target/`, not this product's.
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

# The build host is a Debian-ish one — `dpkg-deb` says so, and `install -D`,
# `du --exclude` and `date -R` below are GNU rather than POSIX.
for tool in cargo dpkg-deb wslib-appliance-xtask; do
    command -v "$tool" >/dev/null || die "$tool is not on PATH"
done

# The build and the checks on the binary, shared with make-image.sh.
. "$HERE/build-binary.sh"

# ---------------------------------------------------------------------------
# What is checked before anything is compiled
# ---------------------------------------------------------------------------
# A cross-build is minutes. Discovering afterwards that the unit starts a binary
# this package does not contain is discovering it slowly, so everything that can
# be answered from the rendered files is answered here.

[ -f "$CONTROL_IN" ] || die "$CONTROL_IN is not there — run \`wslib-appliance-xtask packaging render\`"
[ -f "$UNIT" ] || die "$UNIT is not there — run \`wslib-appliance-xtask packaging render\`"
[ -f "$CONFIG" ] || die "$CONFIG is not there — run \`wslib-appliance-xtask packaging render\`"
[ -f "$PACKAGE_CONFIG" ] || die "$PACKAGE_CONFIG is not there — run \`wslib-appliance-xtask packaging render\`"

# The unit and this script are rendered from one `binary` field, so a
# disagreement means one of them was edited — which is the question
# `wslib-appliance-xtask packaging diff` answers. `-x -F` rather than an
# anchored pattern, because a binary name legitimately contains `.` and `-`.
grep -q -x -F "ExecStart=/usr/bin/$BINARY" "$UNIT" ||
    die "$UNIT does not start /usr/bin/$BINARY — the unit and appliance.toml disagree"

# The three holes this script exists to fill. Checked rather than assumed: if
# wslib-appliance-xtask stopped emitting one, the substitution below would still
# succeed and produce a control file with no version in it, which is a gate
# that has quietly stopped matching anything.
for token in '@VERSION@' '@ARCH@' '@INSTALLED_SIZE@'; do
    grep -q -F "$token" "$CONTROL_IN" ||
        die "$CONTROL_IN has no $token — it came from a wslib-appliance-xtask this script does not match"
done

# The maintainer, which is also the changelog's trailer. The example
# appliance.toml carries a placeholder so a product has to name its own, and a
# package that still carries it is one nobody can send a bug report about.
MAINTAINER=$(sed -n 's/^Maintainer: //p' "$CONTROL_IN")
case "$MAINTAINER" in
*example.invalid*) die "package.maintainer in appliance.toml is still the example's placeholder — name this product's own maintainer" ;;
esac

# The target's package name. Only the .deb, its changelog and /usr/share/doc
# take it; every other shipped path keeps the system name.
DEB_PACKAGE=$(sed -n 's/^Package: //p' "$CONTROL_IN")
[ -n "$DEB_PACKAGE" ] || die "$CONTROL_IN has no Package: line"

{{ui_checks}}

{{consumer_checks}}

# The unit's real drop-ins, which ship; the `.sample` beside them does not. The
# name is held to a character set before the build, because a newline or a
# backslash in one is a name md5sums cannot carry — and a package-shipped
# drop-in has no reason to be called anything a keyboard would not type.
DROPINS="$SCAFFOLD/systemd/$NAME.service.d"
for conf in "$DROPINS"/*.conf; do
    [ -e "$conf" ] || continue
    case "${conf##*/}" in
    *[!A-Za-z0-9._-]*) die "$conf has a character in its name a shipped drop-in may not — letters, digits, \`.\`, \`_\` and \`-\`" ;;
    esac
    [ -f "$conf" ] || die "$conf is not a plain file, and a drop-in is one"
done

# The product's own DEP-5 copyright file, shipped to /usr/share/doc when it is
# there. A package without one installs; lintian objects, and a licence nobody
# can find is its own kind of problem.
[ -f "$SCAFFOLD/debian/copyright" ] ||
    warn "no $SCAFFOLD/debian/copyright — write a DEP-5 one and the next build ships it as /usr/share/doc/$DEB_PACKAGE/copyright"

binary_arch

# ---------------------------------------------------------------------------
# The version
# ---------------------------------------------------------------------------
# **Asked for rather than assembled here.** The `~`, the date leading the sha and
# the `.dirty` spelling are three ordering rules, and they live in
# `wslib-build-id` so this script and the binary's own --version cannot drift.
#
# A package is a snapshot sorting *below* the release it names, so a real release
# installs over a box running one.
#
# A plain assignment from a command substitution, so `set -e` sees the tool's
# refusal — it exits non-zero when the build has no commit to make a version
# from, which includes a build id supplied through the environment. Before the
# build, so a refusal costs nothing.
BASE_VERSION=$(cargo pkgid -p "$PACKAGE" | sed -e 's|.*[#@]||')
VERSION=$(wslib-appliance-xtask build-id --deb-version "$BASE_VERSION")

# ---------------------------------------------------------------------------
# The build, and the four assertions on the binary
# ---------------------------------------------------------------------------
build_binary

# ---------------------------------------------------------------------------
# Staging
# ---------------------------------------------------------------------------
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# **The staging root's own mode becomes the package's `./` entry, and dpkg
# applies that entry to `/`.** `mktemp -d` makes a 0700 directory, so without
# this the package asks dpkg to make the board's root directory unreadable to
# everyone but root — which is not a mistake anything downstream would catch.
#
# A debhelper-built package never meets this: its staging tree is made under the
# ordinary umask and is already 0755.
chmod 0755 "$STAGE"

install -D -m 0755 "$BIN" "$STAGE/usr/bin/$BINARY"

# `/usr/lib/systemd/system` rather than `/lib/systemd/system`: the release this
# chassis targets is usr-merged, and a package shipping into the aliased path is
# one dpkg has to reconcile against the symlink.
install -D -m 0644 "$UNIT" "$STAGE/usr/lib/systemd/system/$NAME.service"

{{ui_staging}}

# **This is where the mode that matters is set.** The mode inside the package is
# the only one that reaches the board — a mode in a consumer's working tree does
# not travel — and this one is load-bearing rather than tidy: dpkg-deb *refuses*
# a maintainer script outside 0555-0775 rather than fixing it, so getting this
# wrong is a failed build and never a bad package.
#
# It does not extend to `control` and `md5sums` below, whose modes dpkg-deb
# normalises to 0644 whatever the staging tree says. Setting those here would be
# a line that looks like this one and does nothing.
for script in postinst prerm postrm; do
    install -D -m 0755 "$TARGET_SCAFFOLD/debian/$script" "$STAGE/DEBIAN/$script"
done

# ---------------------------------------------------------------------------
# What the product ships beside the binary
# ---------------------------------------------------------------------------
# Every file under /etc is listed in DEBIAN/conffiles, so dpkg keeps an
# operator's edit across an upgrade and asks before replacing it. The list is
# appended to as each is staged.
CONFFILES="$STAGE/DEBIAN/conffiles"

# The bootstrap settings, with every listener and [tls] key in them commented.
# 0640 root:root here, so it is never world-readable; postinst gives a
# root-owned one the group, as it does the directory, so the daemon reads it.
install -D -m 0640 "$CONFIG" "$STAGE{{config_dir}}/config.toml"
printf '%s\n' '{{config_dir}}/config.toml' >> "$CONFFILES"

# The package's values from [targets.deb], beneath that file. Not a conffile:
# an upgrade replaces it, so a value [targets.deb] moves reaches a box whose
# operator kept their own config.toml. The unit names it.
install -D -m 0644 "$PACKAGE_CONFIG" "$STAGE/usr/share/$NAME/config.toml"

# The unit's drop-ins, checked above, under the directory a package's belong
# in — `/etc/systemd/system` is the operator's. A product with none stages none.
for conf in "$DROPINS"/*.conf; do
    [ -e "$conf" ] || continue
    install -D -m 0644 "$conf" "$STAGE/usr/lib/systemd/system/$NAME.service.d/${conf##*/}"
done

{{consumer_staging}}

# ---------------------------------------------------------------------------
# /usr/share/doc
# ---------------------------------------------------------------------------
# `copyright` is the product's own file, shipped as it is when it is there — a
# DEP-5 file names a copyright holder and a licence, which are not the chassis's
# to decide. The changelog is made here from the version this build is, because
# a hand-kept one and a snapshot version disagree from the second build on. It
# is `changelog.gz` rather than `changelog.Debian.gz`: a version with no Debian
# revision is a native package, and Policy 12.7 names a native one's that way.
DOC="$STAGE/usr/share/doc/$DEB_PACKAGE"
install -d -m 0755 "$DOC"
if [ -f "$SCAFFOLD/debian/copyright" ]; then
    install -m 0644 "$SCAFFOLD/debian/copyright" "$DOC/copyright"
fi
# Two statements rather than a pipeline, so `set -e` sees either fail. The
# maintainer was read and checked before the build. `-n`, so the archive
# carries no name or timestamp of its own.
printf '%s (%s) unstable; urgency=medium\n\n  * Snapshot build %s.\n\n -- %s  %s\n' \
    "$DEB_PACKAGE" "$VERSION" "$VERSION" "$MAINTAINER" "$(date -R)" > "$DOC/changelog"
gzip -9n "$DOC/changelog"
chmod 0644 "$DOC/changelog.gz"

# ---------------------------------------------------------------------------
# The control file
# ---------------------------------------------------------------------------
# `Installed-Size:` is an estimate, in KiB, of the space the installed package
# needs, and it does not count the control area. `dpkg-gencontrol` computes it
# for a package built the usual way; nothing in this pipeline is that, so it is
# computed here. Without it apt reports "0 B of additional disk space will be
# used" and its free-space check has nothing to work from — which on a small
# filesystem is the check you want.
INSTALLED_SIZE=$(du -k -s --exclude=DEBIAN "$STAGE" | cut -f1)

# **`du` is not the last stage of that pipeline, so `set -e` cannot see it fail.**
# `--exclude` is GNU-only, so a BSD `du` exits 1, `cut` succeeds on nothing, the
# substitution fills the token with an empty string, the "nothing left unfilled"
# grep passes because the token *was* replaced, and dpkg-deb builds a package whose
# `Installed-Size:` is blank — the state the field exists to prevent.
case "$INSTALLED_SIZE" in
'' | *[!0-9]*)
    die "Installed-Size came out as '$INSTALLED_SIZE' — \`du -k -s --exclude=DEBIAN\` did not produce a number, and set -e cannot see a pipeline stage that is not the last"
    ;;
esac

sed -e "s|@VERSION@|$VERSION|g" \
    -e "s|@ARCH@|$ARCH|g" \
    -e "s|@INSTALLED_SIZE@|$INSTALLED_SIZE|g" \
    "$CONTROL_IN" > "$STAGE/DEBIAN/control"

# Nothing may be left unfilled, which is the rule wslib-appliance-xtask holds its
# own placeholders to, applied to the layer below it. dpkg-deb is not a backstop
# here: it refuses an unfilled `@VERSION@`, only *warns* about `@ARCH@` and
# builds anyway, and takes `@INSTALLED_SIZE@` as an ordinary field value in
# silence.
if grep -q -E '@[A-Z_]+@' "$STAGE/DEBIAN/control"; then
    die "$STAGE/DEBIAN/control still has an unfilled token in it"
fi

# What `dpkg --verify` reads. Paths are relative to the filesystem root with no
# leading `./`, and the control area is not listed.
#
# **NUL-separated on the way in**, because a browser bundle carries whatever a
# product's `public/` directory does: `Inter Regular.woff2` splits on the space and
# xargs reports a file called `Inter`, and `dont'panic.svg` is an unterminated
# quote. Both abort the build after the cross-build is already paid for.
#
# **Line-based on the way out.** dpkg's md5sums format is one record per line, so a
# name this pipeline could not carry has already been refused — which means NULs
# past this point buy nothing.
#
# The `./` comes off md5sum's *output* rather than the paths going in, so the match
# is anchored on the two-space separator that format uses rather than on the start
# of the line, where the digest is. Hex cannot contain `/`, so the leftmost `  ./`
# is always the separator, including on the `\`-prefixed lines md5sum writes for an
# escaped name.
(
    cd "$STAGE" && find . -type f ! -path './DEBIAN/*' -print0 |
        LC_ALL=C sort -z | xargs -0 md5sum | sed 's|  \./|  |' > DEBIAN/md5sums
)

# **Every stage of a pipeline but the last is invisible to `set -e`**, and that one
# has four. Counting what came out against what was staged is the only thing here
# that catches a stage that failed silently.
#
# `wc -l` counts lines rather than files, which is right *because* a name with a
# newline was refused before the build. Those two facts are one decision, and
# moving either alone makes this count lie.
STAGED=$(cd "$STAGE" && find . -type f ! -path './DEBIAN/*' | wc -l | tr -d '[:space:]')
LISTED=$(wc -l < "$STAGE/DEBIAN/md5sums" | tr -d '[:space:]')
[ "$STAGED" -eq "$LISTED" ] ||
    die "DEBIAN/md5sums lists $LISTED of $STAGED staged files — either a stage of the pipeline that writes it failed, which set -e cannot see, or a staged name holds a newline and this format cannot carry it"

# ---------------------------------------------------------------------------
# The package
# ---------------------------------------------------------------------------
mkdir -p "$OUT"
DEB="$OUT/${DEB_PACKAGE}_${VERSION}_${ARCH}.deb"

# **`--root-owner-group`**, or every path in the package is owned by whichever
# uid the build host happened to run as — which arrives on the board as a
# numeric owner that means something there and nothing here.
dpkg-deb --root-owner-group --build "$STAGE" "$DEB"

echo "built $DEB"
