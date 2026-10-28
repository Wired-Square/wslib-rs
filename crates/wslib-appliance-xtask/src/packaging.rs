//! The build-host scripts: `make-deb.sh`, which turns a checkout into a `.deb`;
//! `build-binary.sh`, the cross-build and the checks on the binary, which
//! `make-deb.sh` and `make-image.sh` share; and `build-id.sh`, which carries a
//! build's identity to a machine that cannot read git for itself.
//!
//! None is a hook site: what a product ships through them is named in
//! `appliance.toml`, each knob rendered as a block decided here. `make-deb.sh`
//! asks this tool for the version and never spells the format itself, and
//! stages the bundle where `wslib_appliance_config::default_ui_dir` says.

use std::collections::BTreeMap;

use crate::model::{Checked, is_conffile};
use crate::render::{Artefact, RenderError, fixed};

const MAKE_DEB: &str = include_str!("../templates/packaging/make-deb.sh");
const BUILD_ID: &str = include_str!("../templates/packaging/build-id.sh");
const BUILD_BINARY: &str = include_str!("../templates/packaging/build-binary.sh");

/// The build-host scripts, rendered for one product: `make-deb.sh` when it
/// declares the package.
pub fn artefacts(checked: &Checked) -> Result<Vec<Artefact>, RenderError> {
    let app = &checked.appliance;
    let mut artefacts = fixed(
        &[
            ("packaging/build-binary.sh", BUILD_BINARY),
            ("packaging/build-id.sh", BUILD_ID),
        ],
        &[
            ("name", app.name.clone()),
            ("min_binary_bytes", app.package.min_binary_bytes.to_string()),
        ],
    )?;
    if app.targets.deb.is_some() {
        artefacts.extend(make_deb(checked)?);
    }
    Ok(artefacts)
}

fn make_deb(checked: &Checked) -> Result<Vec<Artefact>, RenderError> {
    let app = &checked.appliance;
    let (ui_checks, ui_staging) = bundle_blocks(app.package.ui_dist.as_deref());
    let (checks, staging): (Vec<String>, Vec<String>) = [
        hooks_blocks(app.package.hooks_dir.as_deref()),
        files_blocks(&app.package.files),
    ]
    .into_iter()
    .unzip();
    let values = vec![
        ("name", app.name.clone()),
        ("binary", app.binary.clone()),
        ("config_dir", app.config_dir.display().to_string()),
        ("ui_checks", ui_checks),
        ("ui_staging", ui_staging),
        ("consumer_checks", checks.join("\n\n")),
        ("consumer_staging", staging.join("\n\n")),
    ];

    fixed(&[("packaging/make-deb.sh", MAKE_DEB)], &values)
}

/// What `make-deb.sh` says about a browser bundle: what it checks before the
/// cross-build, and what it stages afterwards. `make-image.sh` makes the same
/// checks. A headless render carries no `cp` and no `UI_DIST` at all, rather
/// than a guard around them.
pub(crate) fn bundle_blocks(dist: Option<&str>) -> (String, String) {
    let Some(dist) = dist else {
        return (
            "# **No browser bundle**, because `appliance.toml` names no `ui_dist`. That is a\n\
             # shape a product can have rather than an omission: the daemon serves its API and\n\
             # answers an `ApiError` for everything else: the one error body, or a page to a\n\
             # browser navigation. Naming a `ui_dist` is what changes it, and nothing in this\n\
             # file wants editing."
                .to_string(),
            "# Nothing is staged under /usr/share: this product has no browser half.".to_string(),
        );
    };

    let checks = format!(
        r#"# The bundle, before the cross-build.
UI_DIST='{dist}'
[ -d "$UI_DIST" ] ||
    die "$UI_DIST is not there — build the browser bundle first, or remove ui_dist from appliance.toml if this appliance has no browser half"

# **index.html is what every client-side route is answered with**, because the
# routes the browser shows exist only in the bundle and a plain file server 404s
# all of them. A directory without one is not a built bundle, and what it makes
# on a box is an appliance whose API works perfectly and whose every page is a
# 404.
[ -f "$UI_DIST/index.html" ] ||
    die "$UI_DIST has no index.html — that is what the daemon answers every page route with, so this is not a built bundle"

# **A source directory passes both checks above.** A product's vite root has an
# index.html by construction, so `ui_dist = "ui"` where `ui/dist` was meant ships
# `.env`, `.env.local` and every source file into a directory the appliance
# serves to anybody who can reach the port, with no credential. These three
# markers do not appear in build output and are conclusive when they do appear.
#
# Each name is quoted, and `.git` has to be: `no_build_script_reimplements_the_
# version_format` greps these scripts for `git ` to catch one working out its own
# version in shell, and an unquoted `-name .git -o` is that string. Quoting is
# right anyway; the gate is why it is not optional.
SOURCEY=$(find "$UI_DIST/." \( -name '.git' -o -name 'node_modules' -o -name '.env*' \) )
[ -z "$SOURCEY" ] ||
    die "$UI_DIST looks like a source directory rather than build output, and everything in it would be served unauthenticated — name the directory your bundler writes: $SOURCEY"

# **Plain files and directories, and nothing else.** A symlink is the member
# everybody thinks of: `cp -R` recreates one rather than following it, a package
# or an image ships it, and the daemon follows it on the box — tower-http's
# ServeDir has no symlink handling of any kind, it builds the path a component
# at a time, refusing `..` and absolute components, then opens it, which follows
# links the way open(2) does. So a link here is a served path resolving
# somewhere nobody shipped, or nowhere at all. Copying with `-L` instead would be
# worse: it pulls whatever the link points at into what ships.
#
# **The test is the whole class rather than that one member**, because the
# sentence above was written as "a bundle is plain files" while the check said
# `-type l`, and a FIFO slips between the two: `cp -R` recreates it, both chmod
# passes skip it, a package's md5sums pass skips it, and `ServeDir` opening it
# for read blocks that request for ever. One predicate that matches the prose.
#
# `$UI_DIST/.` and not `$UI_DIST`, because find does not follow the starting
# operand — so the bare form reports a bundle directory that is *itself* a
# symlink as its own contents, which an ordinary monorepo layout produces.
ODD=$(find "$UI_DIST/." ! -type f ! -type d)
[ -z "$ODD" ] ||
    die "$UI_DIST holds something that is not a plain file or a directory, and a bundle is plain files — a symlink the appliance's file server would follow off the tree, or a FIFO that would hang the request that opened it: $ODD"

# **Names dpkg's md5sums can carry**, refused for an image too, so that one
# bundle ships to either target. That file is one record per line, and GNU
# md5sum escapes a name holding a backslash by prefixing the whole line with `\`
# — which dpkg refuses with "control file 'md5sums' … is missing value
# separator", killing `dpkg --verify` for the *entire package* rather than for
# that one file. It is silent at build time and loud on the board, which is the
# wrong way round, so it is refused here where the message can name the file.
BACKSLASHED=$(find "$UI_DIST/." -name '*\\*')
[ -z "$BACKSLASHED" ] ||
    die "a name in $UI_DIST has a backslash in it, which dpkg's md5sums format cannot carry — rename it: $BACKSLASHED"

# A newline is the other name that format cannot carry, and it is the one that
# would make the md5sums count *lie* rather than fail — that count is `wc -l`.
# Counted rather than matched, because there is no `-name` pattern for a newline:
# one line per entry only holds while no entry has one in it.
LINES=$(find "$UI_DIST/." | wc -l | tr -d '[:space:]')
ENTRIES=$(find "$UI_DIST/." -print0 | tr -cd '\000' | wc -c | tr -d '[:space:]')
[ "$LINES" -eq "$ENTRIES" ] ||
    die "a name in $UI_DIST has a newline in it, which dpkg's md5sums format cannot carry"

# **A `.gz` is sent in place of the file beside it** to every browser that takes
# gzip, so it has to be that file. A build step that edits the output after the
# `.gz` was written leaves the old copy. A `.gz` with nothing beside it is a file
# of its own and ships as one.
STALE=$(find "$UI_DIST/." -type f -name '*.gz' | while IFS= read -r gz; do
    [ ! -f "${{gz%.gz}}" ] || gzip -dc -- "$gz" 2>/dev/null | cmp -s - "${{gz%.gz}}" || printf '%s\n' "$gz"
done)
[ -z "$STALE" ] ||
    die "a .gz in $UI_DIST does not hold the file beside it, and the appliance would send it in that file's place — rebuild the bundle, or remove the .gz: $STALE""#
    );

    let staging =
        r#"# **The browser bundle, into the directory `wslib-appliance-config` defaults to.**
# Nothing on the box connects those two — the unit passes no arguments and no
# maintainer script writes a config.toml — so this path and that default are the
# whole mechanism, and a test holds them against each other rather than against
# this comment.
#
# **`install -d` and not `mkdir -p`**, which is the difference between an
# appliance that starts and one that does not. `install -d` sets the mode on
# every component it creates and ignores the umask; `mkdir -p` honours it. dpkg
# applies an archive directory's mode verbatim when it creates one, so a build
# host with `umask 077` shipped /usr/share/<name> at 0700 — and the daemon's own
# unprivileged user, being "other" against a root-owned directory, could not
# traverse it. Every other directory here comes from `install -D`, which never
# had this.
UI_STAGE="$STAGE/usr/share/$NAME/ui"
install -d -m 0755 "$UI_STAGE"

# The contents rather than the directory, so `dist/index.html` arrives at
# `ui/index.html` and not at `ui/dist/index.html`.
cp -R "$UI_DIST/." "$UI_STAGE"

# **The modes arriving here are the source tree's, not the package's.** `cp -R`
# preserves what the product's build and the build host's umask left behind — the
# same shape as `mktemp -d`'s 0700 becoming the staging root's mode above, an
# artefact inheriting a property of where it was assembled rather than of what
# was put in it. A group-writable file under /usr/share on an appliance is a mode
# nobody chose. A bundle is static files a daemon reads and nothing writes, so it
# is 0755 and 0644 flat.
find "$UI_STAGE" -type d -exec chmod 0755 {} +
find "$UI_STAGE" -type f -exec chmod 0644 {} +"#
            .to_string();

    (checks, staging)
}

/// What `make-deb.sh` says about a product's hooks: the checks before the build,
/// and the staging after it. Anything but `postinst.d` and `prerm.d` is refused,
/// and a hook's name takes `run-parts`' own rule.
fn hooks_blocks(dir: Option<&str>) -> (String, String) {
    let Some(dir) = dir else {
        return (
            "# No hooks: `appliance.toml` names no `hooks_dir`. The maintainer scripts run\n\
             # `run-parts` over /usr/share/$NAME/{postinst.d,prerm.d} when either exists, and\n\
             # naming a directory here is what ships something for them to run."
                .to_string(),
            "# Nothing is staged under /usr/share/$NAME/postinst.d or prerm.d: no hooks_dir."
                .to_string(),
        );
    };

    let checks = format!(
        r#"# The product's hooks, checked before the build for the two ways one silently
# never runs: a name with a dot in it, which run-parts skips, and a missing
# executable bit, which it also skips. Both are refused here, where the message
# can name the file, rather than discovered on a board that did not migrate.
HOOKS_DIR='{dir}'
HOOK_DIRS='postinst.d prerm.d'
[ -d "$HOOKS_DIR" ] || die "$HOOKS_DIR is not there — appliance.toml names it as hooks_dir"
STRAY=$(find "$HOOKS_DIR" -mindepth 1 -maxdepth 1 ! -name postinst.d ! -name prerm.d)
[ -z "$STRAY" ] ||
    die "$HOOKS_DIR holds something that is not postinst.d or prerm.d, and nothing else there could ever run — a postrm hook is deleted before postrm could call it: $STRAY"
for d in $HOOK_DIRS; do
    [ -d "$HOOKS_DIR/$d" ] || continue
    # The three globs together are every entry, dotfiles included.
    for hook in "$HOOKS_DIR/$d"/* "$HOOKS_DIR/$d"/.[!.]* "$HOOKS_DIR/$d"/..?*; do
        [ -e "$hook" ] || continue
        case "${{hook##*/}}" in
        *[!A-Za-z0-9_-]*) die "$hook has a character in its name that run-parts will not run — letters, digits, \`_\` and \`-\`; no \`.sh\`, and no dotfile, which would never ship" ;;
        esac
        [ -f "$hook" ] || die "$hook is not a plain file, and a hook is one"
        [ -x "$hook" ] || die "$hook is not executable, so run-parts would skip it without a word"
    done
done"#
    );

    let staging = r#"# The hooks, into the directories the maintainer scripts run `run-parts` over.
# Checked above, so every name here is one run-parts will run.
for d in $HOOK_DIRS; do
    [ -d "$HOOKS_DIR/$d" ] || continue
    for hook in "$HOOKS_DIR/$d"/*; do
        [ -f "$hook" ] || continue
        install -D -m 0755 "$hook" "$STAGE/usr/share/$NAME/$d/${hook##*/}"
    done
done"#
        .to_string();

    (checks, staging)
}

/// What `make-deb.sh` says about `[package.files]`: each source is checked to
/// exist before the build, and each is staged `0644` afterwards, with the ones
/// under `/etc` listed as conffiles; one rendered line per file.
fn files_blocks(files: &BTreeMap<String, String>) -> (String, String) {
    if files.is_empty() {
        return (
            "# No shipped files: `appliance.toml` has no `[package.files]` table.".to_string(),
            "# Nothing is staged from [package.files].".to_string(),
        );
    }

    let checks = std::iter::once(
        "# The files appliance.toml ships, checked before the build so a missing one is\n\
         # found before minutes are spent compiling."
            .to_string(),
    )
    .chain(files.iter().map(|(destination, source)| {
        format!(
            "[ -f '{source}' ] || die \"{source} is not there — appliance.toml ships it as \
             {destination}\""
        )
    }))
    .collect::<Vec<_>>()
    .join("\n");

    let staging = std::iter::once(
        "# The files appliance.toml ships, each 0644; the ones under /etc are conffiles."
            .to_string(),
    )
    .chain(files.iter().map(|(destination, source)| {
        let conffile = if is_conffile(destination) {
            format!("\nprintf '%s\\n' '{destination}' >> \"$CONFFILES\"")
        } else {
            String::new()
        };
        format!("install -D -m 0644 '{source}' \"$STAGE{destination}\"{conffile}")
    }))
    .collect::<Vec<_>>()
    .join("\n");

    (checks, staging)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EXAMPLE, checked, with_docker, with_every_package_knob};
    use crate::render::{self, commands};

    const MAKE_DEB_PATH: &str = "packaging/make-deb.sh";

    fn body(path: &str) -> String {
        render::body(&artefacts(&checked(EXAMPLE)).expect("renders"), path)
    }

    fn make_deb_for(text: &str) -> String {
        commands(&render::body(
            &artefacts(&checked(text)).expect("renders"),
            MAKE_DEB_PATH,
        ))
    }

    fn make_deb() -> String {
        make_deb_for(EXAMPLE)
    }

    const BUILT: &str = "build_binary";

    fn build_binary() -> String {
        commands(&body("packaging/build-binary.sh"))
    }

    #[test]
    fn make_deb_builds_with_the_shared_script_between_its_checks_and_its_staging() {
        let script = make_deb();
        let order = [
            r#". "$HERE/build-binary.sh""#,
            "binary_arch",
            "VERSION=$(wslib-appliance-xtask",
            BUILT,
            "STAGE=$(mktemp -d)",
        ]
        .map(|step| {
            script
                .find(step)
                .unwrap_or_else(|| panic!("{step}: {script}"))
        });
        assert!(order.is_sorted(), "{order:?}: {script}");
        assert_eq!(script.matches(BUILT).count(), 1, "{script}");
        assert!(!script.contains("cargo build"), "{script}");

        let shared = build_binary();
        assert!(shared.contains("binary_arch() {"), "{shared}");
        assert!(shared.contains("build_binary() {"), "{shared}");
    }

    #[test]
    fn the_floor_and_the_unknown_grep_are_both_made() {
        let script = build_binary();

        assert!(
            script.contains("MIN_BINARY_BYTES='2500000'"),
            "the floor is not the one appliance.toml set: {script}"
        );
        assert!(
            script.contains(r#"[ "$SIZE" -ge "$MIN_BINARY_BYTES" ]"#),
            "the floor is set and never compared: {script}"
        );

        // `build_version!` supplies the parentheses around `UNKNOWN`.
        let rendered = format!(" ({})", wslib_build_id::UNKNOWN);
        assert!(
            script.contains(&format!("grep -q -a '{rendered}'")),
            "the grep does not spell what build_version! renders: {script}"
        );
    }

    #[test]
    fn the_binary_is_the_architecture_the_package_claims_and_stands_alone() {
        let script = build_binary();

        for line in [
            "aarch64-*-musl) ARCH=arm64 MACHINE=183 ;;",
            "x86_64-*-musl) ARCH=amd64 MACHINE=62 ;;",
            r#"GOT=$(od -An -tu2 -j18 -N2 "$BIN" | tr -d '[:space:]')"#,
            r#"grep -q -a -e ld-linux -e ld-musl "$BIN""#,
        ] {
            assert!(script.contains(line), "no `{line}` in: {script}");
        }

        let built = script.find("cargo build").expect("builds");
        let checked = script.find("GOT=$(od").expect("reads the header");
        assert!(built < checked, "{script}");
    }

    #[cfg(unix)]
    #[test]
    fn the_binary_builds_with_its_own_package_features_alone() {
        use std::process::Command;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let put = |path: &str, body: &str| {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, body).expect("write");
        };
        let member = |name: &str, shared: &str| {
            format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
                 [dependencies]\nshared = {{ path = \"../shared\"{shared} }}\n"
            )
        };
        put(
            "Cargo.toml",
            "[workspace]\nmembers = [\"product\", \"other\", \"shared\"]\nresolver = \"3\"\n",
        );
        put(
            "shared/Cargo.toml",
            "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             [features]\nother = []\n",
        );
        put(
            "shared/src/lib.rs",
            "#[cfg(feature = \"other\")]\ncompile_error!(\"another member's feature\");\n",
        );
        put("product/Cargo.toml", &member("product", ""));
        put("product/src/main.rs", "fn main() {}\n");
        put(
            "other/Cargo.toml",
            &member("other", ", features = [\"other\"]"),
        );
        put("other/src/lib.rs", "");
        put("build-binary.sh", &body("packaging/build-binary.sh"));

        let locked = Command::new("cargo")
            .args(["generate-lockfile", "--offline", "-q"])
            .current_dir(dir.path())
            .status()
            .expect("cargo");
        assert!(locked.success());
        let host = Command::new("rustc").arg("-vV").output().expect("rustc");
        let host = String::from_utf8_lossy(&host.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
            .expect("a host triple");

        let out = Command::new("sh")
            .args([
                "-c",
                r#"set -eu; die() { echo "$1" >&2; exit 1; }; . ./build-binary.sh; build_binary"#,
            ])
            .current_dir(dir.path())
            .env("BINARY", "product")
            .env("PACKAGE", "product")
            .env("TARGET_DIR", "target")
            .env("CARGO_BUILD_TARGET", &host)
            .output()
            .expect("sh");
        let built = dir.path().join(format!("target/{host}/release/product"));
        assert!(built.exists(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn an_arm64_binary_is_scanned_for_unpatched_erratum_sites() {
        use clap::Parser;

        let script = build_binary();
        let (guarded, rest) = script
            .split_once(r#"if [ "$ARCH" = arm64 ]; then"#)
            .expect("the check is guarded by the architecture");
        let (check, _) = rest.split_once("\nfi").expect("the guard closes");
        let call = check
            .lines()
            .find(|l| l.starts_with("wslib-appliance-xtask erratum"))
            .expect("the call");
        let words = call.split_whitespace().take_while(|w| *w != "||");
        let parsed = crate::Cli::try_parse_from(words.map(|w| w.trim_matches('"')));
        assert!(parsed.is_ok(), "{call}: {parsed:?}");
        for arm in ["0) ;;", "1) die", "*) die"] {
            assert!(check.contains(arm), "no `{arm}` in: {check}");
        }

        assert!(
            guarded.contains("cargo build"),
            "the scan does not follow the build: {script}"
        );
    }

    #[test]
    fn no_build_script_reimplements_the_version_format() {
        let everything = checked(&with_docker(&with_every_package_knob()));
        let scripts: Vec<_> = crate::chassis_owned(&everything)
            .expect("renders")
            .into_iter()
            .filter(|a| a.path.starts_with("packaging"))
            .collect();
        assert_eq!(scripts.len(), 4, "{scripts:#?}");
        for artefact in scripts {
            let script = commands(&artefact.body);
            for spelled in ["~git", "rev-parse", "--porcelain", "%cd", "git "] {
                assert!(
                    !script.contains(spelled),
                    "{} works out {spelled:?} for itself: {script}",
                    artefact.path.display()
                );
            }
        }

        assert!(
            make_deb().contains("wslib-appliance-xtask build-id --deb-version"),
            "make-deb.sh does not ask for the version at all"
        );
    }

    #[test]
    fn the_unit_is_checked_against_the_binary_before_anything_compiles() {
        let script = make_deb();

        let checked_at = script
            .find(r#""ExecStart=/usr/bin/$BINARY""#)
            .expect("the cross-file check");
        let built_at = script.find(BUILT).expect("the build");
        assert!(
            checked_at < built_at,
            "the unit is checked after the cross-build has already been paid for: {script}"
        );
    }

    /// dpkg-deb refuses only an unfilled `@VERSION@`.
    #[test]
    fn every_token_the_control_file_leaves_is_one_this_script_fills() {
        let checked = checked(EXAMPLE);
        let control = crate::debian::artefacts(&checked)
            .expect("renders")
            .into_iter()
            .find(|a| a.path.to_str() == Some("debian/control.in"))
            .expect("a control file")
            .body;

        // `Maintainer:` carries an `@` too; the character set tells them apart.
        let tokens: Vec<&str> = control
            .split('@')
            .filter(|piece| {
                !piece.is_empty() && piece.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            })
            .collect();
        assert_eq!(tokens, ["VERSION", "ARCH", "INSTALLED_SIZE"], "{control}");

        let script = make_deb();
        for token in tokens {
            assert!(
                script.contains(&format!("s|@{token}@|")),
                "nothing fills @{token}@: {script}"
            );
        }
        assert!(script.contains(r#"grep -q -E '@[A-Z_]+@'"#), "{script}");
    }

    /// The staging root's mode becomes the package's `./`, which dpkg applies
    /// to `/`.
    #[test]
    fn the_staging_root_does_not_carry_mktemps_mode_into_the_package() {
        let script = make_deb();

        let made = script.find("STAGE=$(mktemp -d)").expect("a staging tree");
        let fixed = script
            .find(r#"chmod 0755 "$STAGE""#)
            .expect("the root mode");
        let staged = script.find("install -D").expect("something staged");

        assert!(
            made < fixed && fixed < staged,
            "the staging root's mode is set too late to be the one packaged: {script}"
        );
    }

    #[test]
    fn the_maintainer_scripts_are_staged_with_the_mode_dpkg_deb_demands() {
        let script = make_deb();

        assert!(
            script.contains(r#"install -D -m 0755 "$TARGET_SCAFFOLD/debian/$script""#),
            "{script}"
        );
        assert!(
            script.contains("for script in postinst prerm postrm"),
            "the mode is set for fewer than three scripts: {script}"
        );
    }

    /// A pipeline's non-final stages are invisible to `set -e`.
    #[test]
    fn the_md5sums_are_counted_against_what_was_staged() {
        let script = make_deb();

        assert!(script.contains("LISTED=$(wc -l <"), "{script}");
        assert!(
            script.contains(r#"[ "$STAGED" -eq "$LISTED" ]"#),
            "the counts are taken and never compared: {script}"
        );
    }

    #[test]
    fn the_installed_size_is_checked_for_being_a_number() {
        let script = make_deb();

        assert!(
            script.contains(r#"'' | *[!0-9]*)"#),
            "Installed-Size is computed and never checked: {script}"
        );
    }

    #[test]
    fn the_installed_size_is_computed_from_what_was_staged() {
        let script = make_deb();

        assert!(script.contains("INSTALLED_SIZE=$(du -k -s"), "{script}");
        assert!(script.contains("--exclude=DEBIAN"), "{script}");
    }

    #[test]
    fn the_package_is_built_owned_by_root() {
        let script = make_deb();
        assert!(
            script.contains("dpkg-deb --root-owner-group --build"),
            "{script}"
        );
    }

    #[test]
    fn the_binary_and_the_unit_are_staged() {
        let script = make_deb();

        assert!(script.contains(r#""$STAGE/usr/bin/$BINARY""#), "{script}");
        assert!(
            script.contains(r#""$STAGE/usr/lib/systemd/system/$NAME.service""#),
            "{script}"
        );
    }

    /// Nothing on the box connects the staged path to the daemon's default, so
    /// it is asked of `wslib-appliance-config`, and spelled once.
    #[test]
    fn the_bundle_is_staged_where_the_daemon_looks_for_it() {
        let script = make_deb();
        let assigned = format!(
            r#"UI_STAGE="$STAGE{}""#,
            wslib_appliance_config::default_ui_dir("$NAME").display()
        );
        assert!(
            script.contains(&assigned),
            "nothing assigns {assigned}: {script}"
        );
        let ui_dir = wslib_appliance_config::default_ui_dir("$NAME")
            .display()
            .to_string();
        assert_eq!(
            script.matches(&ui_dir).count(),
            1,
            "the staging path is spelled more than once, so this test holds only one of them: \
             {script}"
        );
    }

    #[test]
    fn the_bundles_directories_do_not_take_the_build_hosts_umask() {
        let script = make_deb();

        assert!(
            script.contains(r#"install -d -m 0755 "$UI_STAGE""#),
            "the staging directory is not created with an explicit mode: {script}"
        );
        assert!(
            !script.contains("mkdir -p \"$UI_STAGE\"") && !script.contains("mkdir -p \"$STAGE"),
            "something under the staging tree is created with the build host's umask: {script}"
        );
    }

    #[test]
    fn every_check_on_the_bundle_happens_before_anything_compiles() {
        let script = make_deb();
        let built_at = script.find(BUILT).expect("the build");

        for check in [
            r#"[ -d "$UI_DIST" ]"#,
            r#"[ -f "$UI_DIST/index.html" ]"#,
            r#"find "$UI_DIST/." \( -name '.git'"#,
            r#"ODD=$(find "$UI_DIST/." ! -type f ! -type d)"#,
            r#"BACKSLASHED=$(find "$UI_DIST/." -name '*\\*')"#,
            r#"STALE=$(find "$UI_DIST/." -type f -name '*.gz'"#,
        ] {
            let checked_at = script
                .find(check)
                .unwrap_or_else(|| panic!("nothing checks `{check}`: {script}"));
            assert!(
                checked_at < built_at,
                "`{check}` runs after the cross-build has already been paid for: {script}"
            );
        }
    }

    #[test]
    fn a_product_with_no_browser_half_stages_no_bundle() {
        let script = make_deb_for(&crate::model::without_ui_dist(EXAMPLE));
        let ui_dir = wslib_appliance_config::default_ui_dir("$NAME")
            .display()
            .to_string();

        for absent in ["cp -R", "UI_DIST", "UI_STAGE", ui_dir.as_str()] {
            assert!(
                !script.contains(absent),
                "a headless appliance's script still has `{absent}` in it: {script}"
            );
        }
    }

    #[test]
    fn every_hook_is_staged_executable_under_the_directory_run_parts_reads() {
        let script = make_deb_for(&with_every_package_knob());
        let built_at = script.find(BUILT).expect("the build");

        for check in [
            "HOOKS_DIR='scaffold/hooks'",
            r#"[ -d "$HOOKS_DIR" ]"#,
            "! -name postinst.d ! -name prerm.d",
            "*[!A-Za-z0-9_-]*)",
            r#"[ -x "$hook" ]"#,
        ] {
            let at = script
                .find(check)
                .unwrap_or_else(|| panic!("nothing checks `{check}`: {script}"));
            assert!(at < built_at, "`{check}` runs after the build: {script}");
        }
        assert!(
            script
                .contains(r#"install -D -m 0755 "$hook" "$STAGE/usr/share/$NAME/$d/${hook##*/}""#),
            "{script}"
        );
        assert_eq!(
            script.matches("for d in $HOOK_DIRS; do").count(),
            2,
            "the check and the staging walk different directories: {script}"
        );
    }

    #[test]
    fn a_products_drop_ins_are_staged_and_its_sample_is_not() {
        let script = make_deb();
        assert!(
            script.contains(r#"DROPINS="$SCAFFOLD/systemd/$NAME.service.d""#),
            "{script}"
        );
        assert!(
            script.contains(
                r#"install -D -m 0644 "$conf" "$STAGE/usr/lib/systemd/system/$NAME.service.d/${conf##*/}""#
            ),
            "{script}"
        );
        assert_eq!(
            script
                .matches(r#"for conf in "$DROPINS"/*.conf; do"#)
                .count(),
            2,
            "the glob that excludes the sample is not the one used both times: {script}"
        );
        assert!(!script.contains("*.sample"), "{script}");
    }

    #[test]
    fn the_examples_placeholder_maintainer_is_refused_before_the_build() {
        let script = make_deb();
        let built_at = script.find(BUILT).expect("the build");
        let refused_at = script
            .find("*example.invalid*) die")
            .expect("the placeholder is refused");
        assert!(refused_at < built_at, "{script}");
    }

    #[test]
    fn a_file_under_etc_is_listed_as_a_conffile_and_one_under_usr_share_is_not() {
        let script = make_deb_for(&with_every_package_knob());
        let built_at = script.find(BUILT).expect("the build");

        let checked_at = script
            .find("[ -f 'scaffold/files/config.toml.example' ]")
            .expect("the source is checked");
        assert!(checked_at < built_at, "{script}");

        assert!(
            script.contains(
                r#"install -D -m 0644 'scaffold/files/config.toml.example' "$STAGE/etc/myappliance/config.toml.example""#
            ),
            "{script}"
        );
        assert!(
            script.contains(
                r#"printf '%s\n' '/etc/myappliance/config.toml.example' >> "$CONFFILES""#
            ),
            "{script}"
        );
        assert!(
            script.contains(
                r#"install -D -m 0644 'scaffold/files/report.html' "$STAGE/usr/share/myappliance/templates/report.html""#
            ),
            "{script}"
        );
        assert!(
            !script.contains("'/usr/share/myappliance/templates/report.html' >>"),
            "a file under /usr/share was listed as a conffile: {script}"
        );
    }

    #[test]
    fn the_rendered_config_ships_as_a_conffile_and_the_package_values_do_not() {
        let script = make_deb_for(EXAMPLE);
        let built_at = script.find(BUILT).expect("the build");
        for check in [r#"[ -f "$CONFIG" ]"#, r#"[ -f "$PACKAGE_CONFIG" ]"#] {
            let checked_at = script.find(check).expect(check);
            assert!(checked_at < built_at, "{check}: {script}");
        }
        for line in [
            r#"CONFIG="$TARGET_SCAFFOLD/debian/config.toml""#,
            r#"install -D -m 0640 "$CONFIG" "$STAGE/etc/myappliance/config.toml""#,
            r#"printf '%s\n' '/etc/myappliance/config.toml' >> "$CONFFILES""#,
            r#"PACKAGE_CONFIG="$TARGET_SCAFFOLD/debian/package-config.toml""#,
            r#"install -D -m 0644 "$PACKAGE_CONFIG" "$STAGE/usr/share/$NAME/config.toml""#,
        ] {
            assert!(script.contains(line), "{line}: {script}");
        }
        assert_eq!(script.matches(r#">> "$CONFFILES""#).count(), 1, "{script}");
    }

    #[test]
    fn copyright_is_staged_when_present_and_only_warned_about_when_not() {
        let script = make_deb();
        let built_at = script.find(BUILT).expect("the build");

        let warned_at = script
            .find(r#"[ -f "$SCAFFOLD/debian/copyright" ] ||"#)
            .expect("the warning");
        assert!(warned_at < built_at, "{script}");
        assert!(
            script.contains("warn \"no $SCAFFOLD/debian/copyright"),
            "{script}"
        );
        assert!(
            script.contains(r#"install -m 0644 "$SCAFFOLD/debian/copyright" "$DOC/copyright""#),
            "{script}"
        );

        let versioned_at = script
            .find("VERSION=$(wslib-appliance-xtask")
            .expect("the version");
        let changelog_at = script.find(r#"> "$DOC/changelog""#).expect("the changelog");
        assert!(versioned_at < changelog_at, "{script}");
        assert!(
            script.contains(r#"gzip -9n "$DOC/changelog""#),
            "not a pipeline, so set -e sees either half fail: {script}"
        );
        assert!(!script.contains("changelog.Debian"), "{script}");
    }

    #[test]
    fn the_package_takes_the_name_its_control_file_gives() {
        let script = make_deb();
        for line in [
            r#"DEB_PACKAGE=$(sed -n 's/^Package: //p' "$CONTROL_IN")"#,
            r#"DEB="$OUT/${DEB_PACKAGE}_${VERSION}_${ARCH}.deb""#,
            r#"install -D -m 0644 "$UNIT" "$STAGE/usr/lib/systemd/system/$NAME.service""#,
        ] {
            assert!(script.contains(line), "no `{line}` in: {script}");
        }
        let read = script.find("DEB_PACKAGE=$(").expect("reads the name");
        assert!(read < script.find(BUILT).expect("builds"), "{script}");
    }

    #[cfg(unix)]
    #[test]
    fn the_target_is_required_named_and_given_its_own_output() {
        use std::process::Command;

        let script = make_deb();
        assert!(
            script.contains(r#"OUT="target/debian/$TARGET""#),
            "{script}"
        );
        assert!(
            script.contains(r#"TARGET_SCAFFOLD="$SCAFFOLD/targets/$TARGET""#),
            "{script}"
        );

        let raw = render::body(
            &artefacts(&checked(EXAMPLE)).expect("renders"),
            MAKE_DEB_PATH,
        );
        let dir = tempfile::TempDir::new().expect("tempdir");
        let packaging = dir.path().join("scaffold/packaging");
        std::fs::create_dir_all(&packaging).expect("mkdir");
        let refusal = |args: &[&str], rust_target: Option<&str>| {
            let mut sh = Command::new("sh");
            sh.arg("-c")
                .arg(&raw)
                .arg(packaging.join("make-deb.sh"))
                .args(args)
                .current_dir(dir.path())
                .env("PATH", "/usr/bin:/bin")
                .env_remove("CARGO_BUILD_TARGET");
            if let Some(rust_target) = rust_target {
                sh.env("CARGO_BUILD_TARGET", rust_target);
            }
            let out = sh.output().expect("sh");
            assert!(!out.status.success(), "{args:?} ran");
            String::from_utf8_lossy(&out.stderr).into_owned()
        };
        for wrong in [
            &[][..],
            &["deb"],
            &["--target"],
            &["--target", "oci"],
            &["--target", "image"],
        ] {
            let said = refusal(wrong, None);
            assert!(
                said.contains("usage:") || said.contains("declares no target"),
                "{wrong:?}: {said}"
            );
        }

        let unnamed = "--target deb needs CARGO_BUILD_TARGET";
        let said = refusal(&["--target", "deb"], None);
        assert!(
            said.contains(unnamed)
                && said.contains("x86_64-unknown-linux-musl")
                && said.contains("aarch64-unknown-linux-musl"),
            "{said}"
        );
        let said = refusal(&["--target", "deb"], Some("x86_64-unknown-linux-musl"));
        assert!(
            !said.contains("usage:")
                && !said.contains("declares no target")
                && !said.contains(unnamed),
            "{said}"
        );
    }

    #[test]
    fn a_product_with_no_hooks_or_files_renders_none_of_it() {
        let script = make_deb();
        for absent in [
            "HOOKS_DIR",
            "install -D -m 0644 '",
            "printf '%s\\n' '/etc/myappliance/config.toml.",
        ] {
            assert!(
                !script.contains(absent),
                "a product with no knobs on still has `{absent}`: {script}"
            );
        }
        assert!(script.contains(r#""$DROPINS"/*.conf"#), "{script}");
        assert!(
            script.contains(r#"DOC="$STAGE/usr/share/doc/$DEB_PACKAGE""#),
            "{script}"
        );
    }
}
