//! The Debian control file, the maintainer scripts, the shipped `config.toml`s,
//! and the README that tells a product where its own hooks go.
//!
//! `{{…}}` is this tool's and `@…@` is `make-deb.sh`'s: the control file leaves
//! the build's identity for the shell to fill.

use crate::model::Checked;
use crate::render::{Artefact, RenderError, fixed};

const CONTROL: &str = include_str!("../templates/debian/control.in");
const POSTINST: &str = include_str!("../templates/debian/postinst");
const PRERM: &str = include_str!("../templates/debian/prerm");
const POSTRM: &str = include_str!("../templates/debian/postrm");
const HOOKS: &str = include_str!("../templates/debian/hooks.README");
const CONFIG: &str = include_str!("../templates/debian/config.toml");
const PACKAGE_CONFIG: &str = include_str!("../templates/debian/package-config.toml");

pub fn artefacts(checked: &Checked) -> Result<Vec<Artefact>, RenderError> {
    let app = &checked.appliance;
    let deb = checked.deb();

    let mut values = values(checked);
    values.extend([
        ("socket", app.socket.display().to_string()),
        ("section", app.package.section.clone()),
        ("maintainer", app.package.maintainer.clone()),
        ("description", app.package.description.clone()),
        ("package", checked.package().to_string()),
        ("relations", relations(checked)),
        ("packages", package_names(checked).join(" ")),
        ("bind_address", format!("{:?}", deb.bind_address)),
        ("https_port", deb.https_port.to_string()),
    ]);

    fixed(
        &[
            ("debian/control.in", CONTROL),
            ("debian/postinst", POSTINST),
            ("debian/prerm", PRERM),
            ("debian/postrm", POSTRM),
            ("debian/config.toml", CONFIG),
            ("debian/package-config.toml", PACKAGE_CONFIG),
        ],
        &values,
    )
}

pub fn hooks_readme(checked: &Checked) -> Result<Vec<Artefact>, RenderError> {
    fixed(&[("debian/hooks.README", HOOKS)], &values(checked))
}

fn values(checked: &Checked) -> Vec<(&'static str, String)> {
    let app = &checked.appliance;
    vec![
        ("name", app.name.clone()),
        ("user", app.user.clone()),
        ("group", app.group.clone()),
        ("config_dir", app.config_dir.display().to_string()),
        ("state_dir", app.state_dir.display().to_string()),
    ]
}

/// Every name a package of the appliance goes by: the system name, the
/// package's own, and `<name>-image`, an earlier image package's.
fn package_names(checked: &Checked) -> Vec<String> {
    let name = &checked.appliance.name;
    let mut names = vec![
        name.clone(),
        checked.package().to_string(),
        format!("{name}-image"),
    ];
    names.sort();
    names.dedup();
    names
}

/// The relationship fields that hold something, each a line; the package
/// conflicts with and replaces every other name in [`package_names`].
fn relations(checked: &Checked) -> String {
    let app = &checked.appliance;
    let displaced: Vec<String> = package_names(checked)
        .into_iter()
        .filter(|other| other != checked.package())
        .collect();
    [
        ("Depends", app.package.depends.clone()),
        (
            "Suggests",
            checked
                .deb()
                .suggests
                .as_ref()
                .unwrap_or(&app.package.suggests)
                .clone(),
        ),
        ("Conflicts", displaced.clone()),
        ("Replaces", displaced),
    ]
    .into_iter()
    .filter(|(_, entries)| !entries.is_empty())
    .map(|(field, entries)| format!("{field}: {}\n", entries.join(", ")))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EXAMPLE, checked, with_deb_keys};
    use crate::render::{self, commands};

    fn rendered(text: &str) -> Vec<Artefact> {
        artefacts(&checked(text)).expect("renders")
    }

    fn body(text: &str, path: &str) -> String {
        render::body(&rendered(text), path)
    }

    #[test]
    fn the_control_file_leaves_the_build_identity_to_make_deb() {
        let control = body(EXAMPLE, "debian/control.in");

        assert!(control.contains("Version: @VERSION@"), "{control}");
        assert!(control.contains("Architecture: @ARCH@"), "{control}");
        assert!(control.contains("Package: myappliance"), "{control}");
        assert!(
            control.contains("Depends: init-system-helpers"),
            "{control}"
        );
    }

    #[test]
    fn a_product_that_suggests_nothing_gets_no_suggests_line() {
        let control = body(EXAMPLE, "debian/control.in");
        assert!(!control.contains("Suggests:"), "{control}");

        let with = EXAMPLE.replace("suggests = []", r#"suggests = ["chrony"]"#);
        assert!(body(&with, "debian/control.in").contains("Suggests: chrony"));
    }

    #[test]
    fn the_packages_own_suggests_replaces_the_shared_one() {
        let control = |text: &str| body(text, "debian/control.in");
        let inherited = EXAMPLE.replace("suggests = []", r#"suggests = ["chrony"]"#);
        assert!(control(&inherited).contains("Suggests: chrony\n"));
        let own = with_deb_keys(&inherited, r#"suggests = ["ntpsec", "bluez"]"#);
        assert!(control(&own).contains("Suggests: ntpsec, bluez\n"));
        let none = with_deb_keys(&inherited, "suggests = []");
        assert!(!control(&none).contains("Suggests:"));
    }

    /// Taken back on every configure and on purge, never on remove.
    #[test]
    fn what_an_image_install_told_sshd_and_timesyncd_is_taken_back() {
        let postinst = commands(&body(EXAMPLE, "debian/postinst"));
        let postrm = commands(&body(EXAMPLE, "debian/postrm"));
        let purge = postrm
            .split("purge)")
            .nth(1)
            .and_then(|s| s.split("\nremove)").next())
            .expect("a purge arm");
        for script in [postinst.as_str(), purge] {
            for removal in [
                r#"rm -f "/etc/ssh/sshd_config.d/50-$NAME.conf""#,
                r#"rm -f "/etc/systemd/timesyncd.conf.d/90-$NAME.conf""#,
            ] {
                assert!(script.contains(removal), "{removal}: {script}");
            }
        }
        for dir in ["sshd_config.d", "timesyncd.conf.d"] {
            assert_eq!(
                postrm.matches(dir).count(),
                purge.matches(dir).count(),
                "{dir} outside the purge arm: {postrm}"
            );
        }
        assert!(postinst.contains("deb-systemd-invoke try-reload-or-restart ssh.service"));
        for absent in ["AuthorizedKeysFile", "ln -s", "journalctl"] {
            assert!(!postinst.contains(absent), "{absent}: {postinst}");
        }
    }

    #[test]
    fn the_image_package_of_an_earlier_tag_is_displaced() {
        let control = body(EXAMPLE, "debian/control.in");
        assert!(
            control.contains("Conflicts: myappliance-image\nReplaces: myappliance-image\n"),
            "{control}"
        );
        let postrm = body(EXAMPLE, "debian/postrm");
        assert!(
            postrm.contains("PACKAGES='myappliance myappliance-image'\n"),
            "{postrm}"
        );
    }

    #[test]
    fn postinst_gives_the_configuration_directory_the_group_systemd_will_not() {
        let postinst = commands(&body(EXAMPLE, "debian/postinst"));
        assert!(
            postinst.contains(r#"install -d -o root -g "$GROUP" -m 0751 "$CONFIG_DIR""#),
            "{postinst}"
        );
        assert!(
            postinst.contains(
                r#"find "$CONFIG_DIR/config.toml" -prune -group 0 -exec chgrp "$GROUP" {} +"#
            ),
            "{postinst}"
        );
    }

    /// Gaining the group from root takes root, so it is not tested here.
    #[cfg(unix)]
    #[test]
    fn postinst_takes_only_world_access_from_the_config_file() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::process::Command;

        let postinst = body(EXAMPLE, "debian/postinst");
        let start = postinst
            .find(r#"    if [ -f "$CONFIG_DIR/config.toml" ]"#)
            .expect("the config.toml block");
        let block = &postinst[start..];
        let block = &block[..block.find("\n    fi\n").expect("its end") + "\n    fi\n".len()];

        let dir = tempfile::TempDir::new().expect("tempdir");
        let config = dir.path().join("config.toml");
        let target = dir.path().join("elsewhere.toml");
        let groups = Command::new("id").arg("-G").output().expect("id");
        let groups: Vec<u32> = String::from_utf8(groups.stdout)
            .expect("utf-8")
            .split_whitespace()
            .map(|gid| gid.parse().expect("a gid"))
            .filter(|&gid| gid != 0)
            .collect();
        let mode = |path: &std::path::Path| {
            std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
        };
        let configure = |group: u32| {
            let status = Command::new("sh")
                .args(["-ec", block])
                .env("CONFIG_DIR", dir.path())
                .env("GROUP", group.to_string())
                .status()
                .expect("sh");
            assert!(status.success());
        };
        let (operators, packages) = (groups[0], *groups.last().expect("a group"));
        let write = |path: &std::path::Path, mode: u32| {
            std::fs::write(path, "").expect("write");
            std::os::unix::fs::chown(path, None, Some(operators)).expect("chgrp");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        };

        for (before, after) in [
            (0o644, 0o640),
            (0o666, 0o660),
            (0o600, 0o600),
            (0o640, 0o640),
        ] {
            write(&config, before);
            configure(packages);
            assert_eq!(mode(&config), after, "{before:o}");
            let gid = std::fs::metadata(&config).expect("stat").gid();
            assert_eq!(gid, operators, "an operator's group is theirs");
        }

        std::fs::remove_file(&config).expect("remove");
        write(&target, 0o644);
        symlink(&target, &config).expect("symlink");
        configure(packages);
        assert_eq!(
            mode(&target),
            0o644,
            "a symlink's target is not ours to change"
        );
    }

    /// `postrm` runs after dpkg has removed the package's files (Policy 6.5).
    #[test]
    fn postrm_has_no_hook_site_because_it_could_never_reach_one() {
        let postrm = commands(&body(EXAMPLE, "debian/postrm"));
        assert!(!postrm.contains("run-parts"), "{postrm}");

        let raw = body(EXAMPLE, "debian/postrm");
        assert!(raw.contains("Policy 6.5"), "the omission has to say why");
    }

    /// dpkg calls `postinst abort-remove` after prerm has stopped the daemon.
    #[test]
    fn an_aborted_removal_still_starts_the_appliance_again() {
        let postinst = commands(&body(EXAMPLE, "debian/postinst"));
        let after_case = postinst
            .rsplit("esac")
            .next()
            .expect("something after the case");

        assert!(after_case.contains("deb-systemd-invoke"), "{after_case}");
        assert!(after_case.contains("deb-systemd-helper"), "{after_case}");
        assert!(postinst.contains("abort-remove"), "{postinst}");
    }

    /// The `postinst configure` after a deconfigure only `try-restart`s.
    #[test]
    fn a_deconfigure_does_not_stop_the_appliance() {
        let prerm = commands(&body(EXAMPLE, "debian/prerm"));
        let arm = prerm
            .split("\nupgrade | deconfigure)")
            .nth(1)
            .and_then(|arm| arm.split(";;").next())
            .expect("a shared upgrade/deconfigure arm");
        assert!(!arm.contains("stop"), "{arm}");
    }

    #[test]
    fn only_a_purge_takes_the_database_and_the_certificate() {
        let postrm = commands(&body(EXAMPLE, "debian/postrm"));
        let purge = postrm
            .split("purge)")
            .nth(1)
            .and_then(|s| s.split("remove)").next())
            .expect("a purge arm");

        assert!(purge.contains(r#"rm -rf "$STATE_DIR""#), "{purge}");
        assert!(purge.contains(r#"rm -rf "$CONFIG_DIR""#), "{purge}");

        let remove = postrm.split("\nremove)").nth(1).expect("a remove arm");
        assert!(!remove.contains("rm -rf"), "{remove}");
    }

    #[test]
    fn every_hook_site_stops_at_the_first_failure() {
        for script in ["debian/postinst", "debian/prerm"] {
            let run = commands(&body(EXAMPLE, script));
            let sites = run.matches("run-parts").count();
            assert!(sites > 0, "{script} runs no hooks");
            assert_eq!(
                run.matches("run-parts --exit-on-error").count(),
                sites,
                "{script} has a run-parts that would carry on after a failure"
            );
            assert_eq!(
                run.matches(r#"--arg="$1" --arg="$2""#).count(),
                sites,
                "{script} forwards fewer arguments than hooks.README promises"
            );
        }
    }

    #[test]
    fn remove_is_the_only_argument_that_stops_the_appliance() {
        let prerm = commands(&body(EXAMPLE, "debian/prerm"));
        let remove = prerm
            .split("\nremove)")
            .nth(1)
            .and_then(|arm| arm.split("\n;;").next())
            .expect("a remove arm");

        assert!(remove.contains("deb-systemd-invoke stop"), "{remove}");
        assert_eq!(
            prerm.matches("deb-systemd-invoke stop").count(),
            1,
            "something other than the remove arm stops the daemon: {prerm}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_daemon_a_remove_stopped_comes_back_and_one_an_operator_stopped_stays_down() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let root = dir.path().display().to_string();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(dir.path().join("run/systemd/system")).expect("mkdir");
        std::fs::create_dir_all(dir.path().join("var/lib")).expect("mkdir");
        std::fs::create_dir_all(&bin).expect("mkdir");
        for (tool, body) in [
            (
                "systemctl",
                "if [ \"$1\" = is-active ]; then echo \"$STATE\"; [ \"$STATE\" = active ]; fi",
            ),
            ("deb-systemd-invoke", "echo \"$1\" >> \"$INVOKED\""),
            ("deb-systemd-helper", "true"),
        ] {
            let path = bin.join(tool);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let script = |path: &str| {
            body(EXAMPLE, path)
                .replace("/run/", &format!("{root}/run/"))
                .replace("'/var/lib/", &format!("'{root}/var/lib/"))
        };
        let (prerm, postinst) = (script("debian/prerm"), script("debian/postinst"));
        let marker_line = postinst
            .lines()
            .find(|line| line.starts_with("REMOVED_WHILE_RUNNING="))
            .expect("the marker's path");
        let unit_block = &format!(
            "NAME='myappliance'\n{marker_line}\n{}",
            postinst
                .rsplit("esac\n")
                .next()
                .expect("the unit block after the case")
        );
        let invoked = dir.path().join("invoked");
        let marker = dir.path().join("var/lib/myappliance.removed-while-running");
        let run = |script: &str, args: &[&str], state: &str| {
            let status = Command::new("sh")
                .arg("-c")
                .arg(script)
                .arg("script")
                .args(args)
                .env("STATE", state)
                .env("INVOKED", &invoked)
                .env(
                    "PATH",
                    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
                )
                .status()
                .expect("sh");
            assert!(status.success(), "{args:?}");
        };
        let actions = || {
            let said = std::fs::read_to_string(&invoked).unwrap_or_default();
            let _ = std::fs::remove_file(&invoked);
            said.lines().map(str::to_string).collect::<Vec<_>>()
        };

        for running in ["active", "activating", "reloading"] {
            run(&prerm, &["remove"], running);
            assert!(
                marker.exists(),
                "an {running} daemon's stop is not recorded"
            );
            run(unit_block, &["configure", "1.0"], "inactive");
            assert_eq!(actions(), ["stop", "start"], "{running}");
            assert!(!marker.exists());
        }

        for stopped in ["inactive", "failed"] {
            run(&prerm, &["remove"], stopped);
            assert!(!marker.exists(), "a {stopped} daemon's remove is recorded");
            run(unit_block, &["configure", "1.0"], "inactive");
            assert_eq!(actions(), ["stop", "try-restart"], "{stopped}");
        }

        std::fs::write(&marker, "").expect("a stale marker");
        run(unit_block, &["configure", ""], "inactive");
        assert_eq!(actions(), ["start"]);
        assert!(!marker.exists(), "a first install leaves a stale marker");
    }

    #[test]
    fn a_package_named_apart_from_the_system_takes_its_place() {
        let text = with_deb_keys(EXAMPLE, r#"package = "myappliance-generic""#);
        let control = |text: &str| {
            body(text, "debian/control.in")
                .lines()
                .filter(|line| {
                    ["Package:", "Provides:", "Conflicts:", "Replaces:"]
                        .iter()
                        .any(|field| line.starts_with(field))
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            control(&text),
            "Package: myappliance-generic\n\
             Conflicts: myappliance, myappliance-image\n\
             Replaces: myappliance, myappliance-image"
        );

        let postinst = body(&text, "debian/postinst");
        assert!(postinst.contains("NAME='myappliance'\n"), "{postinst}");
    }

    #[test]
    fn a_purge_removes_nothing_while_another_package_of_the_appliance_is_there() {
        let postrm = commands(&body(EXAMPLE, "debian/postrm"));
        let purge = postrm
            .split("purge)")
            .nth(1)
            .and_then(|s| s.split("\nremove)").next())
            .expect("a purge arm");
        assert!(
            purge.starts_with("\nif ! OTHERS=$(other_packages_of_this_appliance); then\n"),
            "{purge}"
        );
        let exits: Vec<usize> = ["exit 1", "exit 0"]
            .iter()
            .map(|exit| {
                purge
                    .find(exit)
                    .unwrap_or_else(|| panic!("{exit}: {purge}"))
            })
            .collect();
        assert!(exits[0] < exits[1], "{purge}");
        assert!(
            purge[exits[0]..exits[1]].contains("if [ -n \"$OTHERS\" ]; then\n"),
            "{purge}"
        );
        for removal in ["rm -", "deluser", "delgroup", "deb-systemd-helper"] {
            let at = purge
                .find(removal)
                .unwrap_or_else(|| panic!("{removal}: {purge}"));
            assert!(exits[1] < at, "{removal} before the guard: {purge}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn another_package_of_the_appliance_is_one_of_its_names_with_files() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let named = with_deb_keys(EXAMPLE, r#"package = "myappliance-generic""#);
        let postrm = body(&named, "debian/postrm");
        assert!(
            postrm.contains("PACKAGES='myappliance myappliance-generic myappliance-image'\n"),
            "{postrm}"
        );
        let preamble = postrm
            .split("\ncase \"$1\" in")
            .next()
            .expect("the definitions before the case");
        let dir = tempfile::TempDir::new().expect("tempdir");
        let fake = dir.path().join("dpkg-query");
        std::fs::write(&fake, "#!/bin/sh\ncat \"$LISTING\"\n").expect("write");
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let listing = dir.path().join("listing");
        let run = || {
            Command::new("sh")
                .args([
                    "-c",
                    &format!("{preamble}\nother_packages_of_this_appliance"),
                ])
                .env("LISTING", &listing)
                .env(
                    "PATH",
                    format!(
                        "{}:{}",
                        dir.path().display(),
                        std::env::var("PATH").unwrap()
                    ),
                )
                .output()
                .expect("sh")
        };

        for (listed, others) in [
            ("installed myappliance\n", " myappliance"),
            ("half-installed myappliance\n", " myappliance"),
            ("installed myappliance-image\n", " myappliance-image"),
            ("unpacked myappliance-generic\n", ""),
            (
                "config-files myappliance\nnot-installed myappliance-generic\n",
                "",
            ),
            (
                "installed myappliance-tools\ninstalled myappliance-gen\n",
                "",
            ),
        ] {
            std::fs::write(&listing, listed).expect("write");
            let run = run();
            assert!(run.status.success(), "{listed:?}: {run:?}");
            assert_eq!(String::from_utf8_lossy(&run.stdout), others, "{listed:?}");
        }

        std::fs::remove_file(&listing).expect("remove");
        let run = run();
        assert!(!run.status.success(), "{run:?}");
    }

    /// Resolved by `wslib-appliance-config` itself, over the package's file.
    #[test]
    fn the_shipped_config_resolves_to_what_targets_deb_says() {
        use wslib_appliance_config::{ApplianceArgs, Bootstrap, Resolver};

        let dir = tempfile::TempDir::new().expect("tempdir");
        let package = dir.path().join("package.toml");
        let config = dir.path().join("config.toml");
        let resolved = |text: &str, etc: Option<&str>| -> Bootstrap {
            std::fs::write(&package, body(text, "debian/package-config.toml")).expect("write");
            let _ = std::fs::remove_file(&config);
            if let Some(etc) = etc {
                std::fs::write(&config, etc).expect("write");
            }
            let unit = crate::unit::unit(&checked(text)).expect("renders").body;
            let variable = unit
                .lines()
                .find_map(|line| line.strip_prefix("Environment=MYAPPLIANCE_PACKAGE_CONFIG="))
                .expect("the unit names the package's file");
            assert_eq!(variable, "/usr/share/myappliance/config.toml");
            // SAFETY: nothing else here reads this variable, and every read of
            // the environment in this crate's tests goes through std's lock.
            unsafe { std::env::set_var("MYAPPLIANCE_PACKAGE_CONFIG", &package) };
            let b = Resolver::new("myappliance", "MYAPPLIANCE").resolve(&ApplianceArgs {
                config: etc.map(|_| config.clone()),
                ..ApplianceArgs::default()
            });
            unsafe { std::env::remove_var("MYAPPLIANCE_PACKAGE_CONFIG") };
            b.expect("resolves")
        };

        let shipped = body(EXAMPLE, "debian/config.toml");
        assert!(
            shipped
                .lines()
                .all(|line| line.is_empty() || line.starts_with('#')),
            "{shipped}"
        );
        for key in [
            "# bind_address =\n",
            "# https_port =\n",
            "# redirect_port = 0\n",
            "/usr/share/myappliance/config.toml",
            "# [tls]",
            "# cert = ",
            "# key = ",
        ] {
            assert!(shipped.contains(key), "{key}: {shipped}");
        }
        let tls_comment = shipped.split("# [tls]").next().unwrap();
        let tls_comment = tls_comment.rsplit("\n\n").next().unwrap();
        assert!(
            tls_comment.contains("makes its own at first start, at the paths"),
            "the paths shown are the daemon's own pair, not where yours go: {tls_comment}"
        );
        let defaults = resolved(EXAMPLE, Some(&shipped));
        assert_eq!(defaults.bind_address.to_string(), "0.0.0.0");
        assert_eq!(defaults.https_port, 8443);
        assert_eq!(defaults.redirect_port, None);
        assert!(!defaults.tls.named);

        let moved = EXAMPLE
            .replace("https_port = 8443", "https_port = 443")
            .replace(r#"bind_address = "0.0.0.0""#, r#"bind_address = "::""#);
        let operators = "[tls]\ncert = \"/etc/myappliance/cert.pem\"\n";
        let moved_shipped = body(&moved, "debian/config.toml");
        assert_eq!(
            moved_shipped, shipped,
            "a release that moves the port must not change the conffile, or dpkg prompts"
        );
        for etc in [Some(moved_shipped.as_str()), Some(operators), None] {
            let b = resolved(&moved, etc);
            assert_eq!(b.bind_address.to_string(), "::", "{etc:?}");
            assert_eq!(b.https_port, 443, "{etc:?}");
            assert_eq!(b.redirect_port, None, "{etc:?}");
        }

        let named = shipped
            .replace("# [tls]", "[tls]")
            .replace("# cert =", "cert =")
            .replace("# key =", "key =");
        let tls = resolved(EXAMPLE, Some(&named)).tls;
        assert!(tls.named);
        assert_eq!(
            tls.cert,
            std::path::Path::new("/var/lib/myappliance/cert.pem")
        );
    }
}
