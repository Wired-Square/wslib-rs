//! Renders a product's packaging scaffolding from `appliance.toml`.
//!
//! Every file it writes is rewritten unconditionally; a product's own additions
//! live in files it never writes. `--version` names this tool's version (and
//! commit, from a checkout), `build-id` the commit of the product being built.
//! Exit codes: `0` clean, `1` drift or an unpatched erratum site, `2` could not run.

mod debian;
#[cfg(unix)]
mod dev_console;
mod docker;
mod erratum;
mod model;
mod packaging;
mod render;
mod unit;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use model::{Appliance, Checked};
use render::{Artefact, RenderError};

/// Something on disk is not what this version renders, or not safe on a Cortex-A53.
const FOUND: u8 = 1;

/// Something went wrong before anything could be decided.
const COULD_NOT_RUN: u8 = 2;

#[derive(Debug, Parser)]
#[command(name = "wslib-appliance-xtask", version = wslib_build_id::build_version!())]
#[command(about = "Renders an appliance's packaging scaffolding.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// The files that build a package.
    Packaging {
        #[command(subcommand)]
        command: Packaging,
    },
    /// The identity of the build happening in this directory.
    BuildId(Identity),
    /// Refuse an aarch64 binary with a Cortex-A53 erratum 843419 site its linker left unpatched.
    #[command(name = "erratum-843419")]
    Erratum843419 { binary: PathBuf },
    /// Stand in for a console in development: plain HTTP on loopback, proxied to an app socket as one chosen account.
    #[cfg(unix)]
    DevConsole(dev_console::DevConsole),
}

#[derive(Debug, Args)]
struct Identity {
    /// Append the Debian snapshot suffix to this base version.
    #[arg(long, value_name = "BASE")]
    deb_version: Option<String>,
}

/// The rendered scripts take `scaffold/` to be a direct child of the product
/// root, so no flag moves either path.
#[derive(Debug, Subcommand)]
enum Packaging {
    /// Write every chassis-owned file into ./scaffold from ./appliance.toml, overwriting whatever is there.
    Render,
    /// Report every chassis-owned file in ./scaffold that is not what ./appliance.toml renders at this version.
    Diff,
}

const CONFIG: &str = "appliance.toml";
const SCAFFOLD: &str = "scaffold";

/// `ExitCode` rather than `Result`, which would print the error with `Debug`.
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(COULD_NOT_RUN)
        }
    }
}

/// Every file the chassis owns: only these are ever reported as drift, and a
/// product must not edit any of them.
fn chassis_owned(checked: &Checked) -> Result<Vec<Artefact>, RenderError> {
    let deb = checked.appliance.targets.deb.is_some();
    let mut artefacts = Vec::new();
    if deb {
        artefacts.push(unit::sample(checked)?);
        artefacts.extend(debian::hooks_readme(checked)?);
    }
    artefacts.extend(packaging::artefacts(checked)?);
    if deb {
        let dir = Path::new("targets").join(model::DEB);
        let mut target = vec![unit::unit(checked)?];
        target.extend(debian::artefacts(checked)?);
        artefacts.extend(target.into_iter().map(|artefact| Artefact {
            path: dir.join(artefact.path),
            ..artefact
        }));
    }
    if let Some((docker, label)) = checked.docker() {
        artefacts.extend(docker::artefacts(checked, docker, label)?);
    }
    Ok(artefacts)
}

/// Files under `scaffold` that an earlier layout, version or target left, which
/// no render writes or deletes.
fn retired(scaffold: &Path, checked: &Checked) -> Vec<String> {
    const UNREAD: &str = "and nothing reads it";
    let deb = Path::new("targets").join(model::DEB);
    let paths: Vec<(PathBuf, &str)> =
        ["control.in", "postinst", "prerm", "postrm", "journald.conf"]
            .into_iter()
            .map(|file| Path::new("debian").join(file))
            .chain([
                PathBuf::from(format!("systemd/{}.service", checked.appliance.name)),
                PathBuf::from("targets/image"),
                deb.join("debian/journald.conf"),
                deb.join("debian/upgrade"),
                deb.join("debian/upgrade.service"),
            ])
            .map(|path| (path, UNREAD))
            .chain([(
                PathBuf::from("image"),
                "and its build-image.sh would still build a card",
            )])
            .chain(undeclared(checked))
            .collect();
    paths
        .into_iter()
        .map(|(path, why)| (scaffold.join(path), why))
        .filter(|(path, _)| path.exists())
        .map(|(path, why)| {
            format!(
                "{} is no longer rendered from appliance.toml, {why} — delete it",
                path.display()
            )
        })
        .collect()
}

/// The files rendered only for a target `appliance.toml` no longer declares.
fn undeclared(checked: &Checked) -> Vec<(PathBuf, &'static str)> {
    let Appliance { name, targets, .. } = &checked.appliance;
    [
        (
            targets.deb.is_none(),
            "as it declares no [targets.deb]",
            vec![
                PathBuf::from("packaging/make-deb.sh"),
                Path::new("targets").join(model::DEB),
                PathBuf::from(format!("systemd/{name}.service.d/00-example.conf.sample")),
                PathBuf::from("debian/hooks.README"),
            ],
        ),
        (
            targets.docker.is_none(),
            "as it declares no [targets.docker]",
            vec!["packaging/make-image.sh".into(), "targets/docker".into()],
        ),
    ]
    .into_iter()
    .filter(|(dropped, ..)| *dropped)
    .flat_map(|(_, why, paths)| paths.into_iter().map(move |path| (path, why)))
    .collect()
}

/// What `build-id` prints, or why it will not: a build with no commit to name
/// is refused here, the packaging step.
fn identity(id: &wslib_build_id::BuildId, base: Option<&str>) -> Result<String, String> {
    match base {
        // A supplied id is refused too: it carries no commit date to sort on.
        Some(base) => id
            .snapshot_suffix()
            .map(|suffix| format!("{base}{suffix}"))
            .ok_or_else(|| {
                "this build has no commit to make a package version from — build from a \
                 checkout. A build id supplied through the environment does not answer this \
                 either: it is used verbatim for --version and carries no date to sort on"
                    .to_string()
            }),
        None => id.is_known().then(|| id.to_string()).ok_or_else(|| {
            format!(
                "nothing names this build — no {} and no checkout to read. Capturing it here \
                 would carry the literal {:?} into the build, which is what make-deb.sh refuses \
                 to ship",
                wslib_build_id::ENV,
                wslib_build_id::UNKNOWN
            )
        }),
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let command = match Cli::parse().command {
        Command::Packaging { command } => command,
        Command::BuildId(args) => {
            let id = wslib_build_id::BuildId::detect();
            println!("{}", identity(&id, args.deb_version.as_deref())?);
            return Ok(ExitCode::SUCCESS);
        }
        Command::Erratum843419 { binary } => {
            let sites = erratum::unpatched_sites(&binary)?;
            if sites.is_empty() {
                return Ok(ExitCode::SUCCESS);
            }
            for site in &sites {
                println!("{site:#x}");
            }
            eprintln!(
                "error: {} has {} unpatched Cortex-A53 erratum 843419 site(s) — link it with \
                 rust-lld and --fix-cortex-a53-843419, with no RUSTFLAGS or \
                 CARGO_ENCODED_RUSTFLAGS in the environment (data in a code section can also \
                 read as a site)",
                binary.display(),
                sites.len()
            );
            return Ok(ExitCode::from(FOUND));
        }
        #[cfg(unix)]
        Command::DevConsole(args) => {
            dev_console::run(args)?;
            return Ok(ExitCode::SUCCESS);
        }
    };
    let scaffold = Path::new(SCAFFOLD);

    let (checked, warnings) = Appliance::load(Path::new(CONFIG))?;
    for warning in warnings.iter().chain(&retired(scaffold, &checked)) {
        eprintln!("warning: {warning}");
    }
    let artefacts = chassis_owned(&checked)?;

    Ok(match command {
        Packaging::Render => {
            render::write(scaffold, &artefacts)?;
            for artefact in &artefacts {
                println!("wrote {}", scaffold.join(&artefact.path).display());
            }
            ExitCode::SUCCESS
        }
        Packaging::Diff => {
            let compared = render::compare(scaffold, &artefacts);
            let mut drifted = 0usize;
            for (path, state) in &compared {
                if !state.is_drift() {
                    continue;
                }
                drifted += 1;
                println!("{} {}", scaffold.join(path).display(), state.because());
            }

            if drifted == 0 {
                println!("{} chassis-owned files, all in step", compared.len());
                ExitCode::SUCCESS
            } else {
                println!("run `wslib-appliance-xtask packaging render`, then read the diff in git");
                ExitCode::from(FOUND)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{EXAMPLE, checked, docker_only, with_docker, with_every_package_knob};

    /// Every artefact of every shape: the example, everything on, and an image
    /// with no package.
    fn every_artefact() -> Vec<(&'static str, Artefact)> {
        [
            ("example", EXAMPLE.to_string()),
            ("everything-on", with_docker(&with_every_package_knob())),
            ("docker-only", docker_only()),
        ]
        .into_iter()
        .flat_map(|(shape, text)| {
            chassis_owned(&checked(&text))
                .expect("renders")
                .into_iter()
                .map(move |artefact| (shape, artefact))
        })
        .collect()
    }

    #[test]
    fn nothing_the_chassis_owns_still_carries_a_placeholder() {
        for (shape, artefact) in every_artefact() {
            assert!(
                !artefact.body.contains("{{"),
                "{} still has a placeholder for {shape}",
                artefact.path.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn every_rendered_script_is_shell_that_parses() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut checked_any = 0usize;
        for (shape, artefact) in every_artefact() {
            if !artefact.body.starts_with("#!") {
                continue;
            }
            checked_any += 1;

            let mut sh = Command::new("sh")
                .arg("-n")
                .stdin(Stdio::piped())
                .spawn()
                .expect("sh");
            sh.stdin
                .take()
                .expect("stdin")
                .write_all(artefact.body.as_bytes())
                .expect("write");

            assert!(
                sh.wait().expect("sh ran").success(),
                "{} is not shell that parses, for {shape}",
                artefact.path.display()
            );
        }

        // Two in every shape, four in the two with the package, one in the two
        // with the image.
        assert_eq!(
            checked_any,
            2 * 3 + 4 * 2 + 2,
            "the wrong number of scripts was parsed"
        );
    }

    #[test]
    fn make_deb_reads_the_packages_files_where_render_writes_them() {
        let artefacts = chassis_owned(&checked(EXAMPLE)).expect("renders");
        let make_deb = render::commands(&render::body(&artefacts, "packaging/make-deb.sh"));
        for read in [
            r#"TARGET_SCAFFOLD="$SCAFFOLD/targets/$TARGET""#,
            r#"CONTROL_IN="$TARGET_SCAFFOLD/debian/control.in""#,
            r#"UNIT="$TARGET_SCAFFOLD/systemd/$NAME.service""#,
            r#""$TARGET_SCAFFOLD/debian/$script""#,
            "for script in postinst prerm postrm; do",
            r#"[ "$TARGET" = deb ]"#,
        ] {
            assert!(make_deb.contains(read), "{read}: {make_deb}");
        }

        let paths: Vec<_> = artefacts.iter().map(|a| a.path.clone()).collect();
        for file in [
            "systemd/myappliance.service",
            "debian/control.in",
            "debian/postinst",
            "debian/prerm",
            "debian/postrm",
        ] {
            let path = Path::new("targets").join(model::DEB).join(file);
            assert!(paths.contains(&path), "{}", path.display());
        }
    }

    #[test]
    fn what_a_dropped_target_rendered_is_warned_about() {
        let both = checked(&with_docker(EXAMPLE));
        let dir = tempfile::TempDir::new().expect("tempdir");
        render::write(dir.path(), &chassis_owned(&both).expect("renders")).expect("writes");
        assert_eq!(retired(dir.path(), &both), Vec::<String>::new());

        for (text, target, paths) in [
            (
                EXAMPLE.to_string(),
                "docker",
                &["packaging/make-image.sh ", "targets/docker "][..],
            ),
            (
                docker_only(),
                "deb",
                &[
                    "packaging/make-deb.sh ",
                    "targets/deb ",
                    "systemd/myappliance.service.d/00-example.conf.sample ",
                    "debian/hooks.README ",
                ],
            ),
        ] {
            let warned: Vec<String> = retired(dir.path(), &checked(&text))
                .into_iter()
                .map(|w| w.replace('\\', "/"))
                .collect();
            assert_eq!(warned.len(), paths.len(), "{warned:#?}");
            for path in paths {
                assert!(
                    warned.iter().any(|w| w.contains(path)
                        && w.contains(&format!("declares no [targets.{target}]"))),
                    "{path}: {warned:#?}"
                );
            }
        }
    }

    #[test]
    fn a_file_no_render_writes_any_more_is_warned_about() {
        let checked = checked(EXAMPLE);
        let dir = tempfile::TempDir::new().expect("tempdir");
        render::write(dir.path(), &chassis_owned(&checked).expect("renders")).expect("writes");
        assert_eq!(retired(dir.path(), &checked), Vec::<String>::new());

        let left = [
            "debian/postinst",
            "systemd/myappliance.service",
            "targets/image/systemd/myappliance.service",
            "targets/deb/debian/journald.conf",
            "image/build-image.sh",
        ];
        for path in left {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, "").expect("write");
        }
        let warned: Vec<String> = retired(dir.path(), &checked)
            .into_iter()
            .map(|w| w.replace('\\', "/"))
            .collect();
        assert_eq!(warned.len(), left.len(), "{warned:#?}");
        for named in [
            "debian/postinst",
            "systemd/myappliance.service",
            "targets/image",
            "targets/deb/debian/journald.conf",
        ] {
            assert!(
                warned
                    .iter()
                    .any(|w| w.contains(named) && w.contains("nothing reads it")),
                "{named}: {warned:#?}"
            );
        }
        assert!(
            warned
                .iter()
                .any(|w| w.contains("would still build a card")),
            "{warned:#?}"
        );
        assert!(dir.path().join("image/build-image.sh").exists());
    }

    #[test]
    fn no_two_chassis_owned_files_claim_one_path() {
        let mut paths: Vec<_> = chassis_owned(&checked(EXAMPLE))
            .expect("renders")
            .into_iter()
            .map(|a| a.path)
            .collect();
        let rendered = paths.len();
        paths.sort();
        paths.dedup();

        assert_eq!(paths.len(), rendered, "{paths:#?}");
    }

    /// Environment-dependent; the refusals are in `tests/build_id.rs`.
    #[test]
    fn the_two_renderings_agree_about_whether_there_is_a_commit() {
        let id = wslib_build_id::BuildId::detect();

        assert_eq!(identity(&id, None).is_ok(), id.is_known());
        assert_eq!(
            identity(&id, Some("0.1.0")).is_ok(),
            id.snapshot_suffix().is_some()
        );

        if let Ok(version) = identity(&id, Some("0.1.0")) {
            // `~` sorts below the release, so a real 0.1.0 installs over this.
            assert!(version.starts_with("0.1.0~git"), "{version}");
        }
    }
}
