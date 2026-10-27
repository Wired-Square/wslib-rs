//! `gates`: the rules a product's CI checks with the version of this tool it
//! installs, so a new rule reaches a product only when it bumps that version.
//!
//! The default run greps and resolves but compiles nothing; `--release` adds
//! the builds, for a tag.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitCode};

use serde::Deserialize;

/// The family crates whose layout and keys the rendered files assume.
pub const RENDERS_FOR: [(&str, &str); 3] = [
    ("wslib-appliance-config", "0.1.1"),
    ("wslib-appliance-store", "0.1.1"),
    ("wslib-appliance-server", "0.1.0"),
];

const FORBIDDEN_NAMES: &str = "scripts/forbidden-names.txt";

const SQLX_MACRO: &str = r"sqlx::(query|query_as|query_scalar|query_file)[a-z_]*!";

const PROVIDERS: [&str; 2] = ["ring", "aws-lc-rs"];

const CROSS: &str = "aarch64-unknown-linux-musl";

/// `CROSS` as it is spelt in `CC_<triple>` and `AR_<triple>`.
const CROSS_VAR: &str = "aarch64_unknown_linux_musl";

const CLIPPY: [&str; 4] = ["clippy", "--workspace", "--all-targets", "--locked"];

const DENY_WARNINGS: [&str; 3] = ["--", "-D", "warnings"];

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Skipped(String),
    Failed { why: String, hits: Vec<String> },
}

fn failed_with(why: impl Into<String>, hits: Vec<String>) -> Outcome {
    Outcome::Failed {
        why: why.into(),
        hits,
    }
}

fn failed(why: impl Into<String>) -> Outcome {
    failed_with(why, Vec::new())
}

#[derive(Debug)]
pub struct Verdict {
    pub outcome: Outcome,
    pub warnings: Vec<String>,
}

impl From<Outcome> for Verdict {
    fn from(outcome: Outcome) -> Self {
        Verdict {
            outcome,
            warnings: Vec::new(),
        }
    }
}

/// Run every gate in `root`, reporting each as it finishes; warnings never fail.
pub fn run(root: &Path, release: bool) -> ExitCode {
    let mut any_failed = false;
    let mut report = |name: &str, verdict: Verdict| {
        for warning in &verdict.warnings {
            eprintln!("warning: {name}: {warning}");
        }
        match verdict.outcome {
            Outcome::Passed => println!("{name}: ok"),
            Outcome::Skipped(why) => println!("{name}: skipped, {why}"),
            Outcome::Failed { why, hits } => {
                any_failed = true;
                println!("{name}: failed, {why}");
                for hit in hits {
                    println!("  {hit}");
                }
            }
        }
    };

    report("forbidden names", forbidden_names(root).into());
    report("sqlx query macros", sqlx_macros(root).into());
    report(
        "lock",
        match std::fs::read_to_string(root.join("Cargo.lock")) {
            Ok(text) => lock(&text),
            Err(e) => failed(format!("Cargo.lock could not be read: {e}")).into(),
        },
    );
    report("rustls provider", rustls_provider(root).into());
    report("packaging", packaging(root));
    if release {
        report("cross clippy", cross_clippy(root).into());
        report(
            "clippy",
            cargo(root, &[&CLIPPY[..], &DENY_WARNINGS].concat()).into(),
        );
        report(
            "test",
            cargo(root, &["test", "--workspace", "--locked"]).into(),
        );
    }

    if any_failed {
        ExitCode::from(crate::FOUND)
    } else {
        ExitCode::SUCCESS
    }
}

fn could_not_run(what: &str, because: impl std::fmt::Display) -> Outcome {
    failed(format!("{what} could not run: {because}"))
}

/// `git` that finds its repository from its own directory: under a git hook,
/// `GIT_DIR` and its kin name the hook's repository instead.
fn git() -> Command {
    let mut git = Command::new("git");
    for (var, _) in std::env::vars_os() {
        if var.to_string_lossy().starts_with("GIT_") {
            git.env_remove(var);
        }
    }
    git
}

/// `git grep`, where a match is the failure.
fn grep(root: &Path, args: &[&str], why: &str) -> Outcome {
    match git().arg("grep").args(args).current_dir(root).output() {
        Ok(out) if out.status.code() == Some(1) => Outcome::Passed,
        Ok(out) if out.status.success() => failed_with(
            why,
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(String::from)
                .collect(),
        ),
        Ok(out) => could_not_run("git grep", String::from_utf8_lossy(&out.stderr).trim()),
        Err(e) => could_not_run("git grep", e),
    }
}

pub fn forbidden_names(root: &Path) -> Outcome {
    match std::fs::read_to_string(root.join(FORBIDDEN_NAMES)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Outcome::Skipped(format!("no {FORBIDDEN_NAMES}"));
        }
        Err(e) => return failed(format!("{FORBIDDEN_NAMES} could not be read: {e}")),
        Ok(names) if names.trim().is_empty() => {
            return Outcome::Skipped(format!("{FORBIDDEN_NAMES} names nothing"));
        }
        Ok(_) => {}
    }
    grep(
        root,
        &[
            "-nIiE",
            "--untracked",
            "-f",
            FORBIDDEN_NAMES,
            "--",
            &format!(":!{FORBIDDEN_NAMES}"),
        ],
        &format!("a name {FORBIDDEN_NAMES} forbids is in the tree"),
    )
}

pub fn sqlx_macros(root: &Path) -> Outcome {
    grep(
        root,
        &["-nE", "--untracked", SQLX_MACRO, "--", "*.rs"],
        "a sqlx query! macro needs a database to build; use the runtime sqlx::query API",
    )
}

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    package: Vec<Locked>,
}

#[derive(Deserialize)]
struct Locked {
    name: String,
    version: String,
    source: Option<String>,
}

/// Every family crate in `text`, a `Cargo.lock`, comes from a registry, and
/// one this tool renders for at another version is a warning.
pub fn lock(text: &str) -> Verdict {
    let lock: Lock = match toml::from_str(text) {
        Ok(lock) => lock,
        Err(e) => return failed(format!("Cargo.lock does not parse: {e}")).into(),
    };
    let family: Vec<&Locked> = lock
        .package
        .iter()
        .filter(|p| p.name.starts_with("wslib-appliance"))
        .collect();
    let unregistered: Vec<String> = family
        .iter()
        .filter_map(|p| match p.source.as_deref() {
            Some(s) if s.starts_with("registry+") || s.starts_with("sparse+") => None,
            Some(s) => Some(format!("{} {} from {s}", p.name, p.version)),
            None => Some(format!("{} {} by path", p.name, p.version)),
        })
        .collect();
    let warnings = family
        .iter()
        .filter_map(|p| {
            RENDERS_FOR
                .iter()
                .find(|(name, version)| *name == p.name && *version != p.version)
                .map(|(_, version)| {
                    format!(
                        "{} is locked at {}; this tool renders for {version}",
                        p.name, p.version
                    )
                })
        })
        .collect();
    Verdict {
        outcome: if unregistered.is_empty() {
            Outcome::Passed
        } else {
            failed_with(
                "a family crate is not from a registry, so a tag of this product cannot be rebuilt",
                unregistered,
            )
        },
        warnings,
    }
}

fn rustls_provider(root: &Path) -> Outcome {
    let args = [
        "tree",
        "--workspace",
        "--locked",
        "--target",
        "all",
        "-e",
        "normal",
        "--prefix",
        "none",
    ];
    match Command::new("cargo").args(args).current_dir(root).output() {
        Ok(out) if out.status.success() => providers(&String::from_utf8_lossy(&out.stdout)),
        Ok(out) => could_not_run("cargo tree", String::from_utf8_lossy(&out.stderr).trim()),
        Err(e) => could_not_run("cargo tree", e),
    }
}

/// Exactly one rustls provider in `tree`, the output of `cargo tree --prefix none`.
pub fn providers(tree: &str) -> Outcome {
    let crates: BTreeSet<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let found: Vec<String> = PROVIDERS
        .into_iter()
        .filter(|p| crates.contains(p))
        .map(String::from)
        .collect();
    match found.len() {
        1 => Outcome::Passed,
        _ if !crates.contains("rustls") => Outcome::Skipped("no rustls in the graph".into()),
        0 => failed("rustls has no provider; depend on rustls with the ring or aws-lc-rs feature"),
        _ => failed_with(
            "two rustls providers, and a process default cannot choose between them",
            found,
        ),
    }
}

fn packaging(root: &Path) -> Verdict {
    if !root.join(crate::CONFIG).is_file() {
        return Outcome::Skipped(format!("no {}", crate::CONFIG)).into();
    }
    match crate::owned(root) {
        Err(e) => failed(e.to_string()).into(),
        Ok((artefacts, warnings)) => {
            let drifted = crate::drifted(&root.join(crate::SCAFFOLD), &artefacts);
            Verdict {
                outcome: if drifted.is_empty() {
                    Outcome::Passed
                } else {
                    failed_with(crate::RENDER_AGAIN, drifted)
                },
                warnings,
            }
        }
    }
}

fn cargo(root: &Path, args: &[&str]) -> Outcome {
    match Command::new("cargo").args(args).current_dir(root).status() {
        Ok(status) if status.success() => Outcome::Passed,
        Ok(status) => failed(format!("cargo {} {status}", args.join(" "))),
        Err(e) => could_not_run("cargo", e),
    }
}

fn cross_clippy(root: &Path) -> Outcome {
    let var = |tool: &str| std::env::var_os(format!("{tool}_{CROSS_VAR}"));
    match cross_target(root).and_then(|()| cross_compiler(var("CC"), var("AR"))) {
        Ok(()) => cargo(
            root,
            &[&CLIPPY[..], &["--target", CROSS], &DENY_WARNINGS].concat(),
        ),
        Err(missing) => failed(missing),
    }
}

fn cross_target(root: &Path) -> Result<(), String> {
    let libdir = Command::new("rustc")
        .args(["--print", "target-libdir", "--target", CROSS])
        .current_dir(root)
        .output()
        .map_err(|e| format!("rustc could not run: {e}"))?;
    let libdir = String::from_utf8_lossy(&libdir.stdout);
    if Path::new(libdir.trim()).is_dir() {
        Ok(())
    } else {
        Err(format!(
            "{CROSS} is not installed: rustup target add {CROSS}"
        ))
    }
}

/// A build script of a dependency compiles C for the target, so clippy needs
/// a C compiler and an archiver for it: `cc` and `ar` are the
/// `CC_`/`AR_<triple>` variables, as cc-rs reads them.
fn cross_compiler(cc: Option<OsString>, ar: Option<OsString>) -> Result<(), String> {
    let runs = |tool: Option<OsString>, fallback: &str| {
        let tool = tool.unwrap_or_else(|| fallback.into());
        let tool = tool.to_string_lossy();
        let mut words = tool.split_whitespace();
        words.next().is_some_and(|program| {
            Command::new(program)
                .args(words)
                .arg("--version")
                .output()
                .is_ok_and(|out| out.status.success())
        })
    };
    if runs(cc, "aarch64-linux-musl-gcc") && runs(ar, "aarch64-linux-musl-ar") {
        Ok(())
    } else {
        Err(format!(
            "no C compiler and archiver for {CROSS} answered --version: set CC_{CROSS_VAR} and AR_{CROSS_VAR} \
             (shims over `zig cc` and `zig ar`, as the README's Gates section has them), or \
             put aarch64-linux-musl-gcc and aarch64-linux-musl-ar on PATH"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EXAMPLE;
    use tempfile::TempDir;

    const REGISTRY: &str = "sparse+https://forge.example/api/packages/family/cargo/";

    fn locked(name: &str, version: &str, source: Option<&str>) -> String {
        let source = source.map_or(String::new(), |s| format!(", source = \"{s}\""));
        format!("{{ name = \"{name}\", version = \"{version}\"{source} }}")
    }

    /// Inline tables, as the repository's citation gate reads a doubled
    /// bracket as a link.
    fn lock_of(packages: &[String]) -> String {
        format!("version = 4\npackage = [\n{}\n]\n", packages.join(",\n"))
    }

    fn a_repository() -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        let init = git()
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .expect("git");
        assert!(init.success());
        dir
    }

    fn put(dir: &Path, path: &str, body: &str) {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, body).expect("write");
    }

    fn hits(outcome: Outcome) -> Vec<String> {
        match outcome {
            Outcome::Failed { hits, .. } => hits,
            other => panic!("passed or skipped: {other:?}"),
        }
    }

    #[test]
    fn the_rendered_for_versions_are_the_ones_the_readme_names() {
        let readme = include_str!("../README.md").replace('\n', " ");
        for (name, version) in RENDERS_FOR {
            assert!(readme.contains(&format!("`{name}` {version}")), "{name}");
        }
    }

    #[test]
    fn family_crates_from_the_registry_pass_and_others_do_not() {
        let fine = lock_of(&[
            locked("wslib-appliance-config", "0.1.1", Some(REGISTRY)),
            locked(
                "wslib-appliance-core",
                "0.1.0",
                Some("registry+https://forge.example/index"),
            ),
            locked("serde", "1.0.0", Some("git+https://example.com/serde#abc")),
            locked("myappliance", "0.1.0", None),
        ]);
        let verdict = lock(&fine);
        assert_eq!(verdict.outcome, Outcome::Passed);
        assert!(verdict.warnings.is_empty(), "{:?}", verdict.warnings);

        let git = lock_of(&[locked(
            "wslib-appliance-store",
            "0.1.1",
            Some("git+https://example.com/family#abc"),
        )]);
        assert_eq!(
            hits(lock(&git).outcome),
            ["wslib-appliance-store 0.1.1 from git+https://example.com/family#abc"]
        );

        let path = lock_of(&[locked("wslib-appliance-server", "0.1.0", None)]);
        assert_eq!(
            hits(lock(&path).outcome),
            ["wslib-appliance-server 0.1.0 by path"]
        );
    }

    #[test]
    fn a_family_crate_at_another_version_warns_naming_both_and_passes() {
        let older = lock_of(&[
            locked("wslib-appliance-config", "0.1.0", Some(REGISTRY)),
            locked("wslib-appliance-core", "0.9.0", Some(REGISTRY)),
        ]);
        let verdict = lock(&older);
        assert_eq!(verdict.outcome, Outcome::Passed);
        assert_eq!(
            verdict.warnings,
            ["wslib-appliance-config is locked at 0.1.0; this tool renders for 0.1.1"]
        );
    }

    #[test]
    fn a_lock_that_does_not_parse_fails() {
        assert!(matches!(
            lock("[[package]\n").outcome,
            Outcome::Failed { .. }
        ));
    }

    #[test]
    fn exactly_one_rustls_provider_passes() {
        assert_eq!(
            providers(
                "myappliance v0.1.0 (/src)\nrustls v0.23.27\nring v0.17.14\nring v0.17.14 (*)\n"
            ),
            Outcome::Passed
        );
        assert_eq!(
            hits(providers(
                "rustls v0.23.27\nring v0.17.14\naws-lc-rs v1.13.0\n"
            )),
            ["ring", "aws-lc-rs"]
        );
        assert!(matches!(
            providers("rustls v0.23.27\nrustls-pki-types v1.0.0\n"),
            Outcome::Failed { .. }
        ));
        assert!(matches!(
            providers("myappliance v0.1.0 (/src)\n"),
            Outcome::Skipped(_)
        ));
    }

    #[test]
    fn a_cargo_tree_that_fails_fails_rather_than_finding_no_rustls() {
        let dir = TempDir::new().expect("tempdir");
        assert!(matches!(
            rustls_provider(dir.path()),
            Outcome::Failed { .. }
        ));
    }

    #[test]
    fn a_forbidden_name_is_found_and_no_list_is_a_skip() {
        let dir = a_repository();
        put(dir.path(), "src/lib.rs", "//! A widget.\n");
        assert!(matches!(forbidden_names(dir.path()), Outcome::Skipped(_)));

        put(dir.path(), FORBIDDEN_NAMES, "\n");
        assert!(matches!(forbidden_names(dir.path()), Outcome::Skipped(_)));

        put(dir.path(), FORBIDDEN_NAMES, "gadget.?co\n");
        assert_eq!(forbidden_names(dir.path()), Outcome::Passed);

        put(dir.path(), "src/lib.rs", "//! A widget for GadgetCo.\n");
        assert_eq!(
            hits(forbidden_names(dir.path())),
            ["src/lib.rs:1://! A widget for GadgetCo."]
        );
    }

    #[test]
    fn a_compile_time_checked_query_is_found() {
        let dir = a_repository();
        put(
            dir.path(),
            "src/lib.rs",
            "fn f() { sqlx::query(\"SELECT 1\"); }\n",
        );
        assert_eq!(sqlx_macros(dir.path()), Outcome::Passed);

        let planted = concat!("fn f() { sqlx::", "query_as!(Row, \"SELECT 1\"); }\n");
        put(dir.path(), "src/lib.rs", planted);
        assert_eq!(
            hits(sqlx_macros(dir.path())),
            [format!("src/lib.rs:1:{}", planted.trim_end())]
        );
    }

    #[test]
    fn a_grep_outside_a_repository_fails_rather_than_passing() {
        let dir = TempDir::new().expect("tempdir");
        assert!(matches!(sqlx_macros(dir.path()), Outcome::Failed { .. }));
    }

    #[test]
    fn packaging_out_of_step_fails_and_no_appliance_toml_is_a_skip() {
        let dir = TempDir::new().expect("tempdir");
        assert!(matches!(packaging(dir.path()).outcome, Outcome::Skipped(_)));

        put(dir.path(), crate::CONFIG, EXAMPLE);
        let (artefacts, _) = crate::owned(dir.path()).expect("renders");
        crate::render::write(&dir.path().join(crate::SCAFFOLD), &artefacts).expect("writes");
        assert_eq!(packaging(dir.path()).outcome, Outcome::Passed);

        put(dir.path(), "scaffold/packaging/build-id.sh", "#!/bin/sh\n");
        let drifted = hits(packaging(dir.path()).outcome);
        assert_eq!(drifted.len(), 1, "{drifted:?}");
        assert!(drifted[0].contains("build-id.sh"), "{drifted:?}");
    }

    #[test]
    fn a_cargo_that_fails_fails_the_gate() {
        let dir = TempDir::new().expect("tempdir");
        assert_eq!(cargo(dir.path(), &["--version"]), Outcome::Passed);
        assert!(matches!(
            cargo(dir.path(), &["no-such-subcommand"]),
            Outcome::Failed { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_cross_compiler_that_does_not_run_is_named_before_clippy_starts() {
        assert_eq!(
            cross_compiler(Some("true".into()), Some("true".into())),
            Ok(())
        );

        let missing = cross_compiler(Some("/nonexistent/cc".into()), Some("true".into()))
            .expect_err("no compiler");
        assert!(
            missing.contains("CC_aarch64_unknown_linux_musl"),
            "{missing}"
        );
        assert!(cross_compiler(Some("true".into()), Some("false".into())).is_err());
    }
}
