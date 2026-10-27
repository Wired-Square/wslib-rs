//! `gates` over a product with no dependencies, through the process, since a
//! product's CI reads only its output and exit code.

use std::path::Path;
use std::process::{Command, Output};

const EXE: &str = env!("CARGO_BIN_EXE_wslib-appliance-xtask");

fn put(dir: &Path, path: &str, body: &str) {
    let path = dir.join(path);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    std::fs::write(path, body).expect("write");
}

fn scrubbed(program: &str) -> Command {
    let mut command = Command::new(program);
    for (var, _) in std::env::vars_os() {
        if var.to_string_lossy().starts_with("GIT_") {
            command.env_remove(var);
        }
    }
    command
}

fn run(dir: &Path, program: &str, args: &[&str]) {
    let ran = scrubbed(program)
        .args(args)
        .current_dir(dir)
        .status()
        .expect(program);
    assert!(ran.success(), "{program}");
}

fn gates(dir: &Path) -> (Option<i32>, String) {
    let Output { status, stdout, .. } = scrubbed(EXE)
        .arg("gates")
        .current_dir(dir)
        .output()
        .expect("runs");
    (status.code(), String::from_utf8_lossy(&stdout).into_owned())
}

#[test]
fn a_clean_product_passes_and_a_planted_macro_fails_it() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    put(
        dir.path(),
        "Cargo.toml",
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
    );
    put(dir.path(), "src/lib.rs", "");
    run(dir.path(), "git", &["init", "-q"]);
    run(dir.path(), "cargo", &["generate-lockfile", "-q"]);

    let (code, said) = gates(dir.path());
    assert_eq!(code, Some(0), "{said}");
    assert_eq!(
        said,
        "forbidden names: skipped, no scripts/forbidden-names.txt\n\
         sqlx query macros: ok\n\
         lock: ok\n\
         rustls provider: skipped, no rustls in the graph\n\
         packaging: skipped, no appliance.toml\n"
    );

    put(
        dir.path(),
        "src/lib.rs",
        concat!("fn f() { sqlx::", "query!(\"SELECT 1\"); }\n"),
    );
    let (code, said) = gates(dir.path());
    assert_eq!(code, Some(1), "{said}");
    assert!(said.contains("sqlx query macros: failed"), "{said}");
    assert!(said.contains("  src/lib.rs:1:"), "{said}");
}

#[test]
fn a_gate_that_could_not_run_exits_2() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    put(dir.path(), "Cargo.lock", "version = 4\n");
    run(dir.path(), "git", &["init", "-q"]);

    let (code, said) = gates(dir.path());
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains("rustls provider: could not run, cargo tree: "),
        "{said}"
    );
}
