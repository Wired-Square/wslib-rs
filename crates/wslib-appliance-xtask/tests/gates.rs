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

fn gates(dir: &Path) -> (Option<i32>, String) {
    let Output { status, stdout, .. } = Command::new(EXE)
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
    for (program, args) in [
        ("git", ["init", "-q"]),
        ("cargo", ["generate-lockfile", "-q"]),
    ] {
        let mut command = Command::new(program);
        for (var, _) in std::env::vars_os() {
            if var.to_string_lossy().starts_with("GIT_") {
                command.env_remove(var);
            }
        }
        let ran = command
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect(program);
        assert!(ran.success(), "{program}");
    }

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
