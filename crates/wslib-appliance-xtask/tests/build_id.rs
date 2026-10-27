//! The `build-id` refusals, reachable only through the process: `BuildId` has
//! no public constructor, and `make-deb.sh` depends on the exit code.

use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_wslib-appliance-xtask");

/// `COULD_NOT_RUN` in `main.rs`.
const COULD_NOT_RUN: i32 = 2;

/// A supplied id carries no commit date to sort on, so it cannot become a
/// Debian version.
#[test]
fn a_supplied_build_id_is_refused_as_a_package_version() {
    let out = Command::new(EXE)
        .args(["build-id", "--deb-version", "0.1.0"])
        .env("WSLIB_BUILD_ID", "gdeadbeefcafe")
        .output()
        .expect("runs");

    assert_eq!(out.status.code(), Some(COULD_NOT_RUN));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("checkout"), "{said}");
}

#[test]
fn the_same_supplied_id_is_still_a_build_stamp() {
    let out = Command::new(EXE)
        .arg("build-id")
        .env("WSLIB_BUILD_ID", "gdeadbeefcafe")
        .output()
        .expect("runs");

    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "gdeadbeefcafe");
}

#[test]
fn a_build_with_nothing_to_name_it_is_refused_rather_than_called_unknown() {
    for args in [vec!["build-id"], vec!["build-id", "--deb-version", "0.1.0"]] {
        let out = Command::new(EXE)
            .args(&args)
            // Empty is not a supplied id, and overrides an inherited one.
            .env("WSLIB_BUILD_ID", "")
            .env("GIT_DIR", "/nonexistent")
            .output()
            .expect("runs");

        assert_eq!(out.status.code(), Some(COULD_NOT_RUN), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).trim().is_empty(),
            "a refusal printed something a script would have used: {args:?}"
        );
    }
}
