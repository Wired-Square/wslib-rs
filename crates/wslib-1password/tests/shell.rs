#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use wslib_1password::{Error, Op, ReadReference, ShellRunner};

/// A stand-in `op` that echoes its arguments, or fails on `op://x/...`.
fn fake_op() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fake-op");
    fs::write(
        &path,
        "#!/bin/sh\ncase \"$3\" in op://x/*) echo \"[ERROR] vault x not found\" >&2; exit 1;; esac\nprintf '%s ' \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn op() -> Op {
    Op::new(ShellRunner::new().with_program(fake_op()), "ops")
}

#[test]
fn reads_with_op_read_without_a_newline() {
    let out = op().read_reference("op://ci/forge/token").unwrap();
    assert_eq!(
        out.expose(),
        "read --no-newline op://ci/forge/token --account ops "
    );
}

#[test]
fn a_refusal_carries_ops_message() {
    let error = op().read_reference("op://x/item/field").unwrap_err();
    assert!(
        matches!(&error, Error::VaultNotFound(m) if m == "[ERROR] vault x not found"),
        "{error:?}"
    );
}
