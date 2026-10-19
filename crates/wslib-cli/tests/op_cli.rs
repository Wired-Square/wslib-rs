#![cfg(all(unix, feature = "op"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use wslib_cli::op::{OpCli, OpError, ReadReference};

/// A stand-in `op` that echoes its arguments, or fails on `op://x/...`.
fn fake_op() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fake-op");
    fs::write(
        &path,
        "#!/bin/sh\ncase \"$3\" in op://x/*) echo \"[ERROR] no such vault\" >&2; exit 1;; esac\nprintf '%s ' \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn reads_with_op_read_without_a_newline() {
    let out = OpCli::new(fake_op()).read("op://ci/forge/token").unwrap();
    assert_eq!(out, "read --no-newline op://ci/forge/token ");
}

#[test]
fn a_refusal_carries_ops_message() {
    let error = OpCli::new(fake_op()).read("op://x/item/field").unwrap_err();
    assert!(
        matches!(&error, OpError::Failed { message, .. } if message == "[ERROR] no such vault"),
        "{error:?}"
    );
}
