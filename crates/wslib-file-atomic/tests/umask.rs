#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

/// A test at a developer's `022` would pass with no `fchmod`.
#[test]
fn modes_hold_under_a_restrictive_umask() {
    let dir = std::env::temp_dir().join(format!("wslib-file-atomic-umask-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let readable = dir.join("authorized_keys");
    let private = dir.join("token");

    // SAFETY: the only test in this binary, so no other thread creates files under the mask.
    let was = unsafe { libc::umask(0o077) };
    let written = wslib_file_atomic::replace_readable(&readable, b"ssh-ed25519 AAAA")
        .and_then(|()| wslib_file_atomic::replace_private(&private, b"secret"));
    unsafe { libc::umask(was) };
    written.unwrap();

    let mode = |path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&readable), 0o644);
    assert_eq!(mode(&private), 0o600);
    std::fs::remove_dir_all(&dir).unwrap();
}
