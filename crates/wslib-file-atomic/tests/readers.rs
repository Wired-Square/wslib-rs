use std::fs;

mod common;

use common::{Scratch, read};
use wslib_file_atomic::testing::assert_owner_only;

#[test]
fn a_private_write_is_owner_only() {
    let dir = Scratch::new("readers-private");
    let path = dir.join("token");
    wslib_file_atomic::replace_private(&path, b"secret").unwrap();
    assert_owner_only(&path);
    assert_eq!(read(&path), b"secret");
}

#[test]
fn owner_only_tightens_an_existing_file() {
    let dir = Scratch::new("readers-owner-only");
    let path = dir.join("store.db-wal");
    fs::write(&path, b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    wslib_file_atomic::owner_only(&path).unwrap();
    assert_owner_only(&path);
}

#[test]
#[should_panic]
fn a_file_anyone_may_read_is_not_owner_only() {
    let dir = Scratch::new("readers-readable");
    let path = dir.join("authorized_keys");
    wslib_file_atomic::replace_readable(&path, b"ssh-ed25519 AAAA").unwrap();
    assert_owner_only(&path);
}

#[cfg(windows)]
#[test]
fn administrators_may_read_and_delete_a_file_this_user_owns() {
    use std::process::Command;
    use wslib_file_atomic::testing::assert_administrators_read_and_delete;

    let dir = Scratch::new("readers-administrators");
    let path = dir.join("service.log");
    fs::write(&path, b"").unwrap();
    let user = Command::new("whoami").output().unwrap().stdout;
    let user = String::from_utf8(user).unwrap();
    let owned = Command::new("icacls")
        .arg(&path)
        .args(["/setowner", user.trim()])
        .status()
        .unwrap();
    assert!(owned.success(), "owned by {user}, not Administrators");

    wslib_file_atomic::administrators_read_and_delete(&path).unwrap();
    assert_administrators_read_and_delete(&path);
}
