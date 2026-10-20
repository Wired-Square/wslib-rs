use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use wslib_file_atomic::{
    Options, beside, promote, replace_private, replace_readable, write_private,
};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("wslib-file-atomic-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

#[test]
fn a_replace_goes_over_the_old_file() {
    let dir = Scratch::new("replace");
    let path = dir.join("svc.ops");
    fs::write(&path, b"old").unwrap();
    replace_readable(&path, b"new").unwrap();
    assert_eq!(read(&path), b"new");
    assert!(!beside(&path, "new").exists());
    assert!(!dir.join("svc.new").exists(), "the dot is part of the name");
}

#[test]
fn a_failed_write_keeps_the_old_file_and_leaves_no_staged_one() {
    let dir = Scratch::new("failed-write");
    let path = dir.join("config.toml");
    fs::write(&path, b"old").unwrap();
    let failed = Options::new().write_with(&path, |file| {
        io::Write::write_all(file, b"half")?;
        Err(io::Error::other("serialising failed"))
    });
    assert_eq!(failed.unwrap_err().to_string(), "serialising failed");
    assert_eq!(read(&path), b"old");
    assert!(!beside(&path, "new").exists());
}

#[test]
fn a_failed_rename_leaves_no_staged_file() {
    let dir = Scratch::new("failed-rename");
    let path = dir.join("occupied");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("inside"), b"").unwrap();
    assert!(replace_private(&path, b"secret").is_err());
    assert!(!beside(&path, "new").exists());
}

#[test]
fn a_stale_staged_file_is_cleared_and_its_loose_mode_not_kept() {
    let dir = Scratch::new("stale");
    let path = dir.join("token");
    let stale = beside(&path, "new");
    fs::write(&stale, b"stale").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o666)).unwrap();
    }
    replace_private(&path, b"secret").unwrap();
    assert_eq!(read(&path), b"secret");
    assert!(!stale.exists());
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn write_private_refuses_a_path_that_exists() {
    let dir = Scratch::new("create-new");
    let path = dir.join("app.key");
    write_private(&path, b"first").unwrap();
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
    let refused = write_private(&path, b"second").unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(read(&path), b"first");
}

#[test]
fn a_create_new_write_that_fails_removes_what_it_made() {
    let dir = Scratch::new("create-new-failed");
    let path = dir.join("app.key");
    let failed = Options::new()
        .create_new(true)
        .write_with(&path, |_| Err(io::Error::other("card full")));
    assert!(failed.is_err());
    assert!(!path.exists());
}

#[test]
fn staging_is_refused_under_create_new() {
    let dir = Scratch::new("stage-create-new");
    let refused = Options::new()
        .create_new(true)
        .stage(&dir.join("x"), b"")
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn parents_are_created_only_when_asked() {
    let dir = Scratch::new("parents");
    let path = dir.join("a/b/catalogue.toml");
    let missing = replace_readable(&path, b"x").unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    Options::new()
        .create_parents(true)
        .write(&path, b"x")
        .unwrap();
    assert_eq!(read(&path), b"x");
}

#[test]
fn a_custom_suffix_stages_under_that_name_until_promoted() {
    let dir = Scratch::new("suffix");
    let path = dir.join("password");
    fs::write(&path, b"old").unwrap();
    let staged = Options::new()
        .staging_suffix("next")
        .stage(&path, b"rotated")
        .unwrap();
    assert_eq!(staged.path(), dir.join("password.next"));
    assert_eq!(read(staged.path()), b"rotated");
    assert_eq!(read(&path), b"old");
    #[cfg(unix)]
    assert_eq!(mode(staged.path()), 0o600);

    staged.promote().unwrap();
    assert_eq!(read(&path), b"rotated");
    assert!(!dir.join("password.next").exists());
}

#[test]
fn a_staged_file_outlives_its_handle_and_is_promoted_by_path() {
    let dir = Scratch::new("restart");
    let path = dir.join("password");
    fs::write(&path, b"old").unwrap();
    drop(
        Options::new()
            .staging_suffix("next")
            .stage(&path, b"rotated"),
    );
    assert!(dir.join("password.next").exists());

    promote(&path, "next").unwrap();
    assert_eq!(read(&path), b"rotated");
    assert!(!dir.join("password.next").exists());
}

#[test]
fn a_failed_promote_leaves_the_staged_file_for_a_retry() {
    let dir = Scratch::new("failed-promote");
    let path = dir.join("occupied");
    let staged = Options::new().stage(&path, b"secret").unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("inside"), b"").unwrap();
    assert!(staged.promote().is_err());
    assert_eq!(read(&beside(&path, "new")), b"secret");
}

#[test]
fn discard_removes_the_staged_file_and_keeps_the_target() {
    let dir = Scratch::new("discard");
    let path = dir.join("password");
    fs::write(&path, b"old").unwrap();
    let staged = Options::new().stage(&path, b"rotated").unwrap();
    staged.discard().unwrap();
    assert!(!beside(&path, "new").exists());
    assert_eq!(read(&path), b"old");
}

#[test]
fn beside_appends_to_the_whole_name() {
    assert_eq!(
        beside(Path::new("/x/app.crt"), "new"),
        PathBuf::from("/x/app.crt.new")
    );
    assert_eq!(
        beside(Path::new("token"), "next"),
        PathBuf::from("token.next")
    );
}

#[cfg(unix)]
#[test]
fn owner_only_tightens_an_existing_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new("owner-only");
    let path = dir.join("store.db-wal");
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    wslib_file_atomic::owner_only(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
}
