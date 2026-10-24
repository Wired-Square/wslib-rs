//! The installer's layout, checked rather than trusted: each answers the
//! sentence a refusal ends with.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub(crate) fn private_directory(dir: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("it is a symbolic link".to_string());
    }
    if !metadata.is_dir() {
        return Err("it is not a directory".to_string());
    }
    // SAFETY: `geteuid` reads this process's own credentials and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(format!(
            "it is owned by uid {}, not this process's {euid}",
            metadata.uid()
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o027 != 0 {
        return Err(format!(
            "its mode is {mode:04o}; its group may not write it and others may not use it"
        ));
    }
    no_extended_acl(dir)
}

#[cfg(target_os = "macos")]
fn no_extended_acl(dir: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    unsafe extern "C" {
        fn acl_get_link_np(path: *const libc::c_char, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
    }

    let unreadable = |e: std::io::Error| format!("its ACL could not be read: {e}");
    let path = CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| unreadable(std::io::Error::other(e)))?;
    // SAFETY: `path` is a live NUL-terminated string; a non-null answer is an
    // ACL this owns and frees.
    let acl = unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOENT) => Ok(()),
            _ => Err(unreadable(e)),
        };
    }
    unsafe { acl_free(acl) };
    Err("it carries an extended ACL".to_string())
}

#[cfg(not(target_os = "macos"))]
fn no_extended_acl(_: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::private_directory;
    use crate::test_dir::TempDir;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn state_dir(dir: &TempDir) -> std::path::PathBuf {
        let state = dir.join("state");
        std::fs::create_dir(&state).unwrap();
        chmod(&state, 0o700);
        state
    }

    fn refusal(dir: &Path) -> String {
        private_directory(dir).expect_err("refuses").to_string()
    }

    #[test]
    fn a_private_directory_passes_and_its_group_may_read_it() {
        let dir = TempDir::new("private");
        let state = state_dir(&dir);
        let _held = private_directory(&state).expect("passes");
        chmod(&state, 0o750);
        let _held = private_directory(&state).expect("its group may read it");
    }

    #[test]
    fn a_directory_open_to_others_or_writable_by_its_group_refuses() {
        for mode in [0o720, 0o701, 0o704, 0o755] {
            let dir = TempDir::new("private");
            let state = state_dir(&dir);
            chmod(&state, mode);

            let said = refusal(&state);
            assert!(
                said.starts_with(&format!("refusing {}: ", state.display()))
                    && said.contains(&format!("its mode is {mode:04o}")),
                "{said}"
            );
        }
    }

    #[test]
    fn a_directory_behind_a_link_or_not_a_directory_refuses() {
        let dir = TempDir::new("private");
        let link = dir.join("linked");
        std::os::unix::fs::symlink(state_dir(&dir), &link).unwrap();
        assert!(refusal(&link).ends_with("it is a symbolic link"));

        let file = dir.join("file");
        std::fs::write(&file, "").unwrap();
        assert!(refusal(&file).ends_with("it is not a directory"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_directory_with_an_extended_acl_refuses() {
        let dir = TempDir::new("private");
        let state = state_dir(&dir);
        let added = std::process::Command::new("chmod")
            .args(["+a", "everyone allow list"])
            .arg(&state)
            .status()
            .unwrap();
        assert!(added.success());
        assert!(refusal(&state).ends_with("it carries an extended ACL"));
    }
}
