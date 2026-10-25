//! The state directory, and the folders it and the log are in, checked on
//! Windows, where who may use them is their owner and DACL rather than their
//! mode, and a file made in one takes the directory's inheritable entries.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
    IsWellKnownSid, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    WinCreatorOwnerRightsSid, WinCreatorOwnerSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::Refused;

/// What a DACL may not allow anyone but this process's user, SYSTEM and
/// Administrators, and the refusal that says so.
pub(crate) struct Rule {
    forbidden: u32,
    refusal: &'static str,
}

const NOTHING: Rule = Rule {
    forbidden: u32::MAX,
    refusal: "its DACL allows someone besides this process's user, SYSTEM and Administrators",
};

const NO_REPLACING: Rule = Rule {
    forbidden: FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL,
    refusal: "its DACL lets someone besides this process's user, SYSTEM and Administrators \
              delete from it, rename it or change its security",
};

pub(crate) const NO_ADDING_OR_REPLACING: Rule = Rule {
    forbidden: NO_REPLACING.forbidden | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY,
    refusal: "its DACL lets someone besides this process's user, SYSTEM and Administrators \
              add to it, delete from it, rename it or change its security",
};

/// A directory, not a link or junction, owned by this process's user, SYSTEM or
/// Administrators, whose DACL allows nobody else anything, in a directory that
/// passes [`parent_directory`] with nobody else allowed to delete from it,
/// rename it or change its security. Both are held open until the handles
/// drop, so neither can be renamed.
pub(crate) fn private_directory(dir: &Path) -> Result<[File; 2], Refused> {
    Ok([
        parent_directory(dir, &NO_REPLACING)?,
        checked_directory(dir, &NOTHING)?,
    ])
}

/// The directory `path` is in, not a link or junction, owned by this process's
/// user, SYSTEM or Administrators, whose DACL allows nobody else what `rule`
/// forbids; held open until the handle drops.
pub(crate) fn parent_directory(path: &Path, rule: &Rule) -> Result<File, Refused> {
    let parent = match path.parent().unwrap_or(path) {
        parent if parent.as_os_str().is_empty() => Path::new("."),
        parent => parent,
    };
    checked_directory(parent, rule)
}

pub(crate) fn owned_by_the_trusted(file: &File) -> Result<(), String> {
    Trusted::read()?.own(&Security::of(file).map_err(unreadable)?)
}

fn checked_directory(dir: &Path, rule: &Rule) -> Result<File, Refused> {
    directory(dir, rule).map_err(|because| Refused::new(dir, because))
}

/// Opened without `FILE_SHARE_DELETE`, and for listing, since a handle opened
/// only for its attributes or security does not hold the share mode.
fn directory(dir: &Path, rule: &Rule) -> Result<File, String> {
    let opened = OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)
        .map_err(|e| e.to_string())?;
    let metadata = opened.metadata().map_err(|e| e.to_string())?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("it is a link or a junction".to_string());
    }
    if !metadata.is_dir() {
        return Err("it is not a directory".to_string());
    }
    let security = Security::of(&opened).map_err(unreadable)?;
    let trusted = Trusted::read()?;
    trusted.own(&security)?;
    if security.dacl.is_null() {
        return Err("it has no DACL, so everyone may use it".to_string());
    }
    let allowed_nothing_forbidden =
        security
            .aces()
            .map_err(unreadable)?
            .into_iter()
            .all(|ace| match ace {
                Ace::Denied => true,
                Ace::Allowed { sid, mask } => {
                    mask & rule.forbidden == 0 || trusted.are(sid) || is_creator(sid)
                }
                Ace::Other => false,
            });
    if !allowed_nothing_forbidden {
        return Err(format!(
            "{}: {}",
            rule.refusal,
            security.sddl(DACL_SECURITY_INFORMATION)
        ));
    }
    Ok(opened)
}

fn unreadable(e: io::Error) -> String {
    format!("its security could not be read: {e}")
}

/// This process's user, SYSTEM and Administrators.
struct Trusted(ProcessUser);

impl Trusted {
    fn read() -> Result<Self, String> {
        ProcessUser::read().map(Self).map_err(unreadable)
    }

    fn are(&self, sid: PSID) -> bool {
        // SAFETY: `sid` is a valid SID for the call, and so is the user's.
        unsafe {
            EqualSid(sid, self.0.sid()) != 0
                || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        }
    }

    fn own(&self, security: &Security) -> Result<(), String> {
        if self.are(security.owner) {
            return Ok(());
        }
        Err(format!(
            "it is owned by {}; only this process's user, SYSTEM or Administrators may own it",
            security.sddl(OWNER_SECURITY_INFORMATION)
        ))
    }
}

/// An ACE naming whoever owns the object, rather than an account.
fn is_creator(sid: PSID) -> bool {
    // SAFETY: `sid` is a valid SID for the call.
    unsafe {
        IsWellKnownSid(sid, WinCreatorOwnerSid) != 0
            || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0
    }
}

enum Ace {
    Allowed { sid: PSID, mask: u32 },
    Denied,
    Other,
}

/// An object's owner and DACL, pointing into the descriptor they were read
/// with, which is freed on drop.
struct Security {
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
}

impl Security {
    fn of(file: &File) -> io::Result<Self> {
        let mut security = Self {
            descriptor: null_mut(),
            owner: null_mut(),
            dacl: null_mut(),
        };
        // SAFETY: the handle is open while `file` is borrowed; on success
        // `descriptor` owns what `owner` and `dacl` point to.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut security.owner,
                null_mut(),
                &mut security.dacl,
                null_mut(),
                &mut security.descriptor,
            )
        };
        match status {
            0 => Ok(security),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    fn aces(&self) -> io::Result<Vec<Ace>> {
        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` is a valid ACL while `self` lives, and `size` is the
        // structure the class names.
        succeeded(unsafe {
            GetAclInformation(
                self.dacl,
                (&raw mut size).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        })?;
        (0..size.AceCount)
            .map(|index| {
                let mut ace: *mut std::ffi::c_void = null_mut();
                // SAFETY: `index` is below the ACL's count; every ACE starts with
                // its header, and an allowed ACE's SID starts at `SidStart`.
                unsafe {
                    succeeded(GetAce(self.dacl, index, &mut ace))?;
                    Ok(match u32::from((*ace.cast::<ACE_HEADER>()).AceType) {
                        ACCESS_ALLOWED_ACE_TYPE => Ace::Allowed {
                            sid: ace.byte_add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)),
                            mask: (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask,
                        },
                        ACCESS_DENIED_ACE_TYPE => Ace::Denied,
                        _ => Ace::Other,
                    })
                }
            })
            .collect()
    }

    fn sddl(&self, part: OBJECT_SECURITY_INFORMATION) -> String {
        let mut text = null_mut();
        // SAFETY: `descriptor` is valid while `self` lives; on success `text` is
        // a NUL-terminated string this frees once copied.
        unsafe {
            if ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.descriptor,
                SDDL_REVISION_1,
                part,
                &mut text,
                null_mut(),
            ) == 0
            {
                return "an unrenderable descriptor".to_string();
            }
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let rendered = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            rendered
        }
    }
}

impl Drop for Security {
    fn drop(&mut self) {
        // SAFETY: allocated by `GetSecurityInfo` or null, and freed once.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// This process's token user, in the buffer it was read into.
struct ProcessUser(Vec<u64>);

impl ProcessUser {
    fn read() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: the pseudo-handle needs no closing; the token is owned from here.
        let token = unsafe {
            succeeded(OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            ))?;
            OwnedHandle::from_raw_handle(token)
        };
        let mut len = 0u32;
        // SAFETY: a sizing call, with no buffer.
        unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut len) };
        let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buffer` is `len` bytes, aligned for a `TOKEN_USER`.
        succeeded(unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                len,
                &mut len,
            )
        })?;
        Ok(Self(buffer))
    }

    fn sid(&self) -> PSID {
        // SAFETY: the buffer holds a `TOKEN_USER` whose SID points into it.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

fn succeeded(result: i32) -> io::Result<()> {
    match result {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

#[cfg(test)]
pub(crate) fn icacls(path: &Path, args: &[&str]) {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "icacls {} {args:?}", path.display());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_dir::TempDir;
    use std::path::PathBuf;

    fn state_dir(dir: &TempDir) -> PathBuf {
        let state = dir.join("state");
        std::fs::create_dir(&state).unwrap();
        wslib_file_atomic::owner_only(&state).expect("the state directory's DACL");
        state
    }

    fn refusal(dir: &Path) -> String {
        crate::private_directory(dir)
            .expect_err("refuses")
            .to_string()
    }

    #[test]
    fn a_state_directory_only_its_owner_and_system_may_use_passes() {
        let dir = TempDir::new("private");
        drop(crate::private_directory(state_dir(&dir)).expect("passes"));
    }

    #[test]
    fn a_state_directory_granting_users_anything_refuses_naming_its_dacl() {
        let dir = TempDir::new("private");
        let state = state_dir(&dir);
        icacls(&state, &["/grant", "*S-1-5-32-545:(OI)(CI)(RD)"]);

        let said = refusal(&state);
        assert!(
            said.contains(&*state.to_string_lossy())
                && said.contains("its DACL allows someone besides")
                && said.contains(";;;BU)"),
            "{said}"
        );
    }

    #[test]
    fn a_state_directory_behind_a_junction_or_not_a_directory_refuses() {
        let dir = TempDir::new("private");
        let state = state_dir(&dir);
        let junction = dir.join("junction");
        let linked = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .args([&junction, &state])
            .status()
            .unwrap();
        assert!(linked.success());
        assert!(refusal(&junction).ends_with("it is a link or a junction"));

        let file = dir.join("file");
        std::fs::write(&file, "").unwrap();
        assert!(refusal(&file).ends_with("it is not a directory"));
    }

    #[test]
    fn a_parent_users_may_add_to_passes_and_one_they_may_delete_from_or_resecure_refuses() {
        for refused in ["(DC)", "(WDAC)"] {
            let dir = TempDir::new("private");
            let state = state_dir(&dir);
            let grant =
                |rights: &str| icacls(dir.path(), &["/grant", &format!("*S-1-5-32-545:{rights}")]);
            grant("(RX)");
            grant("(WD,AD)");
            drop(crate::private_directory(&state).expect("others may read it and add to it"));

            grant(refused);
            let said = refusal(&state);
            assert!(
                said.starts_with(&format!("refusing {}: ", dir.path().display()))
                    && said.contains("delete from it")
                    && said.contains(";;;BU)"),
                "{refused}: {said}"
            );
        }
    }

    #[test]
    fn a_checked_state_directory_and_its_parent_cannot_be_renamed_while_held() {
        let dir = TempDir::new("private");
        let state = state_dir(&dir);
        let moved = dir.join("moved");
        let held = crate::private_directory(&state).expect("passes");
        std::fs::rename(&state, &moved).expect_err("the state directory is held");
        let parent_moved = dir.path().with_extension("moved");
        std::fs::rename(dir.path(), &parent_moved).expect_err("its parent is held");

        drop(held);
        std::fs::rename(&state, &moved).expect("released");
    }
}
