//! Restricting a file to its owner on Windows, where a new file inherits its
//! directory's ACL, and a directory such as `%ProgramData%` grants every user
//! read.

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, CreateWellKnownSid,
    DACL_SECURITY_INFORMATION, EqualSid, GetLengthSid, GetTokenInformation, InitializeAcl,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_MAX_SID_SIZE, TOKEN_INFORMATION_CLASS, TokenOwner, TokenUser, WELL_KNOWN_SID_TYPE,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ALL_ACCESS, FILE_GENERIC_READ,
    GetFileInformationByHandle,
};

/// Grants the file's owner rather than this process, so a helper run as
/// another account never takes an existing file from the service; SYSTEM is
/// the account a Windows service runs as.
pub(crate) fn owner_only(file: &Path) -> io::Result<()> {
    restrict(file, None)
}

/// As [`owner_only`](crate::owner_only), with Administrators also granted read
/// and delete; a file Administrators own stays theirs in full.
pub fn administrators_read_and_delete(file: &Path) -> io::Result<()> {
    let administrators = WellKnown::new(WinBuiltinAdministratorsSid)?;
    restrict(file, Some(&administrators))
}

fn restrict(file: &Path, administrators: Option<&WellKnown>) -> io::Result<()> {
    let name: Vec<u16> = file.as_os_str().encode_wide().chain([0]).collect();
    let owner = Owner::of(&name)?;
    let system = WellKnown::new(WinLocalSystemSid)?;
    let others = [
        Some((&system, FILE_ALL_ACCESS)),
        administrators.map(|a| (a, FILE_GENERIC_READ | DELETE)),
    ];
    let mut grants = vec![(owner.sid, FILE_ALL_ACCESS)];
    grants.extend(
        others
            .into_iter()
            .flatten()
            // SAFETY: both are valid SIDs for as long as `owner` and `sid` live.
            .filter(|(sid, _)| unsafe { EqualSid(owner.sid, sid.as_psid()) } == 0)
            .map(|(sid, mask)| (sid.as_psid(), mask)),
    );

    let ace_len = |sid| {
        // SAFETY: `sid` is one of the valid SIDs above.
        size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + unsafe { GetLengthSid(sid) } as usize
    };
    let acl_len = size_of::<ACL>() + grants.iter().map(|&(sid, _)| ace_len(sid)).sum::<usize>();
    // `Vec<u32>` because an ACL must be DWORD-aligned.
    let mut acl = vec![0u32; acl_len.div_ceil(4)];
    let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
    let acl_bytes = u32::try_from(acl.len() * 4).expect("three ACEs fit a u32");

    // SAFETY: `acl` is a DWORD-aligned buffer of `acl_bytes`, room for the header
    // and an ACE per SID in `grants`, each of which outlives the calls.
    let built = unsafe {
        InitializeAcl(acl_ptr, acl_bytes, ACL_REVISION) != 0
            && grants
                .iter()
                .all(|&(sid, mask)| AddAccessAllowedAce(acl_ptr, ACL_REVISION, mask, sid) != 0)
    };
    if !built {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `name` is NUL-terminated and `acl` a valid ACL; the call keeps neither.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl_ptr,
            ptr::null(),
        )
    };
    win32(status)
}

fn win32(status: u32) -> io::Result<()> {
    match status {
        0 => Ok(()),
        code => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

/// A file's owner SID, in the security descriptor it was read out of.
struct Owner {
    descriptor: PSECURITY_DESCRIPTOR,
    sid: PSID,
}

impl Owner {
    fn of(name: &[u16]) -> io::Result<Self> {
        let mut owner = Self {
            descriptor: ptr::null_mut(),
            sid: ptr::null_mut(),
        };
        // SAFETY: `name` is NUL-terminated; on success `descriptor` owns the
        // memory `sid` points into, and `drop` frees it.
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner.sid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut owner.descriptor,
            )
        };
        win32(status).map(|()| owner)
    }

    fn of_file(file: &File) -> io::Result<Self> {
        let mut owner = Self {
            descriptor: ptr::null_mut(),
            sid: ptr::null_mut(),
        };
        // SAFETY: the handle is open for the call; on success `descriptor`
        // owns the memory `sid` points into, and `drop` frees it.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner.sid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut owner.descriptor,
            )
        };
        win32(status).map(|()| owner)
    }
}

pub(crate) fn file_id(file: &File) -> io::Result<(u64, u64)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for the call and `info` is written in place.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok((u64::from(info.dwVolumeSerialNumber), index))
}

/// An elevated process gives what it creates to Administrators, its token's
/// default owner, rather than to its user.
pub(crate) fn owned_by_this_process(file: &File) -> io::Result<bool> {
    let owner = Owner::of_file(file)?;
    let ours = [TokenSid::read(TokenUser)?, TokenSid::read(TokenOwner)?];
    // SAFETY: both are valid SIDs for as long as `owner` and `ours` live.
    Ok(ours
        .iter()
        .any(|sid| unsafe { EqualSid(owner.sid, sid.as_psid()) } != 0))
}

/// This process's `TOKEN_USER` or `TOKEN_OWNER`, each led by the SID.
///
/// Boxed: the leading SID pointer points into the buffer, so it must not move.
pub(crate) struct TokenSid(Box<[u64; 64]>);

impl TokenSid {
    pub(crate) fn read(class: TOKEN_INFORMATION_CLASS) -> io::Result<Self> {
        let mut info = Self(Box::new([0; 64]));
        let mut len = 0u32;
        // SAFETY: the buffer is 512 bytes, aligned for either structure, whose
        // SID points into it; -4 is `GetCurrentProcessToken`'s pseudo-handle.
        let read = unsafe {
            GetTokenInformation(
                -4isize as HANDLE,
                class,
                info.0.as_mut_ptr().cast(),
                512,
                &mut len,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    pub(crate) fn as_psid(&self) -> PSID {
        // SAFETY: filled by `read`, which leads with the SID's pointer.
        unsafe { *self.0.as_ptr().cast::<PSID>() }
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        // SAFETY: allocated by `GetNamedSecurityInfoW` or null, and freed once.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// A local well-known SID.
pub(crate) struct WellKnown([u32; SECURITY_MAX_SID_SIZE as usize / 4]);

impl WellKnown {
    pub(crate) fn new(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Self> {
        let mut sid = Self([0; SECURITY_MAX_SID_SIZE as usize / 4]);
        let mut len = SECURITY_MAX_SID_SIZE;
        // SAFETY: the buffer is `len` bytes and DWORD-aligned, and a local
        // well-known SID takes no domain.
        let made = unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), sid.0.as_mut_ptr().cast(), &mut len)
        };
        if made == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sid)
    }

    pub(crate) fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline(never)]
    fn read_elsewhere(class: TOKEN_INFORMATION_CLASS) -> TokenSid {
        TokenSid::read(class).unwrap()
    }

    #[test]
    fn a_token_sid_still_names_the_user_after_it_is_moved() {
        let moved = read_elsewhere(TokenUser);
        let fresh = TokenSid::read(TokenUser).unwrap();
        // SAFETY: both are valid SIDs while `moved` and `fresh` live.
        assert_ne!(unsafe { EqualSid(moved.as_psid(), fresh.as_psid()) }, 0);
    }

    #[test]
    fn a_file_this_process_creates_is_its_own() {
        let path = std::env::temp_dir().join(format!("wslib-owned-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        let owned = owned_by_this_process(&file);
        drop(file);
        let _ = std::fs::remove_file(&path);
        assert!(owned.unwrap());
    }
}
