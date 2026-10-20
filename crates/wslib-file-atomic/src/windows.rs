//! Restricting a file to its owner on Windows, where a new file inherits its
//! directory's ACL, and a directory such as `%ProgramData%` grants every user
//! read.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, CreateWellKnownSid,
    DACL_SECURITY_INFORMATION, EqualSid, GetLengthSid, InitializeAcl, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE,
    WELL_KNOWN_SID_TYPE, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

/// Grants the file's owner rather than this process, so a helper run as
/// another account never takes an existing file from the service; SYSTEM is
/// the account a Windows service runs as.
pub(crate) fn owner_only(file: &Path) -> io::Result<()> {
    let name: Vec<u16> = file.as_os_str().encode_wide().chain([0]).collect();
    let owner = Owner::of(&name)?;
    let system = WellKnown::new(WinLocalSystemSid)?;
    let mut grants = vec![owner.sid];
    // SAFETY: both are valid SIDs for as long as `owner` and `system` live.
    if unsafe { EqualSid(owner.sid, system.as_psid()) } == 0 {
        grants.push(system.as_psid());
    }

    let ace_len = |sid| {
        // SAFETY: `sid` is one of the valid SIDs above.
        size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + unsafe { GetLengthSid(sid) } as usize
    };
    let acl_len = size_of::<ACL>() + grants.iter().map(|&sid| ace_len(sid)).sum::<usize>();
    // `Vec<u32>` because an ACL must be DWORD-aligned.
    let mut acl = vec![0u32; acl_len.div_ceil(4)];
    let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
    let acl_bytes = u32::try_from(acl.len() * 4).expect("two ACEs fit a u32");

    // SAFETY: `acl` is a DWORD-aligned buffer of `acl_bytes`, room for the header
    // and an ACE per SID in `grants`, each of which outlives the calls.
    let built = unsafe {
        InitializeAcl(acl_ptr, acl_bytes, ACL_REVISION) != 0
            && grants
                .iter()
                .all(|&sid| AddAccessAllowedAce(acl_ptr, ACL_REVISION, FILE_ALL_ACCESS, sid) != 0)
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
}

impl Drop for Owner {
    fn drop(&mut self) {
        // SAFETY: allocated by `GetNamedSecurityInfoW` or null, and freed once.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// A local well-known SID.
struct WellKnown([u32; SECURITY_MAX_SID_SIZE as usize / 4]);

impl WellKnown {
    fn new(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Self> {
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

    fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }
}
