//! Assertions that a file is restricted as this crate restricts it, read back
//! from the file system, for a consumer's tests.

use std::path::Path;

/// Assert that `file` is `0600`, or on Windows that its DACL is protected and
/// grants its owner and SYSTEM full control and nobody else anything.
pub fn assert_owner_only(file: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(file)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{}", file.display());
    }
    #[cfg(windows)]
    assert_dacl(file, false);
}

/// As [`assert_owner_only`], with Administrators also granted read and delete
/// unless they own `file`.
#[cfg(windows)]
pub fn assert_administrators_read_and_delete(file: &Path) {
    assert_dacl(file, true);
}

#[cfg(windows)]
fn assert_dacl(file: &Path, administrators: bool) {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_USER, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_ALL_ACCESS, FILE_GENERIC_READ};
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    use crate::windows::WellKnown;

    let system = WellKnown::new(WinLocalSystemSid).expect("SYSTEM's SID");
    let system = system.as_psid();
    let administrators_sid =
        WellKnown::new(WinBuiltinAdministratorsSid).expect("Administrators' SID");
    let administrators_sid = administrators_sid.as_psid();
    let mut token_user = [0u64; 64];
    let mut len = 0u32;
    // SAFETY: `token_user` is 512 bytes, aligned for a `TOKEN_USER`, whose SID
    // points into it; -4 is `GetCurrentProcessToken`'s pseudo-handle.
    let process_user: PSID = unsafe {
        let read = GetTokenInformation(
            -4isize as HANDLE,
            TokenUser,
            token_user.as_mut_ptr().cast(),
            512,
            &mut len,
        );
        assert_ne!(read, 0, "this process's user");
        (*token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid
    };

    let name: Vec<u16> = file.as_os_str().encode_wide().chain([0]).collect();
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `name` is NUL-terminated; on success `descriptor` owns the
    // memory `owner` and `dacl` point into, and is freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    let at = file.display();
    assert_eq!(status, 0, "reading {at}'s DACL");

    let (mut control, mut revision) = (0u16, 0u32);
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `descriptor`, `owner` and `dacl` are live until the
    // `LocalFree`; a failed assertion leaks them, which a test can afford.
    unsafe {
        let read = GetSecurityDescriptorControl(descriptor, &mut control, &mut revision);
        assert_ne!(read, 0, "{at}");
        assert_ne!(control & SE_DACL_PROTECTED, 0, "{at} inherits");

        assert!(
            [process_user, system, administrators_sid]
                .iter()
                .any(|&sid| EqualSid(owner, sid) != 0),
            "{at} is owned by another"
        );
        let others = [
            Some((system, FILE_ALL_ACCESS)),
            administrators.then_some((administrators_sid, FILE_GENERIC_READ | DELETE)),
        ];
        let mut expected = vec![(owner, FILE_ALL_ACCESS)];
        expected.extend(
            others
                .into_iter()
                .flatten()
                .filter(|&(sid, _)| EqualSid(owner, sid) == 0),
        );
        let size_len = size_of::<ACL_SIZE_INFORMATION>() as u32;
        let read = GetAclInformation(dacl, (&raw mut size).cast(), size_len, AclSizeInformation);
        assert_ne!(read, 0, "{at}");
        assert_eq!(size.AceCount as usize, expected.len(), "{at}");

        for (index, (sid, mask)) in (0..).zip(expected) {
            let mut ace: *mut std::ffi::c_void = null_mut();
            assert_ne!(GetAce(dacl, index, &mut ace), 0, "{at}");
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            assert_eq!(
                allowed.Header.AceType, ACCESS_ALLOWED_ACE_TYPE as u8,
                "{at}"
            );
            assert_eq!(allowed.Header.AceFlags, 0, "{at}'s ACE {index} has flags");
            assert_eq!(allowed.Mask, mask, "{at}");
            let granted = ace.byte_add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart));
            assert_ne!(EqualSid(granted, sid), 0, "{at}'s ACE {index} is another's");
        }
        LocalFree(descriptor);
    }
}
