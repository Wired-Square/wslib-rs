use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::str::FromStr;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
    GetTokenInformation, LookupAccountNameW, LookupAccountSidW, OWNER_SECURITY_INFORMATION, PSID,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// A Windows security identifier, displayed in its `S-1-…` form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sid {
    bytes: Vec<u32>,
    text: String,
}

/// An account's name and the domain it is in, `NT AUTHORITY` or a computer's
/// name for a local one.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Account {
    pub domain: String,
    pub name: String,
}

impl Sid {
    /// A copy of the SID at `sid`.
    ///
    /// # Safety
    ///
    /// `sid` points to a valid SID.
    pub unsafe fn from_psid(sid: PSID) -> io::Result<Self> {
        let mut text = null_mut();
        // SAFETY: `sid` is valid, per the contract; `text` is NUL-terminated
        // and freed once read.
        unsafe {
            let len = GetLengthSid(sid) as usize;
            let mut bytes = vec![0u32; len.div_ceil(4)];
            std::ptr::copy_nonoverlapping(sid.cast::<u8>(), bytes.as_mut_ptr().cast::<u8>(), len);
            succeeded(ConvertSidToStringSidW(sid, &mut text))?;
            let chars = (0..).take_while(|&i| *text.add(i) != 0).count();
            let rendered = String::from_utf16_lossy(std::slice::from_raw_parts(text, chars));
            LocalFree(text.cast());
            Ok(Self {
                bytes,
                text: rendered,
            })
        }
    }

    /// The SID of the account or group `name`, such as `NT SERVICE\EventLog`.
    pub fn of_account(name: &str) -> io::Result<Self> {
        let name = wide(name);
        let (mut sid_len, mut domain_len, mut kind) = (0u32, 0u32, 0);
        // SAFETY: a sizing call, with no buffers.
        sized(unsafe {
            LookupAccountNameW(
                null(),
                name.as_ptr(),
                null_mut(),
                &mut sid_len,
                null_mut(),
                &mut domain_len,
                &mut kind,
            )
        })?;
        let mut sid = vec![0u32; (sid_len as usize).div_ceil(4)];
        let mut domain = vec![0u16; domain_len as usize];
        // SAFETY: each buffer is at least as long as its length says; on
        // success `sid` holds a valid SID.
        unsafe {
            succeeded(LookupAccountNameW(
                null(),
                name.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            ))?;
            Self::from_psid(sid.as_mut_ptr().cast())
        }
    }

    /// The account this SID names. Blocking: a domain account's name comes
    /// from a domain controller.
    pub fn account(&self) -> io::Result<Account> {
        let (mut name_len, mut domain_len, mut kind) = (0u32, 0u32, 0);
        // SAFETY: a sizing call, with no buffers.
        sized(unsafe {
            LookupAccountSidW(
                null(),
                self.as_psid(),
                null_mut(),
                &mut name_len,
                null_mut(),
                &mut domain_len,
                &mut kind,
            )
        })?;
        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        // SAFETY: each buffer is as long as its length says.
        succeeded(unsafe {
            LookupAccountSidW(
                null(),
                self.as_psid(),
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        })?;
        let text = |units: &[u16], len: u32| {
            String::from_utf16(&units[..len as usize])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        };
        Ok(Account {
            domain: text(&domain, domain_len)?,
            name: text(&name, name_len)?,
        })
    }

    /// For a Win32 call; valid while `self` is.
    pub fn as_psid(&self) -> PSID {
        self.bytes.as_ptr().cast_mut().cast()
    }

    /// `S-1-5-80-` and five more sub-authorities: one service's own SID, and
    /// never `ALL SERVICES`, `S-1-5-80-0`.
    fn is_one_service(&self) -> bool {
        let sid = self.as_psid();
        // SAFETY: `sid` is a valid SID, so its authority and count may be read,
        // and a count of six means sub-authority 0 exists.
        unsafe {
            (*GetSidIdentifierAuthority(sid)).Value == [0, 0, 0, 0, 0, 5]
                && *GetSidSubAuthorityCount(sid) == 6
                && *GetSidSubAuthority(sid, 0) == 80
        }
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl FromStr for Sid {
    type Err = io::Error;

    fn from_str(text: &str) -> io::Result<Self> {
        let mut sid: PSID = null_mut();
        // SAFETY: the text is NUL-terminated; `sid` is freed once copied.
        unsafe {
            succeeded(ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid))?;
            let copied = Self::from_psid(sid);
            LocalFree(sid);
            copied
        }
    }
}

/// The service `service`'s own account, `NT SERVICE\<service>`; `None` when no
/// service by that name is installed or the name could not be one.
pub fn service_account(service: &str) -> io::Result<Option<Sid>> {
    if service.is_empty() || service.contains(['\\', '/', '\0']) {
        return Ok(None);
    }
    match Sid::of_account(&format!(r"NT SERVICE\{service}")) {
        Ok(sid) => Ok(Some(sid).filter(Sid::is_one_service)),
        Err(e) if e.raw_os_error() == Some(ERROR_NONE_MAPPED as i32) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The owner of a kernel object, such as a named pipe either end holds.
pub fn owner(object: &impl AsRawHandle) -> io::Result<Sid> {
    let mut owner: PSID = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: the handle is live while borrowed. On success `owner` points
    // into `descriptor`, which is freed once the owner is copied.
    unsafe {
        let status = GetSecurityInfo(
            object.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let copied = if owner.is_null() {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the object has no owner",
            ))
        } else {
            Sid::from_psid(owner)
        };
        LocalFree(descriptor);
        copied
    }
}

/// The user this process runs as.
pub fn current_user() -> io::Result<Sid> {
    // SAFETY: the pseudo-handle is always valid and needs no closing.
    token_user(unsafe { GetCurrentProcess() })
}

/// The user process `pid` runs as. Only SYSTEM or the same user may open
/// another user's process.
pub fn process_user(pid: u32) -> io::Result<Sid> {
    // SAFETY: no pointers; a null handle is the failure, and a valid one is
    // owned from here.
    let process = unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(process)
    };
    token_user(process.as_raw_handle())
}

/// The user of the process at the client end of the server end `pipe`: its
/// token's, not an impersonating thread's. It is read through the process id,
/// which may be reused in between, so it is for audit, not authority.
pub fn pipe_client_user(pipe: &impl AsRawHandle) -> io::Result<Sid> {
    let mut pid = 0;
    // SAFETY: the handle is live while borrowed.
    succeeded(unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) })?;
    process_user(pid)
}

fn token_user(process: HANDLE) -> io::Result<Sid> {
    let mut token = null_mut();
    // SAFETY: `process` is live for the call, and the token is owned from here.
    let token = unsafe {
        succeeded(OpenProcessToken(process, TOKEN_QUERY, &mut token))?;
        OwnedHandle::from_raw_handle(token)
    };
    let mut len = 0u32;
    // SAFETY: a sizing call, with no buffer.
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut len) };
    let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buffer` is `len` bytes and aligned for a `TOKEN_USER`, whose SID
    // points into it and is copied out while it lives.
    unsafe {
        succeeded(GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &mut len,
        ))?;
        Sid::from_psid((*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}

fn succeeded(result: i32) -> io::Result<()> {
    match result {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

// A sizing call fails by design with `ERROR_INSUFFICIENT_BUFFER`; any other failure is the answer.
fn sized(result: i32) -> io::Result<()> {
    match succeeded(result) {
        Err(e) if e.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) => Ok(()),
        other => other,
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
