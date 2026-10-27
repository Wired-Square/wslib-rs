use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};

/// Who is at the other end of a Unix socket, as the kernel recorded it at
/// `connect()`: the effective ids, so `sudo` shows as the account it ran as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    /// `None` where the platform does not say, or the peer is in another pid
    /// namespace.
    pub pid: Option<u32>,
}

/// The [`PeerCredentials`] of a connected Unix socket, std's or tokio's.
pub fn peer_credentials(socket: &impl AsFd) -> io::Result<PeerCredentials> {
    credentials(socket.as_fd().as_raw_fd())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn credentials(fd: libc::c_int) -> io::Result<PeerCredentials> {
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` is a live local of the length passed.
    let read = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if read != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: zeroed, then filled in by the call that succeeded.
    let credentials = unsafe { credentials.assume_init() };
    Ok(PeerCredentials {
        uid: credentials.uid,
        gid: credentials.gid,
        pid: positive(credentials.pid),
    })
}

#[cfg(target_vendor = "apple")]
fn credentials(fd: libc::c_int) -> io::Result<PeerCredentials> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: both are live locals.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid: libc::pid_t = 0;
    let mut len = size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` is a live local of the length passed.
    let read = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &mut len,
        )
    };
    Ok(PeerCredentials {
        uid,
        gid,
        pid: if read == 0 { positive(pid) } else { None },
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn credentials(_: libc::c_int) -> io::Result<PeerCredentials> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials are read on Linux and Apple platforms",
    ))
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn positive(pid: libc::pid_t) -> Option<u32> {
    u32::try_from(pid).ok().filter(|&pid| pid != 0)
}

/// The name of the account `uid`, from the passwd database; `None` for a uid
/// with no entry. Blocking: the database may be a directory service.
pub fn account_name(uid: u32) -> io::Result<Option<String>> {
    const LARGEST: usize = 1 << 20;
    let mut buffer: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut entry = MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: each pointer is to a live local, and `buffer.len()` is the
        // length of the buffer passed.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        match status {
            libc::ERANGE if buffer.len() < LARGEST => buffer.resize(buffer.len() * 2, 0),
            0 | libc::ENOENT | libc::ESRCH if found.is_null() => return Ok(None),
            0 => {
                // SAFETY: on success `found` is `entry`, filled in, and its
                // `pw_name` is a NUL-terminated string inside `buffer`.
                let name = unsafe { CStr::from_ptr((*found).pw_name) };
                return name
                    .to_str()
                    .map(|name| Some(name.to_owned()))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
            error => return Err(io::Error::from_raw_os_error(error)),
        }
    }
}
