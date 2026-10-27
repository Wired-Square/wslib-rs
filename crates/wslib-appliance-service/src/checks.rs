//! The control endpoints' directories; each error is the sentence a refusal ends with.

use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

const LOOKUP_DEADLINE: Duration = Duration::from_secs(1);

/// The gid, `None` for no such group, or the errno of a failed lookup.
pub(crate) type Lookup = Result<Option<u32>, i32>;

/// One its group or others could write would let them swap the socket for a
/// link before the chmod.
pub(crate) async fn endpoint_directory(dir: &Path, group: &str) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(dir).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "it is missing".to_string(),
        _ => e.to_string(),
    })?;
    if !metadata.is_dir() {
        return Err("it is not a directory".to_string());
    }
    // SAFETY: `geteuid` reads this process's own credentials and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid && metadata.uid() != 0 {
        return Err(format!(
            "it is owned by uid {}, neither this process's {euid} nor root",
            metadata.uid()
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "its mode is {mode:04o}; neither its group nor others may write it"
        ));
    }
    wslib_service::no_extended_acl(dir).map_err(|refused| refused.because)?;
    let gid = group_id(group, LOOKUP_DEADLINE, gid_of).await?;
    if metadata.gid() != gid {
        return Err(format!(
            "it is owned by gid {}, not {group}'s {gid}",
            metadata.gid()
        ));
    }
    Ok(())
}

/// The lookup runs on a detached thread, so one still blocked at `deadline`
/// holds neither start-up nor the runtime's shutdown.
pub(crate) async fn group_id(
    group: &str,
    deadline: Duration,
    lookup: impl FnOnce(&CStr) -> Lookup + Send + 'static,
) -> Result<u32, String> {
    let name = CString::new(group).map_err(|_| format!("{group:?} is not a group name"))?;
    let (answer, answered) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("group lookup".to_string())
        .spawn(move || answer.send(lookup(&name)).ok())
        .map_err(|e| format!("could not look up the group {group}: {e}"))?;
    match tokio::time::timeout(deadline, answered).await {
        Ok(Ok(Ok(Some(gid)))) => Ok(gid),
        Ok(Ok(Ok(None))) => Err(format!("there is no group named {group}")),
        Ok(Ok(Err(errno))) => Err(format!(
            "looking up the group {group} failed: {}",
            std::io::Error::from_raw_os_error(errno)
        )),
        Ok(Err(_)) => Err(format!("looking up the group {group} failed")),
        Err(_) => Err(format!(
            "looking up the group {group} did not answer within {deadline:?}"
        )),
    }
}

/// Blocking.
fn gid_of(name: &CStr) -> Lookup {
    const LARGEST: usize = 1 << 20;
    let mut buffer: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut entry = MaybeUninit::<libc::group>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: each pointer is to a live local, and `buffer.len()` is the
        // length of the buffer passed.
        let status = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        match status {
            libc::ERANGE if buffer.len() < LARGEST => buffer.resize(buffer.len() * 2, 0),
            // SAFETY: on success `found` is `entry`, filled in.
            0 if !found.is_null() => return Ok(Some(unsafe { (*found).gr_gid })),
            // Some libcs say "no such group" with one of these rather than 0.
            0 | libc::ENOENT | libc::ESRCH => return Ok(None),
            errno => return Err(errno),
        }
    }
}
