use std::ffi::CStr;
use std::sync::OnceLock;
use std::time::Duration;

use uuid::Uuid;

/// The first label only: a Mac's kernel name may be a DHCP or reverse-DNS
/// FQDN.
pub(super) fn hostname() -> Option<String> {
    let mut name = [0u8; 256];
    // SAFETY: the length passed is the buffer's.
    if unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
        return None;
    }
    short(CStr::from_bytes_until_nul(&name).ok()?.to_str().ok()?)
}

pub(super) fn short(name: &str) -> Option<String> {
    let label = name.split('.').next()?.trim();
    (!label.is_empty()).then(|| label.to_string())
}

/// Darwin's `CLOCK_MONOTONIC` counts sleep and does not jump when the clock
/// is set: it is the wall clock less `kern.boottime`, which a set moves
/// with it.
pub(super) fn uptime() -> Option<Duration> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a live local the call writes.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return None;
    }
    Some(Duration::new(
        u64::try_from(now.tv_sec).ok()?,
        u32::try_from(now.tv_nsec).ok()?,
    ))
}

pub(super) fn sysctl(name: &CStr) -> Option<String> {
    let mut value = [0u8; 256];
    let mut len = value.len();
    // SAFETY: `name` is NUL-terminated, and `len` is `value`'s length for
    // the whole call.
    let read = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 {
        return None;
    }
    let text = CStr::from_bytes_until_nul(value.get(..len)?)
        .ok()?
        .to_str()
        .ok()?
        .trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// `IOPlatformUUID` as 32 hex digits, the shape `/etc/machine-id` has;
/// asked once, since the call blocks for up to a second.
pub(super) fn hardware_uuid() -> Option<String> {
    static ID: OnceLock<String> = OnceLock::new();
    if let Some(id) = ID.get() {
        return Some(id.clone());
    }
    let id = ask_hardware_uuid()?;
    Some(ID.get_or_init(|| id).clone())
}

fn ask_hardware_uuid() -> Option<String> {
    let mut id = [0u8; 16];
    // A zero wait is forever.
    let wait = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    // SAFETY: `id` is the 16-byte `uuid_t` the call writes; `wait` is a live local.
    let status = unsafe { libc::gethostuuid(id.as_mut_ptr(), &wait) };
    (status == 0).then(|| Uuid::from_bytes(id).simple().to_string())
}
