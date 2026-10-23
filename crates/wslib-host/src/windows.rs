use std::ptr::null_mut;
use std::time::Duration;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows_sys::Win32::System::SystemInformation::{
    ComputerNamePhysicalDnsHostname, GetComputerNameExW, GetTickCount64,
};
use windows_sys::core::{PCWSTR, w};

const CURRENT_VERSION: PCWSTR = w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");

/// `GetTickCount64` counts sleep and hibernation, as `CLOCK_BOOTTIME` does.
pub(super) fn uptime() -> Option<Duration> {
    // SAFETY: no arguments, and no failure.
    Some(Duration::from_millis(unsafe { GetTickCount64() }))
}

pub(super) fn product() -> Option<String> {
    let build = text(w!("CurrentBuild")).and_then(|build| build.parse().ok());
    Some(super::windows_product(
        &text(w!("ProductName"))?,
        text(w!("DisplayVersion")).as_deref(),
        text(w!("ReleaseId")).as_deref(),
        build.unwrap_or(0),
    ))
}

pub(super) fn kernel_version() -> Option<String> {
    Some(super::windows_kernel(
        number(w!("CurrentMajorVersionNumber"))?,
        number(w!("CurrentMinorVersionNumber"))?,
        &text(w!("CurrentBuild"))?,
        number(w!("UBR")),
    ))
}

fn text(value: PCWSTR) -> Option<String> {
    let mut data = [0u16; 256];
    let mut size = size_of_val(&data) as u32;
    // SAFETY: both names are NUL-terminated, and `data` is a live,
    // writable local of `size` bytes for the whole call.
    let read = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            CURRENT_VERSION,
            value,
            RRF_RT_REG_SZ,
            null_mut(),
            data.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if read != ERROR_SUCCESS {
        return None;
    }
    let units = data.get(..size as usize / 2)?;
    let text = String::from_utf16(units.split(|&unit| unit == 0).next()?).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn number(value: PCWSTR) -> Option<u32> {
    let mut data = 0u32;
    let mut size = size_of_val(&data) as u32;
    // SAFETY: both names are NUL-terminated, and `data` is a live,
    // writable local of `size` bytes for the whole call.
    let read = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            CURRENT_VERSION,
            value,
            RRF_RT_REG_DWORD,
            null_mut(),
            (&raw mut data).cast(),
            &mut size,
        )
    };
    (read == ERROR_SUCCESS).then_some(data)
}

/// This machine's own DNS host name, with no domain, like a Mac's first
/// label; not a cluster's virtual name, nor the NetBIOS name, which is
/// upper-cased and cut to 15 characters.
pub(super) fn hostname() -> Option<String> {
    let mut name = [0u16; 256];
    let mut len = name.len() as u32;
    // SAFETY: `name` is a live, writable local of `len` UTF-16 units for
    // the whole call.
    let named =
        unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, name.as_mut_ptr(), &mut len) };
    if named == 0 {
        return None;
    }
    let name = String::from_utf16(name.get(..len as usize)?).ok()?;
    (!name.is_empty()).then_some(name)
}
