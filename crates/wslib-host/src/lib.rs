//! What a host says about itself, never asked of a command or a bus: on Linux
//! read from `/proc` and `/etc`. macOS answers [`hostname`], [`uptime`],
//! [`machine_id`], [`kernel_release`] and [`os_name`] from libc and sysctl,
//! and Windows all but [`machine_id`] of those from Win32 and the registry;
//! every other reader is `None` off Linux.
//!
//! Beside them, who an account is: on Unix a socket peer's
//! `PeerCredentials` and a uid's `account_name`, and on Windows the `Sid`
//! of an account, a service, a process, a pipe's client or an object's owner.

use std::path::Path;
use std::time::Duration;

use uuid::Uuid;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix_account;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_account;

#[cfg(unix)]
pub use unix_account::{PeerCredentials, account_name, peer_credentials};
#[cfg(windows)]
pub use windows_account::{
    Account, Sid, current_user, owner, pipe_client_user, process_user, service_account,
};

/// Where [`hostname`] reads on this platform, for a log line when it fails.
#[cfg(not(any(target_os = "macos", windows)))]
pub const HOSTNAME_SOURCE: &str = "/proc/sys/kernel/hostname";
/// Where [`hostname`] reads on this platform, for a log line when it fails.
#[cfg(target_os = "macos")]
pub const HOSTNAME_SOURCE: &str = "gethostname";
/// Where [`hostname`] reads on this platform, for a log line when it fails.
#[cfg(windows)]
pub const HOSTNAME_SOURCE: &str = "GetComputerNameExW";

/// The kernel's running hostname, on macOS its first label only, on Windows
/// the DNS host name.
///
/// On Linux this is `/proc/sys/kernel/hostname`, not `/etc/hostname`: the
/// running name, namespaced by UTS, so under a unit's `ProtectHostname=yes`
/// it is the name at the service's start.
pub fn hostname() -> Option<String> {
    #[cfg(target_os = "macos")]
    return macos::hostname();
    #[cfg(windows)]
    return windows::hostname();
    #[cfg(not(any(target_os = "macos", windows)))]
    read_trimmed(HOSTNAME_SOURCE)
}

/// How long the host has been up, sleep included, on a clock that does not
/// jump when the wall clock is set.
pub fn uptime() -> Option<Duration> {
    #[cfg(target_os = "macos")]
    return macos::uptime();
    #[cfg(windows)]
    return windows::uptime();
    #[cfg(not(any(target_os = "macos", windows)))]
    read_trimmed("/proc/uptime").and_then(|text| parse_uptime(&text))
}

/// A new random id each boot, the same for every process within it.
pub fn boot_id() -> Option<String> {
    read_trimmed("/proc/sys/kernel/random/boot_id")
}

/// The kernel's release, e.g. `6.12.48+deb13-amd64`; on Windows the version
/// as build numbers, e.g. `10.0.26200.9457`.
pub fn kernel_release() -> Option<String> {
    #[cfg(target_os = "macos")]
    return macos::sysctl(c"kern.osrelease");
    #[cfg(windows)]
    return windows::kernel_version();
    #[cfg(not(any(target_os = "macos", windows)))]
    read_trimmed("/proc/sys/kernel/osrelease")
}

/// `/etc/os-release`'s `PRETTY_NAME`, unquoted; on macOS e.g. `macOS 26.6.2`,
/// and on Windows e.g. `Windows 11 Pro 25H2`.
pub fn os_name() -> Option<String> {
    #[cfg(target_os = "macos")]
    return macos::sysctl(c"kern.osproductversion").map(|version| format!("macOS {version}"));
    #[cfg(windows)]
    return windows::product();
    #[cfg(not(any(target_os = "macos", windows)))]
    read_trimmed("/etc/os-release").and_then(|text| pretty_name(&text))
}

/// This host's id for `app`, which a rename does not change and which tells
/// the host's other apps nothing: systemd's `sd_id128_get_app_specific`.
///
/// Keyed on `/etc/machine-id`, or on macOS the `IOPlatformUUID`; `None`
/// without a valid one, and on Windows. On Linux it equals
/// `systemd-id128 machine-id --app-specific=<app> -u`.
pub fn machine_id(app: Uuid) -> Option<Uuid> {
    #[cfg(target_os = "macos")]
    let machine = macos::hardware_uuid();
    #[cfg(windows)]
    let machine: Option<String> = None;
    #[cfg(not(any(target_os = "macos", windows)))]
    let machine = read_trimmed("/etc/machine-id");
    app_specific(&machine?, app)
}

/// `None` unless `machine_id` is 32 hex digits and not all zero.
fn app_specific(machine_id: &str, app: Uuid) -> Option<Uuid> {
    use hmac::{Hmac, Mac};

    if machine_id.len() != 32 {
        return None;
    }
    let machine = Uuid::try_parse(machine_id).ok().filter(|id| !id.is_nil())?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(machine.as_bytes()).ok()?;
    mac.update(app.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut id = [0u8; 16];
    id.copy_from_slice(&tag[..16]);
    Some(uuid::Builder::from_random_bytes(id).into_uuid())
}

#[cfg(any(test, not(any(target_os = "macos", windows))))]
fn parse_uptime(text: &str) -> Option<Duration> {
    let seconds: f64 = text.split_whitespace().next()?.parse().ok()?;
    Duration::try_from_secs_f64(seconds).ok()
}

#[cfg(any(test, not(any(target_os = "macos", windows))))]
fn pretty_name(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim().trim_matches('"').to_string())
        .filter(|value| !value.is_empty())
}

/// The registry's `ProductName` still says Windows 10 on Windows 11, whose
/// builds start at 22000.
#[cfg(any(test, windows))]
fn windows_product(
    name: &str,
    display_version: Option<&str>,
    release_id: Option<&str>,
    build: u32,
) -> String {
    let name = match name.strip_prefix("Windows 10") {
        Some(edition) if build >= 22_000 => format!("Windows 11{edition}"),
        _ => name.to_string(),
    };
    match display_version.or(release_id) {
        Some(version) => format!("{name} {version}"),
        None => name,
    }
}

#[cfg(any(test, windows))]
fn windows_kernel(major: u32, minor: u32, build: &str, revision: Option<u32>) -> String {
    match revision {
        Some(revision) => format!("{major}.{minor}.{build}.{revision}"),
        None => format!("{major}.{minor}.{build}"),
    }
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests;
