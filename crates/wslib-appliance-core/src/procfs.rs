//! What the box says about itself, never asked of a command or a bus: on Linux
//! read from `/proc` and `/etc`. macOS answers [`hostname`], [`boottime`],
//! [`box_id`] and the kernel's and OS's versions from libc and sysctl, and
//! Windows all but [`box_id`] of those from Win32 and the registry; every other
//! reader is `None` off Linux.

use std::path::Path;
use std::time::Duration;

use uuid::Uuid;

/// The kernel's running name, not `/etc/hostname`; under a unit's
/// `ProtectHostname=yes` it is the name at start until a restart.
#[cfg(not(any(target_os = "macos", windows)))]
pub(crate) const HOSTNAME: &str = "/proc/sys/kernel/hostname";
#[cfg(target_os = "macos")]
pub(crate) const HOSTNAME: &str = "gethostname";
#[cfg(windows)]
pub(crate) const HOSTNAME: &str = "GetComputerNameExW";
#[cfg(not(any(target_os = "macos", windows)))]
const UPTIME: &str = "/proc/uptime";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
#[cfg(not(any(target_os = "macos", windows)))]
const KERNEL_RELEASE: &str = "/proc/sys/kernel/osrelease";
#[cfg(not(any(target_os = "macos", windows)))]
const OS_RELEASE: &str = "/etc/os-release";
#[cfg(not(target_os = "macos"))]
const MACHINE_ID: &str = "/etc/machine-id";

/// `systemd-id128 machine-id --app-specific=6e882fe490034dc4973989aa7425c9b9 -u`
/// prints a Linux box's [`box_id`].
const BOX_ID_APP: Uuid = Uuid::from_u128(0x6e882fe4_9003_4dc4_9739_89aa7425c9b9);

/// The kernel's running hostname, on macOS its first label only, on Windows
/// the DNS host name; `None` elsewhere.
pub fn hostname() -> Option<String> {
    #[cfg(target_os = "macos")]
    return macos::hostname();
    #[cfg(windows)]
    return windows::hostname();
    #[cfg(not(any(target_os = "macos", windows)))]
    read_trimmed(HOSTNAME)
}

/// How long the box has been up, sleep included, on a clock that does not jump
/// when the wall clock is set.
pub fn boottime() -> Option<Duration> {
    #[cfg(target_os = "macos")]
    return macos::boottime();
    #[cfg(windows)]
    return windows::boottime();
    #[cfg(not(any(target_os = "macos", windows)))]
    read_trimmed(UPTIME).and_then(|text| uptime(&text))
}

/// A new random id each boot, the same for every process within it.
pub(crate) fn boot_id() -> Option<String> {
    read_trimmed(BOOT_ID)
}

/// On Windows the version as build numbers, e.g. `10.0.26200.9457`.
pub(crate) fn kernel_release() -> Option<String> {
    #[cfg(target_os = "macos")]
    return macos::sysctl(c"kern.osrelease");
    #[cfg(windows)]
    return windows::kernel_version();
    #[cfg(not(any(target_os = "macos", windows)))]
    read_trimmed(KERNEL_RELEASE)
}

/// `PRETTY_NAME`, unquoted; on macOS e.g. `macOS 26.6.2`, and on Windows e.g.
/// `Windows 11 Pro 25H2`.
pub(crate) fn os_pretty_name() -> Option<String> {
    #[cfg(target_os = "macos")]
    return macos::sysctl(c"kern.osproductversion").map(|version| format!("macOS {version}"));
    #[cfg(windows)]
    return windows::product();
    #[cfg(not(any(target_os = "macos", windows)))]
    read_trimmed(OS_RELEASE).and_then(|text| pretty_name(&text))
}

/// This box's identity, which a rename does not change, keyed on `/etc/machine-id`
/// or, on macOS, `IOPlatformUUID`; `None` without a valid one.
pub fn box_id() -> Option<String> {
    #[cfg(target_os = "macos")]
    let machine = macos::platform_uuid();
    #[cfg(not(target_os = "macos"))]
    let machine = read_trimmed(MACHINE_ID);
    app_specific(&machine?, &BOX_ID_APP)
}

/// systemd's `sd_id128_get_app_specific`, as a v4 UUID; `None` unless `machine_id`
/// is 32 hex digits and not all zero.
fn app_specific(machine_id: &str, app: &Uuid) -> Option<String> {
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
    Some(uuid::Builder::from_random_bytes(id).into_uuid().to_string())
}

#[cfg(any(test, not(any(target_os = "macos", windows))))]
fn uptime(text: &str) -> Option<Duration> {
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

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::CStr;
    use std::sync::OnceLock;
    use std::time::Duration;

    use uuid::Uuid;

    /// The first label only: a Mac's kernel name may be a DHCP or reverse-DNS
    /// FQDN, and the certificate adds `.local` to it.
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
    /// is set.
    pub(super) fn boottime() -> Option<Duration> {
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
        // SAFETY: `name` is NUL-terminated, and `len` is `value`'s length.
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
    pub(super) fn platform_uuid() -> Option<String> {
        static ID: OnceLock<String> = OnceLock::new();
        if let Some(id) = ID.get() {
            return Some(id.clone());
        }
        let id = ask_platform_uuid()?;
        Some(ID.get_or_init(|| id).clone())
    }

    fn ask_platform_uuid() -> Option<String> {
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
}

#[cfg(windows)]
mod windows {
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
    pub(super) fn boottime() -> Option<Duration> {
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

    /// This machine's own DNS host name, with no domain; not a cluster's virtual
    /// name, nor the upper-cased, truncated NetBIOS name.
    pub(super) fn hostname() -> Option<String> {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: `name` is a live, writable local of `len` UTF-16 units.
        let named = unsafe {
            GetComputerNameExW(ComputerNamePhysicalDnsHostname, name.as_mut_ptr(), &mut len)
        };
        if named == 0 {
            return None;
        }
        let name = String::from_utf16(name.get(..len as usize)?).ok()?;
        (!name.is_empty()).then_some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_uptime_is_the_first_field_and_the_name_is_unquoted_and_both_fail_soft() {
        assert_eq!(
            uptime("350735.47 234388.90").map(|d| d.as_secs()),
            Some(350_735)
        );
        assert_eq!(uptime("not a number"), None);
        assert_eq!(uptime("-1.0 0.0"), None);

        assert_eq!(
            pretty_name("NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"")
                .as_deref(),
            Some("Debian GNU/Linux 13 (trixie)")
        );
        assert_eq!(pretty_name("NAME=\"Debian GNU/Linux\""), None);
        assert_eq!(
            pretty_name("PRETTY_NAME=\"\""),
            None,
            "an empty name is no name"
        );
    }

    #[test]
    fn the_box_id_is_systemds_app_specific_id() {
        // The vector from systemd's own `test-id128.c`.
        let app = Uuid::from_u128(0xf03daaeb_1c33_4b43_a732_172944bf772e);
        assert_eq!(
            app_specific("51df0b4bc3b04c9780e299b98ca373b8", &app).as_deref(),
            Some("1dee5954-e75c-4d6f-b96c-c6c04ca18a86")
        );
    }

    #[test]
    fn the_box_id_follows_the_machine() {
        let ours = app_specific("0123456789abcdef0123456789abcdef", &BOX_ID_APP);
        assert_eq!(
            ours.as_deref(),
            Some("9afd9204-8138-4c97-b08d-8788f4680c1f")
        );
        assert_eq!(
            app_specific("0123456789ABCDEF0123456789ABCDEF", &BOX_ID_APP),
            ours
        );
        assert_ne!(
            app_specific("fedcba9876543210fedcba9876543210", &BOX_ID_APP),
            ours
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_macs_box_id_is_keyed_on_its_ioplatformuuid() {
        let ioreg = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .expect("ioreg");
        let listed = String::from_utf8(ioreg.stdout)
            .unwrap()
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("\"IOPlatformUUID\" = ")?
                    .trim_matches('"')
                    .parse::<Uuid>()
                    .ok()
            })
            .expect("an IOPlatformUUID");

        assert_eq!(macos::platform_uuid(), Some(listed.simple().to_string()));
        assert_eq!(
            box_id(),
            app_specific(&listed.simple().to_string(), &BOX_ID_APP)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_macs_name_is_its_first_label() {
        assert_eq!(
            macos::short("box-01.example.com").as_deref(),
            Some("box-01")
        );
        assert_eq!(macos::short("box-01").as_deref(), Some("box-01"));
        for none in ["", ".x", "...", " "] {
            assert_eq!(macos::short(none), None, "{none:?}");
        }

        let this = hostname().expect("this Mac's name");
        assert!(!this.is_empty() && !this.contains('.'), "{this:?}");
    }

    #[test]
    fn windows_11_is_named_for_its_build_and_the_kernel_carries_the_patch_level() {
        assert_eq!(
            windows_product("Windows 10 Pro", Some("25H2"), Some("2009"), 26_200),
            "Windows 11 Pro 25H2",
            "ReleaseId is frozen at 2009 where DisplayVersion exists"
        );
        assert_eq!(
            windows_product("Windows 10 Pro", Some("22H2"), Some("2009"), 19_045),
            "Windows 10 Pro 22H2"
        );
        assert_eq!(
            windows_product("Windows Server 2016 Standard", None, Some("1607"), 14_393),
            "Windows Server 2016 Standard 1607"
        );
        assert_eq!(
            windows_product("Windows 10 Enterprise", None, None, 10_240),
            "Windows 10 Enterprise"
        );
        assert_eq!(
            windows_product("Windows Server 2025 Datacenter", Some("24H2"), None, 26_100),
            "Windows Server 2025 Datacenter 24H2"
        );

        assert_eq!(
            windows_kernel(10, 0, "26200", Some(9457)),
            "10.0.26200.9457"
        );
        assert_eq!(windows_kernel(10, 0, "14393", None), "10.0.14393");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_macs_os_kernel_and_uptime_are_the_ones_it_reports() {
        let asked = |program: &str, args: &[&str]| {
            let out = std::process::Command::new(program)
                .args(args)
                .output()
                .expect(program);
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        assert_eq!(
            os_pretty_name(),
            Some(format!("macOS {}", asked("sw_vers", &["-productVersion"])))
        );
        assert_eq!(kernel_release(), Some(asked("uname", &["-r"])));

        let booted: u64 = asked("sysctl", &["-n", "kern.boottime"])
            .strip_prefix("{ sec = ")
            .and_then(|rest| rest.split(',').next())
            .and_then(|sec| sec.parse().ok())
            .expect("kern.boottime's seconds");
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let up = boottime().expect("an uptime").as_secs();
        assert!(
            (wall - booted).abs_diff(up) <= 5,
            "up {up} s, booted {} s ago by the wall clock",
            wall - booted
        );
    }

    #[cfg(windows)]
    #[test]
    fn this_windows_computers_os_kernel_and_uptime_are_read() {
        let os = os_pretty_name().expect("a product name");
        assert!(os.starts_with("Windows "), "{os:?}");
        let kernel = kernel_release().expect("a kernel version");
        assert!(kernel.starts_with("10.0."), "{kernel:?}");
        assert!(boottime().is_some_and(|up| up > Duration::ZERO));
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_computers_name_is_its_dns_host_name() {
        let this = hostname().expect("this computer's name");
        assert!(!this.is_empty() && !this.contains('.'), "{this:?}");
    }

    #[test]
    fn a_machine_id_that_is_not_one_has_no_box_id() {
        for not_one in [
            "",
            "uninitialized",
            "00000000000000000000000000000000",
            "+123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0",
        ] {
            assert_eq!(app_specific(not_one, &BOX_ID_APP), None, "{not_one:?}");
        }
    }
}
