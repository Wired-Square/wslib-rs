use super::*;

const APP: Uuid = Uuid::from_u128(0x6e882fe4_9003_4dc4_9739_89aa7425c9b9);

fn app_specific_text(machine_id: &str, app: Uuid) -> Option<String> {
    app_specific(machine_id, app).map(|id| id.to_string())
}

#[test]
fn the_uptime_is_the_first_field_and_the_name_is_unquoted_and_both_fail_soft() {
    assert_eq!(
        parse_uptime("350735.47 234388.90").map(|d| d.as_secs()),
        Some(350_735)
    );
    assert_eq!(parse_uptime("not a number"), None);
    assert_eq!(parse_uptime("-1.0 0.0"), None);

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
fn the_machine_id_is_systemds_app_specific_id() {
    // The vector from systemd's own `test-id128.c`.
    let app = Uuid::from_u128(0xf03daaeb_1c33_4b43_a732_172944bf772e);
    assert_eq!(
        app_specific_text("51df0b4bc3b04c9780e299b98ca373b8", app).as_deref(),
        Some("1dee5954-e75c-4d6f-b96c-c6c04ca18a86")
    );
}

/// What `systemd-id128 machine-id --app-specific=6e882fe490034dc4973989aa7425c9b9 -u`
/// prints under this machine id, as ring's HMAC-SHA256 computed it before.
#[test]
fn the_machine_id_is_what_systemd_id128_prints() {
    assert_eq!(
        app_specific_text("0123456789abcdef0123456789abcdef", APP).as_deref(),
        Some("9afd9204-8138-4c97-b08d-8788f4680c1f")
    );
}

#[test]
fn the_machine_id_follows_the_machine() {
    let ours = app_specific("0123456789abcdef0123456789abcdef", APP);
    assert!(ours.is_some());
    assert_eq!(app_specific("0123456789ABCDEF0123456789ABCDEF", APP), ours);
    assert_ne!(app_specific("fedcba9876543210fedcba9876543210", APP), ours);
}

#[test]
fn a_machine_id_that_is_not_one_has_no_app_specific_id() {
    for not_one in [
        "",
        "uninitialized",
        "00000000000000000000000000000000",
        "+123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef0",
    ] {
        assert_eq!(app_specific(not_one, APP), None, "{not_one:?}");
    }
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
fn this_macs_machine_id_is_keyed_on_its_ioplatformuuid() {
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

    assert_eq!(macos::hardware_uuid(), Some(listed.simple().to_string()));
    assert_eq!(
        machine_id(APP),
        app_specific(&listed.simple().to_string(), APP)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_macs_name_is_its_first_label() {
    assert_eq!(
        macos::short("jayne.ferrara.com.au").as_deref(),
        Some("jayne")
    );
    assert_eq!(macos::short("jayne").as_deref(), Some("jayne"));
    for none in ["", ".x", "...", " "] {
        assert_eq!(macos::short(none), None, "{none:?}");
    }

    let this = hostname().expect("this Mac's name");
    assert!(!this.is_empty() && !this.contains('.'), "{this:?}");
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
        os_name(),
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
    let up = uptime().expect("an uptime").as_secs();
    assert!(
        (wall - booted).abs_diff(up) <= 5,
        "up {up} s, booted {} s ago by the wall clock",
        wall - booted
    );
}

#[cfg(windows)]
#[test]
fn this_windows_computers_os_kernel_and_uptime_are_read() {
    let os = os_name().expect("a product name");
    assert!(os.starts_with("Windows "), "{os:?}");
    let kernel = kernel_release().expect("a kernel version");
    assert!(kernel.starts_with("10.0."), "{kernel:?}");
    assert!(uptime().is_some_and(|up| up > Duration::ZERO));
}

#[cfg(windows)]
#[test]
fn a_windows_computers_name_is_its_dns_host_name() {
    let this = hostname().expect("this computer's name");
    assert!(!this.is_empty() && !this.contains('.'), "{this:?}");
}

#[cfg(windows)]
#[test]
fn windows_has_no_machine_id() {
    assert_eq!(machine_id(APP), None);
}
