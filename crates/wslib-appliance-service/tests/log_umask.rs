//! A binary of its own, because it sets the process's umask and installs the
//! global subscriber.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use wslib_appliance_service::install_logs;

#[test]
fn the_log_file_is_group_readable_whatever_the_umask_and_timestamped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("service.log");

    // SAFETY: `umask` swaps a process-wide value and cannot fail.
    let umask = unsafe { libc::umask(0o077) };
    let installed = install_logs(&path, &["log_umask"]);
    unsafe { libc::umask(umask) };
    installed.expect("installs");

    tracing::info!("a line for the file");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640);
    let written = std::fs::read_to_string(&path).unwrap();
    let line = written
        .lines()
        .find(|line| line.ends_with("a line for the file"))
        .unwrap_or_else(|| panic!("{written}"));
    assert!(line.starts_with("20"), "timestamped: {line}");
}
