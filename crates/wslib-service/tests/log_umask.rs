//! A binary of its own, because it sets the process's umask and installs the
//! global subscriber.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use wslib_service::LogFile;

#[test]
fn the_log_file_is_group_readable_whatever_the_umask_and_timestamped() {
    let dir = std::env::temp_dir().join(format!("wslib-service-umask-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("service.log");

    // SAFETY: `umask` swaps a process-wide value and cannot fail.
    let umask = unsafe { libc::umask(0o077) };
    let opened = LogFile::open(&path);
    unsafe { libc::umask(umask) };
    wslib_telemetry::Telemetry::new("info")
        .writer(Arc::new(opened.expect("opens")))
        .init();

    tracing::info!("a line for the file");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let written = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(mode, 0o640);
    let line = written
        .lines()
        .find(|line| line.ends_with("a line for the file"))
        .unwrap_or_else(|| panic!("{written}"));
    assert!(line.starts_with("20"), "timestamped: {line}");
    assert!(!line.contains('\x1b'), "no colour: {line:?}");
}
