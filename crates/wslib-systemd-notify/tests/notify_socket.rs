#![cfg(unix)]

use std::os::unix::net::UnixDatagram;
use std::time::Duration;

#[test]
fn each_call_sends_its_message_to_notify_socket() {
    let dir = std::env::temp_dir().join(format!("wslib-sd-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("notify");
    let listener = UnixDatagram::bind(&path).unwrap();
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var("NOTIFY_SOCKET", &path) };

    wslib_systemd_notify::ready().unwrap();
    wslib_systemd_notify::status("serving").unwrap();
    wslib_systemd_notify::extend_timeout(Duration::from_millis(1500)).unwrap();
    wslib_systemd_notify::watchdog().unwrap();
    wslib_systemd_notify::stopping().unwrap();

    let mut buf = [0; 64];
    let received: Vec<String> = (0..5)
        .map(|_| {
            let n = listener.recv(&mut buf).unwrap();
            String::from_utf8(buf[..n].to_vec()).unwrap()
        })
        .collect();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        received,
        [
            "READY=1",
            "STATUS=serving",
            "EXTEND_TIMEOUT_USEC=1500000",
            "WATCHDOG=1",
            "STOPPING=1",
        ]
    );
}
