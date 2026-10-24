//! How the process ends, run as a child of this test binary: `child` is the
//! service when `WSLIB_SERVICE_CHILD` names what it does, and nothing otherwise.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wslib_service::Daemon;

const CHILD: &str = "WSLIB_SERVICE_CHILD";

#[test]
fn child() {
    let Ok(does) = std::env::var(CHILD) else {
        return;
    };
    let ran = Daemon::new("widgets").run(move |stop| async move {
        match does.as_str() {
            "serves" | "ends-in-error-once-stopped" => {
                println!("serving");
                stop.await;
                match does.as_str() {
                    "serves" => Ok(()),
                    _ => Err("an error while stopping"),
                }
            }
            "returns" => Ok(()),
            "fails" => Err("boom"),
            "panics" => panic!("boom"),
            other => panic!("no such child: {other}"),
        }
    });
    std::process::exit(if ran.is_ok() { 0 } else { 1 });
}

fn spawn(does: &str) -> Child {
    spawn_with(does, |command| command.env_remove("NOTIFY_SOCKET"))
}

fn spawn_with(does: &str, set: impl FnOnce(&mut Command) -> &mut Command) -> Child {
    set(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child", "--nocapture", "--test-threads=1"])
        .env(CHILD, does))
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawns")
}

fn ended(mut child: Child) -> (i32, String) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().ok();
            panic!("the child did not end");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status.code().expect("exited"), stderr)
}

fn stopped_by_sigterm(does: &str) -> (i32, String) {
    sigterm_once_serving(spawn(does))
}

fn sigterm_once_serving(mut child: Child) -> (i32, String) {
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while !line.trim_end().ends_with("serving") {
        line.clear();
        assert_ne!(stdout.read_line(&mut line).unwrap(), 0, "never served");
    }
    let sent = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    ended(child)
}

#[test]
fn a_service_stopped_by_sigterm_exits_successfully() {
    let (code, stderr) = stopped_by_sigterm("serves");
    assert_eq!(code, 0, "{stderr}");
}

#[test]
fn an_error_once_asked_to_stop_is_logged_and_still_a_success() {
    let (code, stderr) = stopped_by_sigterm("ends-in-error-once-stopped");
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("widgets: the service ended in error: an error while stopping"),
        "{stderr}"
    );
}

#[test]
fn a_service_that_returns_unasked_fails() {
    let (code, stderr) = ended(spawn("returns"));
    assert_eq!(code, 1);
    assert!(
        stderr.contains("widgets: the service ended without being asked to stop"),
        "{stderr}"
    );
}

#[test]
fn a_service_that_fails_unasked_fails_saying_why() {
    let (code, stderr) = ended(spawn("fails"));
    assert_eq!(code, 1);
    assert!(
        stderr.contains("widgets: the service ended in error: boom"),
        "{stderr}"
    );
}

#[test]
fn a_service_that_panics_fails_saying_where() {
    let (code, stderr) = ended(spawn("panics"));
    assert_eq!(code, 1);
    assert!(
        stderr.contains("widgets: a thread of the service panicked at ")
            && stderr.contains("process.rs")
            && stderr.contains(": boom"),
        "{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn under_systemd_it_says_ready_feeds_the_watchdog_and_says_stopping_with_the_grace() {
    use std::os::unix::net::UnixDatagram;

    let dir = std::env::temp_dir().join(format!("wslib-service-notify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("notify");
    let listener = UnixDatagram::bind(&socket).unwrap();
    listener
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let received = || {
        let mut buffer = [0; 512];
        let length = listener.recv(&mut buffer).expect("a notification");
        String::from_utf8(buffer[..length].to_vec()).unwrap()
    };

    let child = spawn_with("serves", |command| {
        command
            .env("NOTIFY_SOCKET", &socket)
            .env("WATCHDOG_USEC", "200000")
            .env_remove("WATCHDOG_PID")
    });
    let mut said = Vec::new();
    while !said.iter().any(|said| said == "READY=1")
        || !said.iter().any(|said| said == "WATCHDOG=1")
    {
        said.push(received());
    }
    let (code, stderr) = sigterm_once_serving(child);
    assert_eq!(code, 0, "{stderr}");
    let stopping = std::iter::repeat_with(received)
        .find(|said| said != "WATCHDOG=1")
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(stopping, "STOPPING=1\nEXTEND_TIMEOUT_USEC=20000000");
}
