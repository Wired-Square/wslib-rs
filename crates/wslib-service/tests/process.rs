//! How the process ends, run as a child of this test binary: `child` is the
//! service when `WSLIB_SERVICE_CHILD` names what it does, and nothing otherwise.
#![cfg(unix)]

use std::fmt;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wslib_service::Daemon;

const CHILD: &str = "WSLIB_SERVICE_CHILD";

/// An error with a cause it shows only in the alternate form, as anyhow's do.
struct Said(&'static str, Option<&'static str>);

impl fmt::Display for Said {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)?;
        match self.1 {
            Some(cause) if f.alternate() => write!(f, ": {cause}"),
            _ => Ok(()),
        }
    }
}

#[test]
fn child() {
    let Ok(does) = std::env::var(CHILD) else {
        return;
    };
    if matches!(does.as_str(), "serves" | "stops-itself") {
        wslib_telemetry::Telemetry::new("info")
            .writer(std::io::stderr)
            .without_time()
            .init();
    }
    let ran = Daemon::new("widgets")
        .grace(Duration::from_millis(200))
        .run(move |mut stop| async move {
            match does.as_str() {
                "serves" => {
                    println!("serving");
                    stop.await;
                    Ok("stopped")
                }
                "ends-in-error-once-stopped" => {
                    println!("serving");
                    stop.await;
                    Err(Said("an error while stopping", None))
                }
                "overruns" => {
                    println!("serving");
                    stop.await;
                    std::future::pending().await
                }
                "says-ready-itself" => {
                    let ready = stop.ready();
                    let early = tokio::time::timeout(Duration::from_millis(50), &mut stop);
                    assert!(early.await.is_err(), "not stopped yet");
                    ready.send(Some("x"));
                    ready.send(Some("y"));
                    println!("serving");
                    stop.await;
                    Ok("stopped")
                }
                "stops-itself" => {
                    stop.token().cancel();
                    stop.await;
                    Ok("to apply")
                }
                "stops-itself-and-overruns" => {
                    stop.token().cancel();
                    stop.await;
                    std::future::pending().await
                }
                "returns" => Ok("unasked"),
                "fails" => Err(Said("boom", Some("the cause"))),
                "panics" => panic!("boom"),
                other => panic!("no such child: {other}"),
            }
        });
    match ran {
        Ok(value) => {
            println!("returned {value}");
            std::process::exit(0);
        }
        Err(_) => std::process::exit(1),
    }
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

struct Ended {
    code: i32,
    stdout: String,
    stderr: String,
}

fn ended(mut child: Child) -> Ended {
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
    let read = |pipe: Option<&mut dyn Read>| {
        let mut text = String::new();
        if let Some(pipe) = pipe {
            pipe.read_to_string(&mut text).unwrap();
        }
        text
    };
    Ended {
        code: status.code().expect("exited"),
        stdout: read(child.stdout.as_mut().map(|pipe| pipe as &mut dyn Read)),
        stderr: read(child.stderr.as_mut().map(|pipe| pipe as &mut dyn Read)),
    }
}

fn stopping(ended: &Ended) -> Vec<&str> {
    let lines = ended.stderr.lines();
    lines.filter(|line| line.contains("stopping")).collect()
}

fn stopped_by_sigterm(does: &str) -> Ended {
    sigterm_once_serving(spawn(does))
}

fn sigterm_once_serving(mut child: Child) -> Ended {
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
    let mut ended = ended(child);
    stdout.read_to_string(&mut ended.stdout).unwrap();
    ended
}

#[test]
fn a_service_stopped_by_sigterm_exits_successfully_with_what_main_returned() {
    let ended = stopped_by_sigterm("serves");
    assert_eq!(ended.code, 0, "{}", ended.stderr);
    assert!(
        ended.stdout.contains("returned stopped"),
        "{}",
        ended.stdout
    );
    assert!(
        matches!(&stopping(&ended)[..], [line] if line.contains("SIGTERM") && line.contains("grace=200ms")),
        "{}",
        ended.stderr
    );
}

#[test]
fn an_error_once_asked_to_stop_is_logged_and_a_failure() {
    let ended = stopped_by_sigterm("ends-in-error-once-stopped");
    assert_eq!(ended.code, 1);
    assert!(
        ended
            .stderr
            .contains("widgets: the service ended in error: an error while stopping"),
        "{}",
        ended.stderr
    );
}

#[test]
fn a_service_still_running_its_grace_after_sigterm_overran() {
    let ended = stopped_by_sigterm("overruns");
    assert_eq!(ended.code, 1);
    assert!(
        ended
            .stderr
            .contains("widgets: the service did not end within its grace of 200ms once stopped"),
        "{}",
        ended.stderr
    );
}

#[test]
fn a_stop_of_its_own_is_a_success_with_what_main_returned() {
    let ended = ended(spawn("stops-itself"));
    assert_eq!(ended.code, 0, "{}", ended.stderr);
    assert!(
        ended.stdout.contains("returned to apply"),
        "{}",
        ended.stdout
    );
    assert!(
        matches!(&stopping(&ended)[..], [line] if line.ends_with("stopping, by the service itself grace=200ms")),
        "{}",
        ended.stderr
    );
}

#[test]
fn a_stop_of_its_own_that_overruns_its_grace_overran() {
    let ended = ended(spawn("stops-itself-and-overruns"));
    assert_eq!(ended.code, 1);
    assert!(
        ended
            .stderr
            .contains("did not end within its grace of 200ms"),
        "{}",
        ended.stderr
    );
}

#[test]
fn a_service_that_returns_unasked_fails() {
    let ended = ended(spawn("returns"));
    assert_eq!(ended.code, 1);
    assert!(
        ended
            .stderr
            .contains("widgets: the service ended without being asked to stop"),
        "{}",
        ended.stderr
    );
}

#[test]
fn a_service_that_fails_unasked_fails_saying_why_with_the_whole_chain() {
    let ended = ended(spawn("fails"));
    assert_eq!(ended.code, 1);
    assert!(
        ended
            .stderr
            .contains("widgets: the service ended in error: boom: the cause"),
        "{}",
        ended.stderr
    );
}

#[test]
fn a_service_that_panics_fails_saying_where() {
    let ended = ended(spawn("panics"));
    assert_eq!(ended.code, 1);
    assert!(
        ended
            .stderr
            .contains("widgets: a thread of the service panicked at ")
            && ended.stderr.contains("process.rs")
            && ended.stderr.contains(": boom"),
        "{}",
        ended.stderr
    );
}

#[cfg(target_os = "linux")]
mod systemd {
    use std::os::unix::net::UnixDatagram;
    use std::path::PathBuf;

    use super::*;

    struct Notified {
        dir: PathBuf,
        socket: PathBuf,
        listener: UnixDatagram,
    }

    impl Notified {
        fn bind(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("wslib-service-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let socket = dir.join("notify");
            let listener = UnixDatagram::bind(&socket).unwrap();
            listener
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            Self {
                dir,
                socket,
                listener,
            }
        }

        fn received(&self) -> String {
            let mut buffer = [0; 512];
            let length = self.listener.recv(&mut buffer).expect("a notification");
            String::from_utf8(buffer[..length].to_vec()).unwrap()
        }

        fn rest(&self) -> Vec<String> {
            self.listener.set_nonblocking(true).unwrap();
            let mut buffer = [0; 512];
            std::iter::from_fn(|| {
                let length = self.listener.recv(&mut buffer).ok()?;
                Some(String::from_utf8(buffer[..length].to_vec()).unwrap())
            })
            .collect()
        }

        fn spawn(&self, does: &str, watchdog: Option<&str>) -> Child {
            spawn_with(does, |command| {
                command
                    .env("NOTIFY_SOCKET", &self.socket)
                    .env_remove("WATCHDOG_PID");
                match watchdog {
                    Some(usec) => command.env("WATCHDOG_USEC", usec),
                    None => command.env_remove("WATCHDOG_USEC"),
                }
            })
        }
    }

    impl Drop for Notified {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    #[test]
    fn it_says_ready_feeds_the_watchdog_and_answers_sigterm_with_stopping_and_the_grace() {
        let notified = Notified::bind("notify");
        let child = notified.spawn("serves", Some("200000"));
        let mut said = Vec::new();
        while !said.iter().any(|said| said == "READY=1")
            || !said.iter().any(|said| said == "WATCHDOG=1")
        {
            said.push(notified.received());
        }
        let ended = sigterm_once_serving(child);
        assert_eq!(ended.code, 0, "{}", ended.stderr);
        let stopping = std::iter::repeat_with(|| notified.received())
            .find(|said| said != "WATCHDOG=1")
            .unwrap();
        assert_eq!(stopping, "STOPPING=1\nEXTEND_TIMEOUT_USEC=5200000");
    }

    #[test]
    fn a_taken_ready_says_ready_with_its_status_once_and_the_first_poll_does_not() {
        let notified = Notified::bind("ready");
        let ended = sigterm_once_serving(notified.spawn("says-ready-itself", None));
        assert_eq!(ended.code, 0, "{}", ended.stderr);
        assert_eq!(notified.received(), "READY=1\nSTATUS=x");
        assert_eq!(notified.received(), "STATUS=y");
        assert_eq!(notified.rest(), ["STOPPING=1\nEXTEND_TIMEOUT_USEC=5200000"]);
    }

    #[test]
    fn a_stop_of_its_own_tells_systemd_nothing() {
        let notified = Notified::bind("self-stop");
        let ended = ended(notified.spawn("stops-itself", None));
        assert_eq!(ended.code, 0, "{}", ended.stderr);
        assert!(
            ended.stdout.contains("returned to apply"),
            "{}",
            ended.stdout
        );
        assert_eq!(notified.received(), "READY=1");
        assert_eq!(notified.rest(), Vec::<String>::new());
    }
}
