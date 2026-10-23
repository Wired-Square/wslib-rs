use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// One `op` invocation, as a [`Runner`] receives it.
#[derive(Clone)]
pub struct Call {
    pub(crate) args: Vec<String>,
    pub(crate) shown: Vec<String>,
    pub(crate) stdin: Option<Vec<u8>>,
    pub(crate) env: Vec<(String, String)>,
}

impl Call {
    pub(crate) fn new() -> Self {
        Self {
            args: Vec::new(),
            shown: Vec::new(),
            stdin: None,
            env: Vec::new(),
        }
    }

    pub(crate) fn of<const N: usize>(args: [&str; N]) -> Self {
        args.into_iter().fold(Self::new(), Self::arg)
    }

    pub(crate) fn arg(mut self, arg: impl Into<String>) -> Self {
        let arg = arg.into();
        self.shown.push(arg.clone());
        self.args.push(arg);
        self
    }

    pub(crate) fn secret_arg(mut self, arg: String, shown: String) -> Self {
        self.args.push(arg);
        self.shown.push(shown);
        self
    }

    /// The arguments after the program name.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// What to write to `op`'s stdin, if anything.
    pub fn stdin(&self) -> Option<&[u8]> {
        self.stdin.as_deref()
    }

    /// Variables to set in `op`'s environment.
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }
}

/// The command line with assignment values redacted; stdin and the environment left out.
impl fmt::Display for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("op")?;
        self.shown.iter().try_for_each(|arg| write!(f, " {arg}"))
    }
}

impl fmt::Debug for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Call({self})")
    }
}

/// What `op` answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: String,
    /// The exit code; `None` when a signal ended `op`.
    pub code: Option<i32>,
}

impl Output {
    /// A success with `stdout`.
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: String::new(),
            code: Some(0),
        }
    }

    /// A failure, exit code 1, with `stderr`.
    pub fn fail(stderr: impl Into<String>) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: stderr.into(),
            code: Some(1),
        }
    }

    /// Whether `op` exited 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// How `op` is run: [`ShellRunner`], or a fake in tests.
pub trait Runner {
    /// Runs `op` with `call`; an `io::ErrorKind::NotFound` means there is no `op`,
    /// and `TimedOut` that it did not answer in time.
    fn run(&self, call: &Call) -> io::Result<Output>;
}

impl<R: Runner + ?Sized> Runner for &R {
    fn run(&self, call: &Call) -> io::Result<Output> {
        (**self).run(call)
    }
}

/// Runs the real `op`, killing it after a timeout.
#[derive(Clone, Debug)]
pub struct ShellRunner {
    program: OsString,
    timeout: Duration,
    interactive: bool,
}

impl Default for ShellRunner {
    fn default() -> Self {
        Self {
            program: "op".into(),
            timeout: Duration::from_secs(30),
            interactive: false,
        }
    }
}

impl ShellRunner {
    /// `op` from `PATH`, a 30 s timeout, and stdin closed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `program` in place of `op`.
    pub fn with_program(mut self, program: impl Into<OsString>) -> Self {
        self.program = program.into();
        self
    }

    /// Kills `op` after `timeout` instead of 30 s.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Gives `op` this process's stdin when it is not fed input, so it can ask a
    /// person at a terminal to unlock.
    pub fn interactive(mut self) -> Self {
        self.interactive = true;
        self
    }
}

impl Runner for ShellRunner {
    fn run(&self, call: &Call) -> io::Result<Output> {
        let stdin = match (call.stdin.is_some(), self.interactive) {
            (true, _) => Stdio::piped(),
            (false, true) => Stdio::inherit(),
            (false, false) => Stdio::null(),
        };
        let mut child = Command::new(&self.program)
            .args(&call.args)
            .envs(call.env.iter().map(|(k, v)| (k, v)))
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Every pipe on its own thread: a child blocked writing a full pipe
        // (~64 KiB) never exits, so reading them in turn deadlocks.
        let writer = feed(child.stdin.take(), call.stdin.clone());
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());

        let status = wait(&mut child, self.timeout)?;
        let _ = writer.join();
        let stdout = stdout.join().unwrap_or_default();
        let stderr = stderr.join().unwrap_or_default();
        Ok(Output {
            stdout,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            code: status.code(),
        })
    }
}

fn wait(child: &mut Child, timeout: Duration) -> io::Result<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "op did not answer in time",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn feed(pipe: Option<impl Write + Send + 'static>, input: Option<Vec<u8>>) -> JoinHandle<()> {
    thread::spawn(move || {
        if let (Some(mut pipe), Some(input)) = (pipe, input) {
            let _ = pipe.write_all(&input);
        }
    })
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Call {
        Call::new().arg("-c").arg(script)
    }

    fn shell() -> ShellRunner {
        ShellRunner::new().with_program("/bin/sh")
    }

    #[test]
    fn output_past_the_pipe_buffer_on_both_streams_comes_back_whole() {
        let script = "head -c 300000 /dev/zero; head -c 200000 /dev/zero >&2";
        let out = shell().run(&sh(script)).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.len(), 300_000);
        assert_eq!(out.stderr.len(), 200_000);
    }

    #[test]
    fn stdin_comes_back_byte_for_byte() {
        let input: Vec<u8> = (0..=255u8).cycle().take(150_000).chain(*b"\r\n").collect();
        let mut call = sh("cat");
        call.stdin = Some(input.clone());
        assert_eq!(shell().run(&call).unwrap().stdout, input);
    }

    #[test]
    fn the_environment_is_set() {
        let mut call = sh("printf %s \"$WSLIB_TEST\"");
        call.env = vec![("WSLIB_TEST".into(), "set".into())];
        assert_eq!(shell().run(&call).unwrap().stdout, b"set");
    }

    #[test]
    fn a_failure_keeps_its_code_and_stderr() {
        let out = shell().run(&sh("echo nope >&2; exit 3")).unwrap();
        assert_eq!((out.code, out.stderr.as_str()), (Some(3), "nope\n"));
    }

    #[test]
    fn a_slow_op_is_killed_at_the_timeout() {
        let runner = shell().with_timeout(Duration::from_millis(100));
        let start = Instant::now();
        let error = runner.run(&sh("sleep 5")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_missing_program_is_not_found() {
        let runner = ShellRunner::new().with_program("wslib-1password-no-such-op");
        assert_eq!(
            runner.run(&Call::new()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
