//! Opening the pipe, and checking that its owner is the service.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::time::Duration;

use tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::time::{Instant, sleep};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_CREATE_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use wslib_host::Sid;

use crate::path::is_local_pipe;

/// The `0x12019b` the service's pipe grants its group, and no more.
const PIPE_ACCESS: u32 = (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !FILE_CREATE_PIPE_INSTANCE;

const BUSY_FOR: Duration = Duration::from_secs(2);
const BUSY_POLL: Duration = Duration::from_millis(50);

/// Why [`connect`] returned no connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
    /// Not a `\\.\pipe\…` path, or one with an empty, all-dot or NUL component.
    #[error("not a pipe on this machine")]
    NotLocal,

    /// No pipe by that name exists: the service is not running, or not yet listening.
    #[error("the service is not running")]
    NotRunning,

    /// Every instance of the pipe stayed in use for the two seconds [`connect`] waits.
    #[error("the service is busy")]
    Busy,

    /// The pipe's security refuses this user, whoever owns it: on an appliance, a
    /// user outside the endpoint's group.
    #[error("this user may not open the pipe")]
    Denied,

    /// The pipe's owner is not the service's account; also, before the pipe is
    /// opened, no service by that name is installed or the name could not be one.
    #[error("the pipe does not belong to the service")]
    NotOurService,

    /// Any other failure to look up the service, open the pipe or read its owner.
    #[error(transparent)]
    Io(io::Error),
}

/// Connects to the pipe at `pipe`, a `\\.\pipe\…` path, and returns the
/// connection once the pipe's owner is shown to be `NT SERVICE\<service>`. A
/// pipe owned by anyone else, SYSTEM included, is refused. An administrator can
/// set any owner, so this stops only unprivileged squatters.
///
/// Waits up to two seconds while every instance of the pipe is in use. Needs a
/// Tokio runtime with IO and time enabled.
pub async fn connect(
    pipe: impl AsRef<OsStr>,
    service: &str,
) -> Result<NamedPipeClient, ConnectError> {
    let pipe = pipe.as_ref();
    if !is_local_pipe(pipe) {
        return Err(ConnectError::NotLocal);
    }
    let service = service_sid(service)?;
    let client = open(pipe).await?;
    check_owner(&client, &service)?;
    Ok(client)
}

fn service_sid(service: &str) -> Result<Sid, ConnectError> {
    wslib_host::service_account(service)
        .map_err(ConnectError::Io)?
        .ok_or(ConnectError::NotOurService)
}

async fn open(pipe: &OsStr) -> Result<NamedPipeClient, ConnectError> {
    let name: Vec<u16> = pipe.encode_wide().chain([0]).collect();
    let deadline = Instant::now() + BUSY_FOR;
    loop {
        match open_once(&name) {
            Ok(client) => return Ok(client),
            Err(e) => match os_error(&e) {
                Some(ERROR_FILE_NOT_FOUND) => return Err(ConnectError::NotRunning),
                Some(ERROR_ACCESS_DENIED) => return Err(ConnectError::Denied),
                Some(ERROR_PIPE_BUSY) if Instant::now() >= deadline => {
                    return Err(ConnectError::Busy);
                }
                Some(ERROR_PIPE_BUSY) => sleep(BUSY_POLL).await,
                _ => return Err(ConnectError::Io(e)),
            },
        }
    }
}

fn open_once(name: &[u16]) -> io::Result<NamedPipeClient> {
    // SAFETY: `name` is NUL-terminated, and nothing else is passed by pointer.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            PIPE_ACCESS,
            0,
            ptr::null(),
            OPEN_EXISTING,
            // Identification only: a squatter is refused after it has the
            // connection, so it must not be able to impersonate the user.
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a pipe handle this function opened, overlapped, and owns.
    unsafe { NamedPipeClient::from_raw_handle(handle) }
}

fn os_error(e: &io::Error) -> Option<u32> {
    e.raw_os_error().map(|code| code as u32)
}

fn check_owner(client: &NamedPipeClient, expected: &Sid) -> Result<(), ConnectError> {
    if wslib_host::owner(client).map_err(ConnectError::Io)? == *expected {
        Ok(())
    } else {
        Err(ConnectError::NotOurService)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NONE_MAPPED, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TokenOwner,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use wslib_host::current_user;

    use super::*;

    /// Installed on every Windows machine, and never the owner of a test's pipe.
    const OTHER_SERVICE: &str = "EventLog";
    const NOT_INSTALLED: &str = "wslib-appliance-client-test-not-installed";

    macro_rules! assert_refused {
        ($result:expr, $why:pat) => {
            let result = $result;
            assert!(matches!(result, Err($why)), "{result:?}");
        };
    }

    fn pipe_name() -> String {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        format!(
            r"\\.\pipe\wslib-appliance-client-test-{}-{n}",
            std::process::id()
        )
    }

    fn listening() -> (String, NamedPipeServer) {
        let name = pipe_name();
        let server = ServerOptions::new().create(&name).unwrap();
        (name, server)
    }

    /// The default owner of what this process creates: the user, or
    /// Administrators in an elevated process.
    fn token_owner() -> Sid {
        let mut token: HANDLE = ptr::null_mut();
        // `u64` for the alignment the structure needs.
        let mut buf = [0u64; 16];
        let mut len = 0;
        // SAFETY: `buf` is as long as the length passed; `TOKEN_OWNER` begins
        // with the SID's pointer, into `buf`, which outlives the copy.
        unsafe {
            assert_ne!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token),
                0
            );
            assert_ne!(
                GetTokenInformation(
                    token,
                    TokenOwner,
                    buf.as_mut_ptr().cast(),
                    size_of_val(&buf) as u32,
                    &mut len,
                ),
                0
            );
            CloseHandle(token);
            Sid::from_psid(*buf.as_ptr().cast::<PSID>()).unwrap()
        }
    }

    /// Owned by this user, with a protected DACL granting only the user `access`, if any.
    fn listening_granting_user(access: Option<u32>) -> (String, NamedPipeServer) {
        let user = current_user().unwrap();
        let ace = access.map_or_else(String::new, |a| format!("(A;;{a:#x};;;{user})"));
        let sddl: Vec<u16> = format!("O:{user}D:P{ace}")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let name = pipe_name();
        // SAFETY: `sddl` is NUL-terminated; `descriptor` lives until the pipe
        // is created and is then freed once.
        unsafe {
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                ),
                0
            );
            let mut attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let server = ServerOptions::new()
                .create_with_security_attributes_raw(&name, (&raw mut attributes).cast());
            LocalFree(descriptor);
            (name, server.unwrap())
        }
    }

    #[tokio::test]
    async fn a_pipe_the_service_does_not_own_is_refused() {
        let (name, _server) = listening();
        let client = open(OsStr::new(&name)).await.unwrap();
        let service = service_sid(OTHER_SERVICE).unwrap();
        assert_refused!(check_owner(&client, &service), ConnectError::NotOurService);
    }

    #[tokio::test]
    async fn a_pipe_owned_by_the_expected_account_is_accepted() {
        let (name, _server) = listening();
        let client = open(OsStr::new(&name)).await.unwrap();
        check_owner(&client, &token_owner()).unwrap();
    }

    #[tokio::test]
    async fn a_pipe_withholding_instance_creation_is_opened() {
        let (name, _server) = listening_granting_user(Some(0x0012_019b));
        let client = open(OsStr::new(&name)).await.unwrap();
        check_owner(&client, &current_user().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn a_user_the_pipe_grants_nothing_is_denied() {
        let (name, _server) = listening_granting_user(None);
        assert_refused!(connect(&name, OTHER_SERVICE).await, ConnectError::Denied);
    }

    #[test]
    fn a_service_resolves_to_its_service_sid() {
        let Ok(sid) = service_sid(OTHER_SERVICE) else {
            panic!("{OTHER_SERVICE} did not resolve to one service's SID");
        };
        let rendered = sid.to_string();
        assert!(rendered.starts_with("S-1-5-80-"), "{rendered}");
        assert_eq!(rendered.split('-').count(), 9, "{rendered}");
    }

    #[test]
    fn a_service_that_is_not_installed_has_no_account() {
        let Err(unmapped) = Sid::of_account(&format!(r"NT SERVICE\{NOT_INSTALLED}")) else {
            panic!("an uninstalled service resolved");
        };
        assert_eq!(os_error(&unmapped), Some(ERROR_NONE_MAPPED), "{unmapped:?}");
    }

    /// The only instance is held, so opening the pipe would be `Busy`.
    #[tokio::test]
    async fn a_service_that_cannot_own_the_pipe_is_refused_before_it_is_opened() {
        let (name, _server) = listening();
        let _only_instance = ClientOptions::new().open(&name).unwrap();
        for service in [
            NOT_INSTALLED,
            "ALL SERVICES",
            "",
            r"NT SERVICE\EventLog",
            "a/b",
            "EventLog\0",
        ] {
            assert_refused!(connect(&name, service).await, ConnectError::NotOurService);
        }
    }

    #[tokio::test]
    async fn a_missing_pipe_means_the_service_is_not_running() {
        assert_refused!(
            connect(pipe_name(), OTHER_SERVICE).await,
            ConnectError::NotRunning
        );
    }

    #[tokio::test]
    async fn a_remote_pipe_is_refused_before_it_is_opened() {
        assert_refused!(
            connect(r"\\wslib-appliance-client-test\pipe\x", OTHER_SERVICE).await,
            ConnectError::NotLocal
        );
    }

    #[tokio::test]
    async fn a_busy_pipe_is_retried_until_an_instance_is_free() {
        let (name, _server) = listening();
        let _only_instance = ClientOptions::new().open(&name).unwrap();

        let started = Instant::now();
        let (opened, _second_instance) = tokio::join!(open(OsStr::new(&name)), async {
            sleep(Duration::from_millis(300)).await;
            ServerOptions::new().create(&name).unwrap()
        });
        opened.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    #[tokio::test]
    async fn a_busy_pipe_is_given_up_on_within_the_bound() {
        let (name, _server) = listening();
        let _only_instance = ClientOptions::new().open(&name).unwrap();

        let started = Instant::now();
        assert_refused!(connect(&name, OTHER_SERVICE).await, ConnectError::Busy);
        let waited = started.elapsed();
        assert!(waited >= BUSY_FOR, "{waited:?}");
        assert!(waited < BUSY_FOR + Duration::from_secs(1), "{waited:?}");
    }
}
