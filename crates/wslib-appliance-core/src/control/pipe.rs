//! The control sockets as named pipes, where who may open one is the pipe's
//! DACL rather than a socket file's group, and the peer is the client process's
//! token user rather than a uid.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;

use axum::Router;
use axum::serve::Listener;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_OWNER, ERROR_PIPE_BUSY, HANDLE,
    LocalFree, STATUS_SUCCESS,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_OBJECT_ATTRIBUTES, LsaClose, LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy,
    LsaQueryInformationPolicy, POLICY_ACCOUNT_DOMAIN_INFO, POLICY_VIEW_LOCAL_INFORMATION,
    PolicyAccountDomainInformation,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
    GetAce, GetAclInformation, GetSecurityDescriptorControl, LookupAccountNameW,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    SID_NAME_USE, SidTypeAlias,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_CREATE_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use wslib_appliance_types::Role;
use wslib_host::Sid;

use super::windows_account::{named_actor, one_rid_under};
use super::{ControlEndpoint, ServeError, serve_bounded};
use crate::extract::LOCAL_ACTOR;

/// What an endpoint's group is granted: without `FILE_CREATE_PIPE_INSTANCE`, so
/// a member cannot serve an instance of the pipe itself.
pub(super) const CLIENT_ACCESS: u32 =
    (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !FILE_CREATE_PIPE_INSTANCE;

pub(super) const LOCAL_SYSTEM: &str = "S-1-5-18";
const ALLOWED: u8 = ACCESS_ALLOWED_ACE_TYPE as u8;
const PIPE_PREFIX: &str = r"\\.\pipe\";
const RETRY: Duration = Duration::from_secs(1);
const RETRY_CAP: Duration = Duration::from_secs(60);

/// An ACE's type, mask and SID.
pub(super) type Ace = (u8, u32, String);

pub(super) fn same_endpoint(a: &Path, b: &Path) -> bool {
    a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
}

pub(super) async fn serve_endpoint(
    router: Router,
    ControlEndpoint {
        path,
        ceiling,
        group,
        service,
    }: ControlEndpoint,
    stop: CancellationToken,
) -> Result<(), ServeError> {
    let security = Security::new(group.as_deref(), service.as_deref()).map_err(|because| {
        ServeError::Socket {
            path: path.clone(),
            because,
        }
    })?;
    serve_secured(router, path, ceiling, security, stop).await
}

pub(super) async fn serve_secured(
    router: Router,
    name: PathBuf,
    ceiling: Role,
    mut security: Security,
    stop: CancellationToken,
) -> Result<(), ServeError> {
    let failed = |because: String| ServeError::Socket {
        path: name.clone(),
        because,
    };
    if !is_pipe_name(&name) {
        return Err(failed(format!(
            "a pipe name is {PIPE_PREFIX} and components neither empty nor all dots"
        )));
    }
    let first = security.create(&name, true).map_err(|e| {
        match e.raw_os_error().map(|code| code as u32) {
            Some(ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY) if pipe_exists(&name) => {
                ServeError::PipeInUse { name: name.clone() }
            }
            Some(ERROR_INVALID_OWNER) => failed(format!(
                "this process may not make {} the pipe's owner",
                security.expected.owner
            )),
            _ => failed(e.to_string()),
        }
    })?;
    security.verify(&first).map_err(failed)?;
    drop(
        security
            .create(&name, false)
            .map_err(|e| failed(format!("a second instance: {e}")))?,
    );
    tracing::info!(
        pipe = %name.display(),
        %ceiling,
        owner = %security.expected.owner,
        aces = ?security.expected.aces,
        "control pipe listening"
    );
    let listener = PipeListener {
        name,
        security,
        listening: first,
    };
    serve_bounded(listener, router, ceiling, stop).await
}

fn is_pipe_name(name: &Path) -> bool {
    name.to_str()
        .and_then(|name| name.split_at_checked(PIPE_PREFIX.len()))
        .filter(|(prefix, _)| prefix.eq_ignore_ascii_case(PIPE_PREFIX))
        .is_some_and(|(_, rest)| {
            rest.split('\\')
                .all(|part| !part.is_empty() && !part.chars().all(|c| c == '.'))
        })
}

/// Whether another process holds `name`: an instance being busy is not its
/// absence.
fn pipe_exists(name: &Path) -> bool {
    // SAFETY: the name is NUL-terminated.
    let free = unsafe { WaitNamedPipeW(wide(name).as_ptr(), 1) } != 0;
    free || io::Error::last_os_error().raw_os_error() != Some(ERROR_FILE_NOT_FOUND as i32)
}

/// Never without an instance of our own: a name with none left is one another
/// process may create.
struct PipeListener {
    name: PathBuf,
    security: Security,
    listening: NamedPipeServer,
}

impl PipeListener {
    /// Retried while the instance it replaces is still held, so it only ever
    /// joins a pipe of ours.
    async fn successor(&mut self) -> NamedPipeServer {
        let mut delay = RETRY;
        loop {
            match self.security.create(&self.name, false) {
                Ok(pipe) => return pipe,
                Err(e) => {
                    let pipe = self.name.display();
                    tracing::error!(%pipe, error = %e, retry = ?delay, "could not create a pipe instance");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(RETRY_CAP);
                }
            }
        }
    }
}

impl Listener for PipeListener {
    type Io = NamedPipeServer;
    type Addr = Option<Sid>;

    async fn accept(&mut self) -> (NamedPipeServer, Option<Sid>) {
        loop {
            let connected = self.listening.connect().await;
            let successor = self.successor().await;
            let pipe = std::mem::replace(&mut self.listening, successor);
            let name = self.name.display();
            match connected {
                Ok(()) => {
                    let peer = wslib_host::pipe_client_user(&pipe)
                        .inspect_err(|e| tracing::debug!(pipe = %name, error = %e, "a control pipe client's account is unread"))
                        .ok();
                    return (pipe, peer);
                }
                Err(e) => {
                    tracing::debug!(pipe = %name, error = %e, "a control pipe client left before it was accepted");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Option<Sid>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a pipe has no address",
        ))
    }
}

pub(super) struct Security {
    expected: Readback,
    descriptor: Vec<u64>,
}

impl Security {
    fn new(group: Option<&str>, service: Option<&str>) -> Result<Self, String> {
        let owner = match service {
            Some(service) => {
                let account = format!(r"NT SERVICE\{service}");
                wslib_host::service_account(service)
                    .map_err(|e| format!("no service account {account}: {e}"))?
                    .ok_or_else(|| format!("no service account {account}: it is not one installed service's account"))?
            }
            None => wslib_host::current_user()
                .map_err(|e| format!("reading this process's user: {e}"))?,
        };
        let group = group.map(local_group).transpose()?;
        Self::granting(&owner, group.as_ref()).map_err(|e| e.to_string())
    }

    /// SYSTEM and `owner` full control, and `group` [`CLIENT_ACCESS`].
    pub(super) fn granting(owner: &Sid, group: Option<&Sid>) -> io::Result<Self> {
        let owner = owner.to_string();
        let mut aces = vec![(ALLOWED, FILE_ALL_ACCESS, LOCAL_SYSTEM.to_string())];
        if owner != LOCAL_SYSTEM {
            aces.push((ALLOWED, FILE_ALL_ACCESS, owner.clone()));
        }
        aces.extend(group.map(|group| (ALLOWED, CLIENT_ACCESS, group.to_string())));
        Self::protected(owner, aces)
    }

    fn protected(owner: String, aces: Vec<Ace>) -> io::Result<Self> {
        let dacl: String = aces
            .iter()
            .map(|(_, mask, sid)| format!("(A;;{mask:#x};;;{sid})"))
            .collect();
        Ok(Self {
            descriptor: self_relative(&format!("O:{owner}D:P{dacl}"))?,
            expected: Readback {
                owner,
                protected: true,
                aces,
            },
        })
    }

    fn create(&mut self, name: &Path, first: bool) -> io::Result<NamedPipeServer> {
        create(&mut self.descriptor, name, first)
    }

    /// Refuses an instance whose pipe carries another descriptor, as one that
    /// joined a pipe another process created would.
    fn verify(&self, pipe: &NamedPipeServer) -> Result<(), String> {
        let found = read_security(pipe.as_raw_handle())
            .map_err(|e| format!("reading its security: {e}"))?;
        if found != self.expected {
            tracing::error!(expected = ?self.expected, ?found, "a control pipe's security differs");
            return Err("its security does not read back as it was created".to_string());
        }
        Ok(())
    }
}

fn create(descriptor: &mut [u64], name: &Path, first: bool) -> io::Result<NamedPipeServer> {
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_mut_ptr().cast(),
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` points at a valid descriptor, and both outlive the
    // call, which keeps neither.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, (&raw mut attributes).cast())
    }
}

fn self_relative(sddl: &str) -> io::Result<Vec<u64>> {
    let sddl = wide(sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut len = 0u32;
    // SAFETY: `sddl` is NUL-terminated; on success `descriptor` is a
    // `LocalAlloc`ed block of `len` bytes, copied out and freed below.
    unsafe {
        succeeded(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut len,
        ))?;
        let mut copy = vec![0u64; (len as usize).div_ceil(8)];
        std::ptr::copy_nonoverlapping(
            descriptor.cast::<u8>(),
            copy.as_mut_ptr().cast::<u8>(),
            len as usize,
        );
        LocalFree(descriptor);
        Ok(copy)
    }
}

/// A pipe's owner, whether its DACL is protected, and its ACEs.
#[derive(Debug, PartialEq)]
pub(super) struct Readback {
    pub(super) owner: String,
    pub(super) protected: bool,
    pub(super) aces: Vec<Ace>,
}

pub(super) fn read_security(handle: HANDLE) -> io::Result<Readback> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the handle is live for the call; on success `descriptor` owns the
    // memory `owner` and `dacl` point into, and is freed once they are read.
    unsafe {
        let status = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let read = (|| {
            let (mut control, mut revision) = (0u16, 0u32);
            succeeded(GetSecurityDescriptorControl(
                descriptor,
                &mut control,
                &mut revision,
            ))?;
            let mut size = ACL_SIZE_INFORMATION::default();
            if !dacl.is_null() {
                succeeded(GetAclInformation(
                    dacl,
                    (&raw mut size).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ))?;
            }
            let aces = (0..size.AceCount)
                .map(|index| {
                    let mut ace: *mut std::ffi::c_void = null_mut();
                    succeeded(GetAce(dacl, index, &mut ace))?;
                    let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                    if allowed.Header.AceType != ALLOWED {
                        return Ok((allowed.Header.AceType, 0, String::new()));
                    }
                    let sid = ace.byte_add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart));
                    Ok((ALLOWED, allowed.Mask, Sid::from_psid(sid)?.to_string()))
                })
                .collect::<io::Result<_>>()?;
            Ok(Readback {
                owner: Sid::from_psid(owner)?.to_string(),
                protected: control & SE_DACL_PROTECTED != 0,
                aces,
            })
        })();
        LocalFree(descriptor);
        read
    }
}

pub(super) fn rendered(sid: Sid, account: Option<String>) -> String {
    match account {
        Some(name) => format!("{LOCAL_ACTOR}:{name}"),
        None => format!("{LOCAL_ACTOR}:sid={sid}"),
    }
}

/// Blocking: a domain account's name comes from a domain controller. The
/// [actor's form](named_actor), or `None` when the lookup fails or the name has
/// no such form.
pub(super) fn account_name(sid: Sid) -> Option<String> {
    let account = sid.account().ok()?;
    named_actor(&sid.to_string(), &account.domain, &account.name)
}

/// An alias one RID under this computer's account domain, as a product's
/// installer creates: never a well-known or BUILTIN group, and a domain's only
/// on that domain's controller, whose account domain it is.
fn local_group(name: &str) -> Result<Sid, String> {
    let (sid, kind) = lookup_account(name).map_err(|e| format!("no local group {name}: {e}"))?;
    let domain = account_domain().map_err(|e| format!("reading the account domain: {e}"))?;
    if kind == SidTypeAlias && one_rid_under(&domain.to_string(), &sid.to_string()) {
        Ok(sid)
    } else {
        Err(format!("{name} is not a local group of this computer"))
    }
}

fn account_domain() -> io::Result<Sid> {
    let lsa = |status| match status {
        STATUS_SUCCESS => Ok(()),
        // SAFETY: no pointers.
        _ => Err(io::Error::from_raw_os_error(
            unsafe { LsaNtStatusToWinError(status) } as i32,
        )),
    };
    let attributes = LSA_OBJECT_ATTRIBUTES::default();
    let mut policy = 0;
    // SAFETY: the attributes are zeroed, as the call wants; a policy opened is
    // closed once queried, and the information freed once copied.
    unsafe {
        lsa(LsaOpenPolicy(
            null(),
            &attributes,
            POLICY_VIEW_LOCAL_INFORMATION as u32,
            &mut policy,
        ))?;
        let mut info = null_mut();
        let queried = lsa(LsaQueryInformationPolicy(
            policy,
            PolicyAccountDomainInformation,
            &mut info,
        ));
        LsaClose(policy);
        queried?;
        let sid = (*info.cast::<POLICY_ACCOUNT_DOMAIN_INFO>()).DomainSid;
        let copied = if sid.is_null() {
            Err(io::Error::other("no account domain SID"))
        } else {
            Sid::from_psid(sid)
        };
        LsaFreeMemory(info);
        copied
    }
}

/// The account's SID and its kind.
fn lookup_account(name: &str) -> io::Result<(Sid, SID_NAME_USE)> {
    let name = wide(name);
    let (mut sid_len, mut domain_len, mut kind) = (0u32, 0u32, 0);
    // SAFETY: a sizing call, with no buffers.
    unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            null_mut(),
            &mut sid_len,
            null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    let mut sid = vec![0u32; (sid_len as usize).div_ceil(4)];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: each buffer is at least as long as its length says; on success
    // `sid` holds a valid SID.
    unsafe {
        succeeded(LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        ))?;
        Ok((Sid::from_psid(sid.as_mut_ptr().cast())?, kind))
    }
}

fn succeeded(result: i32) -> io::Result<()> {
    match result {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub(super) fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain([0]).collect()
}

/// A client asking for `access`, as a member of an endpoint's group must.
#[cfg(test)]
pub(super) fn open_client(
    name: &Path,
    access: u32,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };

    let name = wide(name);
    // SAFETY: `name` is NUL-terminated, and a valid handle is handed to the
    // client, which owns it.
    unsafe {
        let handle = CreateFileW(
            name.as_ptr(),
            access,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKUP_OPERATORS: &str = "S-1-5-32-551";

    fn pipe_name(test: &str) -> PathBuf {
        PathBuf::from(format!(
            r"\\.\pipe\appliance-core-{test}-{}",
            std::process::id()
        ))
    }

    /// These tests run as an ordinary user: SYSTEM's own ACE grants it everything.
    fn user() -> String {
        let user = wslib_host::current_user()
            .expect("this process's user")
            .to_string();
        assert_ne!(user, LOCAL_SYSTEM, "run these tests as an ordinary user");
        user
    }

    fn denied(e: &io::Error) -> bool {
        e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32)
    }

    #[test]
    fn only_a_pipe_name_is_served() {
        for name in [r"\\.\pipe\hello-admin", r"\\.\PIPE\a\b", r"\\.\pipe\a.b"] {
            assert!(is_pipe_name(Path::new(name)), "{name}");
        }
        for name in [
            r"C:\hello.sock",
            r"\\.\pipe\",
            r"\\.\pipe\a\\b",
            r"\\.\pipe\..",
            r"\\.\pipe\a\.",
            r"\\server\pipe\a",
        ] {
            assert!(!is_pipe_name(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn a_peer_with_no_name_is_audited_by_its_sid() {
        let user = wslib_host::current_user().expect("this process's user");
        let expected = format!("control-socket:sid={user}");
        assert_eq!(rendered(user, None), expected);
    }

    /// An account, and groups well-known or BUILTIN: Everyone, Authenticated
    /// Users and Users, named as this computer's language names them.
    #[test]
    fn only_a_local_group_of_this_computer_is_granted() {
        let user = user();
        for sid in [user.as_str(), "S-1-1-0", "S-1-5-11", "S-1-5-32-545"] {
            let account = sid.parse::<Sid>().expect(sid).account().expect("named");
            let named = if account.domain.is_empty() {
                account.name
            } else {
                format!(r"{}\{}", account.domain, account.name)
            };
            let refused = Security::new(Some(&named), None).err().expect("refused");
            assert!(
                refused.ends_with("is not a local group of this computer"),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_local_account_is_one_rid_under_the_account_domain() {
        let domain = account_domain().expect("the account domain").to_string();
        let user = wslib_host::current_user()
            .expect("this process's user")
            .to_string();
        assert!(
            one_rid_under(&domain, &user),
            "{user} is not a local account under {domain}: run the Windows tests as a local account"
        );
    }

    #[tokio::test]
    async fn the_groups_access_opens_the_pipe_and_creates_no_instance_of_it() {
        let name = pipe_name("access");
        let aces = vec![
            (ALLOWED, FILE_ALL_ACCESS, LOCAL_SYSTEM.to_string()),
            (ALLOWED, CLIENT_ACCESS, user()),
        ];
        let mut security = Security::protected(user(), aces).expect("the descriptor");
        let _first = security.create(&name, true).expect("creates");

        let instance = security
            .create(&name, false)
            .expect_err("a second instance");
        assert!(denied(&instance), "{instance}");
        open_client(&name, CLIENT_ACCESS).expect("the group's access opens it");
    }

    /// The owner's implicit rights alone do not open the pipe.
    #[tokio::test]
    async fn an_owner_outside_the_group_is_refused() {
        let name = pipe_name("outsider");
        let aces = vec![
            (ALLOWED, FILE_ALL_ACCESS, LOCAL_SYSTEM.to_string()),
            (ALLOWED, CLIENT_ACCESS, BACKUP_OPERATORS.to_string()),
        ];
        let mut security = Security::protected(user(), aces).expect("the descriptor");
        let _first = security.create(&name, true).expect("creates");

        let refused = open_client(&name, CLIENT_ACCESS).expect_err("not a member");
        assert!(denied(&refused), "{refused}");
    }

    #[tokio::test]
    async fn an_instance_that_joins_another_processs_pipe_is_refused() {
        let name = pipe_name("joined");
        let mut permissive =
            self_relative(&format!("O:{}D:(A;;FA;;;WD)", user())).expect("the descriptor");
        let _squatter = create(&mut permissive, &name, true).expect("squats");

        let mut ours = Security::new(None, None).expect("ours");
        let joined = ours
            .create(&name, false)
            .expect("joins the squatter's pipe");
        ours.verify(&joined).expect_err("the squatter's descriptor");
    }
}
