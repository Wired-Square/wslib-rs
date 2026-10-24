//! The service under Windows's service control manager, which starts it in a
//! thread of its own and stops it by a control rather than a signal.

use std::ffi::OsString;
use std::fmt::Display;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use windows_service::service::{
    Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::{ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SUCCESS};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
    RegisterEventSourceW, ReportEventW,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    RRF_NOEXPAND, RRF_RT_ANY, RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW,
};
use windows_sys::Win32::System::Services::{
    QueryServiceConfig2W, SERVICE_CONFIG_PRESHUTDOWN_INFO, SERVICE_PRESHUTDOWN_INFO,
};

use crate::progress::{self, Progress, State, Status};
use crate::{Failure, Main, Manager, Stop};

const TICK: Duration = Duration::from_secs(1);
const WAIT_HINT: Duration = Duration::from_secs(5);
const STOP_MARGIN: Duration = Duration::from_secs(5);
/// `ReportEventW` refuses a string this long, in UTF-16 units.
const EVENT_STRING_LIMIT: usize = 31_839;
const EVENT_MESSAGE_FILE: &str =
    r"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll";

static MAIN: Mutex<Option<(String, Duration, Main)>> = Mutex::new(None);
static OUTCOME: Mutex<Option<Result<(), Failure>>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Runs `main` as the service `name`, returning how it ended once it has
/// stopped, or `main` itself when the process was not started by the service
/// control manager.
pub(crate) fn run(name: &str, grace: Duration, main: Main) -> Result<Result<(), Failure>, Main> {
    *lock(&MAIN) = Some((name.to_string(), grace, main));
    let dispatched = service_dispatcher::start(name, ffi_service_main);
    let main = lock(&MAIN).take();
    match (dispatched, main) {
        (Err(windows_service::Error::Winapi(e)), Some((_, _, main)))
            if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) =>
        {
            Err(main)
        }
        (Err(e), _) => Ok(Err(Failure::ServiceManager(io_error(e)))),
        (Ok(()), _) => Ok(lock(&OUTCOME).take().unwrap_or_else(|| {
            Err(Failure::ServiceManager(std::io::Error::other(
                "the service control manager never started the service",
            )))
        })),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn io_error(e: windows_service::Error) -> std::io::Error {
    match e {
        windows_service::Error::Winapi(e) => e,
        other => std::io::Error::other(other.to_string()),
    }
}

fn service_main(_: Vec<OsString>) {
    let Some((name, grace, main)) = lock(&MAIN).take() else {
        return;
    };
    let requested = CancellationToken::new();
    let handle = {
        let requested = requested.clone();
        service_control_handler::register(&name, move |control| match control {
            ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown => {
                requested.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
    };
    let handle = match handle {
        Ok(handle) => handle,
        Err(e) => {
            let e = io_error(e);
            record(
                &name,
                Level::Error,
                format_args!("could not register for service controls: {e}"),
            );
            *lock(&OUTCOME) = Some(Err(Failure::ServiceManager(e)));
            return;
        }
    };
    let progress = Arc::new(Progress::starting({
        let name = name.clone();
        move |status| {
            if let Err(e) = handle.set_service_status(reported(status)) {
                record(
                    &name,
                    Level::Warning,
                    format_args!("could not report the service as {status:?}: {e}"),
                );
            }
        }
    }));
    {
        let progress = progress.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(TICK);
                if !progress.tick() {
                    break;
                }
            }
        });
    }
    configure(&name, grace.saturating_add(STOP_MARGIN));
    if let Err(e) = register_event_source(&name) {
        record(
            &name,
            Level::Warning,
            format_args!("could not register the service's event source: {e}"),
        );
    }

    let ended = crate::drive(&name, &requested, main, || {
        Stop::new(
            Manager::WindowsService,
            progress::stop(progress.clone(), requested.clone()),
        )
    });
    let asked = ended.is_ok();
    *lock(&OUTCOME) = Some(ended);
    progress.stopped(asked);
}

#[repr(u16)]
pub(crate) enum Level {
    Warning = EVENTLOG_WARNING_TYPE,
    Error = EVENTLOG_ERROR_TYPE,
}

/// Through `tracing` once a subscriber is installed, and to the Application
/// event log before then. An error is one the service ends in, so it goes to
/// the event log as well.
pub(crate) fn record(service: &str, level: Level, message: impl Display) {
    let subscribed = crate::subscribed();
    if subscribed {
        match level {
            Level::Warning => tracing::warn!(%service, "{message}"),
            Level::Error => tracing::error!(%service, "{message}"),
        }
    }
    if !subscribed || matches!(level, Level::Error) {
        to_event_log(service, level as REPORT_EVENT_TYPE, &message.to_string());
    }
}

/// .NET Framework's message file maps every event ID to its first string, so
/// Event Viewer shows the message itself.
fn register_event_source(source: &str) -> std::io::Result<()> {
    let key_name = wide(&format!(
        r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{source}"
    ));
    // SAFETY: both names are NUL-terminated, and no data is read.
    let registered = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key_name.as_ptr(),
            wide("EventMessageFile").as_ptr(),
            RRF_RT_ANY | RRF_NOEXPAND,
            null_mut(),
            null_mut(),
            null_mut(),
        )
    } == ERROR_SUCCESS;
    if registered {
        return Ok(());
    }
    let message_file: Vec<u8> = wide(EVENT_MESSAGE_FILE)
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let types = u32::from(EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE).to_le_bytes();
    let done = |code| match code {
        ERROR_SUCCESS => Ok(()),
        _ => Err(std::io::Error::from_raw_os_error(code as i32)),
    };
    let mut key = null_mut();
    // SAFETY: the name is NUL-terminated, and a key opened is closed below.
    done(unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key_name.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            null(),
            &mut key,
            null_mut(),
        )
    })?;
    let set = |value: &str, kind, data: &[u8]| {
        // SAFETY: the key is open, the name NUL-terminated, and the length the
        // data's own.
        done(unsafe {
            RegSetValueExW(
                key,
                wide(value).as_ptr(),
                0,
                kind,
                data.as_ptr(),
                data.len() as u32,
            )
        })
    };
    let written = set("EventMessageFile", REG_EXPAND_SZ, &message_file)
        .and_then(|()| set("TypesSupported", REG_DWORD, &types));
    // SAFETY: the key is open, and not used again.
    unsafe { RegCloseKey(key) };
    written
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// Cut short at a character to fit, and dropped if the event log refuses it,
/// since there is nowhere left to say so.
fn to_event_log(source: &str, kind: REPORT_EVENT_TYPE, message: &str) {
    let fits = message
        .char_indices()
        .scan(0, |units, (at, c)| {
            *units += c.len_utf16();
            Some((at, *units))
        })
        .find(|&(_, units)| units >= EVENT_STRING_LIMIT)
        .map_or(message, |(at, _)| &message[..at]);
    let (source, message) = (wide(source), wide(fits));
    let strings = [message.as_ptr()];
    // SAFETY: both strings are NUL-terminated and outlive the calls, and the
    // handle is deregistered once, after its one use.
    unsafe {
        let log = RegisterEventSourceW(null(), source.as_ptr());
        if log.is_null() {
            return;
        }
        let _refused_is_dropped =
            ReportEventW(log, kind, 0, 0, null_mut(), 1, 0, strings.as_ptr(), null());
        DeregisterEventSource(log);
    }
}

fn reported(Status { state, checkpoint }: Status) -> ServiceStatus {
    let (current_state, controls_accepted) = match state {
        State::Starting => (ServiceState::StartPending, ServiceControlAccept::empty()),
        State::Running => (
            ServiceState::Running,
            ServiceControlAccept::STOP
                | ServiceControlAccept::PRESHUTDOWN
                | ServiceControlAccept::SHUTDOWN,
        ),
        State::Stopping => (ServiceState::StopPending, ServiceControlAccept::empty()),
        State::Stopped { .. } => (ServiceState::Stopped, ServiceControlAccept::empty()),
    };
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted,
        exit_code: match state {
            State::Stopped { failed: true } => ServiceExitCode::ServiceSpecific(1),
            _ => ServiceExitCode::NO_ERROR,
        },
        checkpoint,
        wait_hint: if checkpoint > 0 {
            WAIT_HINT
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

/// Each step is tried alone, with only the rights it needs.
fn configure(name: &str, wanted: Duration) {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        Ok(manager) => manager,
        Err(e) => {
            return record(
                name,
                Level::Warning,
                format_args!("could not read the service's configuration: {e}"),
            );
        }
    };
    let open = |access| manager.open_service(name, access);
    let has_actions = open(ServiceAccess::QUERY_CONFIG)
        .and_then(|service| service.get_failure_actions())
        .map(|failure| failure.actions.is_some_and(|actions| !actions.is_empty()));
    match has_actions {
        Ok(true) => {}
        Ok(false) => record(
            name,
            Level::Warning,
            format_args!(
                "the service {name} has no failure actions, so it will not be restarted after \
                 a failure until its installer sets them"
            ),
        ),
        Err(e) => record(
            name,
            Level::Warning,
            format_args!("could not read the service's failure actions: {e}"),
        ),
    }
    let raised = open(ServiceAccess::QUERY_CONFIG)
        .and_then(|service| preshutdown_timeout(&service))
        .and_then(|current| {
            if current >= wanted {
                return Ok(());
            }
            open(ServiceAccess::CHANGE_CONFIG)?.set_preshutdown_timeout(wanted)
        });
    if let Err(e) = raised {
        record(
            name,
            Level::Warning,
            format_args!("could not raise the service's preshutdown timeout to {wanted:?}: {e}"),
        );
    }
}

fn preshutdown_timeout(service: &Service) -> windows_service::Result<Duration> {
    let mut info = SERVICE_PRESHUTDOWN_INFO {
        dwPreshutdownTimeout: 0,
    };
    let mut needed = 0;
    // SAFETY: the handle is open while `service` is borrowed, and `info` is the
    // structure the level names, of the size passed.
    let read = unsafe {
        QueryServiceConfig2W(
            service.raw_handle(),
            SERVICE_CONFIG_PRESHUTDOWN_INFO,
            (&raw mut info).cast(),
            size_of::<SERVICE_PRESHUTDOWN_INFO>() as u32,
            &mut needed,
        )
    };
    match read {
        0 => Err(windows_service::Error::Winapi(
            std::io::Error::last_os_error(),
        )),
        _ => Ok(Duration::from_millis(info.dwPreshutdownTimeout.into())),
    }
}
