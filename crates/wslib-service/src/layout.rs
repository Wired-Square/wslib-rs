use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// Where a service keeps its state and its log. A resolved answer, so the
/// fields are public and a product overrides any of them after the platform's
/// defaults. Every constructor builds on every platform.
///
/// Nothing here makes or checks a directory: the installer lays them out, and
/// the service checks `state_dir` with [`private_directory`](crate::private_directory)
/// and opens `log_file` with [`LogFile::open`](crate::LogFile::open).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub state_dir: PathBuf,
    pub log_dir: PathBuf,
    /// `None` where the service manager keeps the service's output.
    pub log_file: Option<PathBuf>,
}

impl Layout {
    /// A launchd daemon's: `/Library/Application Support/<product>/state`, and
    /// the log at `/Library/Logs/<product>/<name>.log`.
    pub fn macos(product: &str, name: &str) -> Self {
        let log_dir = Path::new("/Library/Logs").join(product);
        Self {
            state_dir: Path::new("/Library/Application Support")
                .join(product)
                .join("state"),
            log_file: Some(log_dir.join(format!("{name}.log"))),
            log_dir,
        }
    }

    /// A Windows service's: `%ProgramData%\<product>\state`, and the log at
    /// `%ProgramData%\<product>\logs\<name>.log`, with `%ProgramData%` taken as
    /// `C:\ProgramData` when it is unset or empty.
    pub fn windows(product: &str, name: &str) -> Self {
        Self::windows_under(std::env::var_os("ProgramData"), product, name)
    }

    fn windows_under(program_data: Option<OsString>, product: &str, name: &str) -> Self {
        let data = program_data
            .filter(|data| !data.is_empty())
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
            .join(product);
        let log_dir = data.join("logs");
        Self {
            state_dir: data.join("state"),
            log_file: Some(log_dir.join(format!("{name}.log"))),
            log_dir,
        }
    }

    /// A systemd unit's: `$STATE_DIRECTORY` and `$LOGS_DIRECTORY`, the first
    /// of each when it lists several, as `StateDirectory=` and
    /// `LogsDirectory=` set them, or else `/var/lib/<name>` and
    /// `/var/log/<name>`. No log file: journald keeps the output.
    pub fn systemd(name: &str) -> Self {
        Self::systemd_from(
            std::env::var_os("STATE_DIRECTORY").as_deref(),
            std::env::var_os("LOGS_DIRECTORY").as_deref(),
            name,
        )
    }

    fn systemd_from(state: Option<&OsStr>, logs: Option<&OsStr>, name: &str) -> Self {
        let first_or = |listed: Option<&OsStr>, fallback: &str| {
            let first = listed.and_then(|listed| {
                let bytes = listed.as_encoded_bytes();
                bytes.split(|&byte| byte == b':').next()
            });
            match first {
                // SAFETY: split at an ASCII byte, as `from_encoded_bytes_unchecked` allows.
                Some(first) if !first.is_empty() => {
                    PathBuf::from(unsafe { OsStr::from_encoded_bytes_unchecked(first) })
                }
                _ => Path::new(fallback).join(name),
            }
        };
        Self {
            state_dir: first_or(state, "/var/lib"),
            log_dir: first_or(logs, "/var/log"),
            log_file: None,
        }
    }

    /// [`windows`](Self::windows) on Windows, [`macos`](Self::macos) on macOS,
    /// and [`systemd`](Self::systemd) elsewhere.
    pub fn for_this_os(product: &str, name: &str) -> Self {
        if cfg!(windows) {
            Self::windows(product, name)
        } else if cfg!(target_os = "macos") {
            Self::macos(product, name)
        } else {
            Self::systemd(name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(text: &str) -> Option<&OsStr> {
        Some(OsStr::new(text))
    }

    #[test]
    fn the_macos_layout_is_under_application_support_and_library_logs() {
        assert_eq!(
            Layout::macos("Widget Monitor", "widgets"),
            Layout {
                state_dir: "/Library/Application Support/Widget Monitor/state".into(),
                log_dir: "/Library/Logs/Widget Monitor".into(),
                log_file: Some("/Library/Logs/Widget Monitor/widgets.log".into()),
            }
        );
    }

    #[test]
    fn the_windows_layout_is_under_program_data() {
        let data = Path::new(r"D:\Data").join("Widget Monitor");
        assert_eq!(
            Layout::windows_under(Some(r"D:\Data".into()), "Widget Monitor", "widgets"),
            Layout {
                state_dir: data.join("state"),
                log_dir: data.join("logs"),
                log_file: Some(data.join("logs").join("widgets.log")),
            }
        );
    }

    #[test]
    fn an_unset_or_empty_program_data_is_c_program_data() {
        for unset in [None, Some(OsString::new())] {
            assert_eq!(
                Layout::windows_under(unset, "Widget Monitor", "widgets").state_dir,
                Path::new(r"C:\ProgramData")
                    .join("Widget Monitor")
                    .join("state")
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_program_data_with_a_trailing_backslash_takes_one_separator() {
        for data in [r"D:\Data", r"D:\Data\"] {
            let layout = Layout::windows_under(Some(data.into()), "Widget Monitor", "widgets");
            assert_eq!(
                layout.log_file.unwrap().as_os_str(),
                r"D:\Data\Widget Monitor\logs\widgets.log"
            );
        }
    }

    #[test]
    fn the_systemd_layout_takes_the_first_directory_systemd_names() {
        assert_eq!(
            Layout::systemd_from(
                os("/var/lib/widgets:/var/lib/widgets-cache"),
                os("/var/log/widgets"),
                "widgets"
            ),
            Layout {
                state_dir: "/var/lib/widgets".into(),
                log_dir: "/var/log/widgets".into(),
                log_file: None,
            }
        );
    }

    #[test]
    fn the_systemd_layout_falls_back_to_var_lib_and_var_log() {
        for (state, logs) in [(None, None), (os(""), os(""))] {
            let layout = Layout::systemd_from(state, logs, "widgets");
            assert_eq!(layout.state_dir, Path::new("/var/lib/widgets"));
            assert_eq!(layout.log_dir, Path::new("/var/log/widgets"));
        }
    }
}
