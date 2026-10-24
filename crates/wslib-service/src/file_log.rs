//! The service's log in a file of its own, since neither launchd nor the
//! service control manager keeps a daemon's output.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::Refused;

/// The service's log, appended to a file of its own, for a subscriber to
/// write through: `Arc<LogFile>` is a `tracing-subscriber` `MakeWriter`.
///
/// A file this creates is `0640`, whatever the umask, or on Windows its
/// owner's and SYSTEM's, with Administrators allowed to read and delete it; one
/// that exists keeps its mode or DACL, and must be a regular file, not a link
/// or a FIFO. On Windows it is held sharing read and delete but not write, so a
/// reader must share write to open it.
///
/// On Windows the file must be owned by this process's user, SYSTEM or
/// Administrators, in a directory with the same owners that nobody else may
/// add to, delete from, rename or change the security of. The directory is
/// held open while the `LogFile` lives, so it cannot be renamed; under a global
/// subscriber, that is the life of the process.
///
/// Rotate it with a newsyslog entry carrying the `N` flag, no pid file, and an
/// `owner:group` with mode `640`, so the file it makes keeps the group: the
/// first write a [check](LogFileBuilder::check_every) or more after a rotation
/// reopens the path. newsyslog splits its lines on whitespace, so a path with a
/// space takes the `G` flag and a `?` for each space.
///
/// On Windows it rotates itself instead: at 10 MiB or more, checked at open and
/// at most once a second at a write, it is renamed over the path with `.1`
/// appended and a new file is opened at the path. A reader holding the log
/// without sharing delete puts the rotation off, as, on Windows without POSIX
/// rename, does any reader of `.1`; no line is lost.
///
/// On Windows too, a file deleted or renamed away is replaced at the next check;
/// while another handle keeps a deleted file's name, lines are dropped.
///
/// ```no_run
/// # fn main() -> Result<(), wslib_service::Refused> {
/// let log = std::sync::Arc::new(wslib_service::LogFile::open("/Library/Logs/Widgets/widgets.log")?);
/// wslib_telemetry::Telemetry::new("info").writer(log).init();
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct LogFile {
    path: PathBuf,
    every: Duration,
    rotate_at: Option<u64>,
    current: Mutex<Current>,
    #[cfg(windows)]
    _folder: File,
}

/// How often a [`LogFile`] checks its path, and the size it rotates itself at.
#[derive(Clone, Debug)]
#[must_use = "nothing is opened until `open`"]
pub struct LogFileBuilder {
    every: Duration,
    rotate_at: Option<u64>,
}

#[derive(Debug)]
struct Current {
    /// `None` once a held file left delete-pending is let go of and no new one
    /// opens: lines are dropped until one does.
    file: Option<File>,
    checked: Instant,
}

impl LogFile {
    /// Opens `path` with the defaults: a check each second, and rotation at
    /// 10 MiB on Windows only.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Refused> {
        Self::builder().open(path)
    }

    pub fn builder() -> LogFileBuilder {
        LogFileBuilder {
            every: Duration::from_secs(1),
            rotate_at: cfg!(windows).then_some(10 << 20),
        }
    }

    fn current(&self) -> MutexGuard<'_, Current> {
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        if current.checked.elapsed() >= self.every {
            current.check(&self.path, self.rotate_at);
        }
        current
    }
}

impl LogFileBuilder {
    /// How often a write looks for the file having been rotated away, or
    /// having reached [`rotate_at`](Self::rotate_at).
    pub fn check_every(mut self, every: Duration) -> Self {
        self.every = every;
        self
    }

    /// The size at which the file renames itself over `.1`; `None` leaves
    /// rotation to something else, such as newsyslog.
    pub fn rotate_at(mut self, bytes: Option<u64>) -> Self {
        self.rotate_at = bytes;
        self
    }

    pub fn open(self, path: impl AsRef<Path>) -> Result<LogFile, Refused> {
        let path = path.as_ref();
        #[cfg(windows)]
        let folder =
            crate::windows::parent_directory(path, &crate::windows::NO_ADDING_OR_REPLACING)?;
        let mut current = Current {
            file: Some(open(path).map_err(|e| Refused::new(path, e.to_string()))?),
            checked: Instant::now(),
        };
        current.check(path, self.rotate_at);
        Ok(LogFile {
            path: path.to_path_buf(),
            every: self.every,
            rotate_at: self.rotate_at,
            current: Mutex::new(current),
            #[cfg(windows)]
            _folder: folder,
        })
    }
}

impl Current {
    /// Renames the held file over `path`'s `.1` once it reaches `rotate_at`, then
    /// holds the file at `path` if that is another. A file that cannot be renamed
    /// or opened keeps the old one: a lost rotation beats a lost log. A held file
    /// left delete-pending, whose lines die with it and which blocks `path` until
    /// every handle closes, is let go of, and lines are dropped until `path` opens.
    fn check(&mut self, path: &Path, rotate_at: Option<u64>) {
        self.checked = Instant::now();
        let Some(held) = &self.file else {
            self.file = open(path).ok();
            return;
        };
        let mut at_path = same_file(held, path);
        if at_path && rotate_at.is_some_and(|at| held.metadata().is_ok_and(|m| m.len() >= at)) {
            let mut old = path.as_os_str().to_owned();
            old.push(".1");
            at_path = std::fs::rename(path, old).is_err();
        }
        if at_path {
            return;
        }
        match open(path) {
            Ok(file) => self.file = Some(file),
            Err(_) if delete_pending(held) => {
                drop(self.file.take());
                self.file = open(path).ok();
            }
            Err(_) => {}
        }
    }
}

impl Write for &LogFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match &mut self.current().file {
            Some(file) => file.write(bytes),
            None => Ok(bytes.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.current().file.as_mut().map_or(Ok(()), Write::flush)
    }
}

#[cfg(unix)]
fn same_file(file: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let identity = |metadata: std::fs::Metadata| (metadata.dev(), metadata.ino());
    match (file.metadata(), std::fs::symlink_metadata(path)) {
        (Ok(held), Ok(named)) => identity(held) == identity(named),
        _ => false,
    }
}

#[cfg(unix)]
fn delete_pending(_: &File) -> bool {
    false
}

#[cfg(windows)]
fn delete_pending(file: &File) -> bool {
    /// `FILE_STANDARD_INFO` with its `BOOLEAN`s as bytes, which windows-sys reads
    /// as `bool`s: a filter driver may write any byte.
    #[repr(C)]
    #[derive(Default)]
    struct StandardInfo {
        _allocation_size: i64,
        _end_of_file: i64,
        _links: u32,
        delete_pending: u8,
        _directory: u8,
    }
    // SAFETY: `StandardInfo` has the layout of the structure the class names.
    unsafe {
        file_info::<StandardInfo>(
            file,
            windows_sys::Win32::Storage::FileSystem::FileStandardInfo,
        )
    }
    .is_some_and(|info| info.delete_pending != 0)
}

/// # Safety
///
/// `T` must be the structure `class` names.
#[cfg(windows)]
unsafe fn file_info<T: Default>(
    file: &File,
    class: windows_sys::Win32::Storage::FileSystem::FILE_INFO_BY_HANDLE_CLASS,
) -> Option<T> {
    use std::os::windows::io::AsRawHandle;
    let mut info = T::default();
    // SAFETY: the handle is open while `file` is borrowed, and `info` is the
    // structure `class` names.
    let read = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&raw mut info).cast(),
            size_of::<T>() as u32,
        )
    };
    (read != 0).then_some(info)
}

#[cfg(windows)]
fn same_file(file: &File, path: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_READ_ATTRIBUTES, FileIdInfo,
    };
    let identity = |file: &File| {
        // SAFETY: the class names that structure.
        unsafe { file_info::<FILE_ID_INFO>(file, FileIdInfo) }
            .map(|info| (info.VolumeSerialNumber, info.FileId.Identifier))
    };
    let named = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path);
    match (identity(file), named.ok().as_ref().and_then(identity)) {
        (Some(held), Some(named)) => held == named,
        _ => false,
    }
}

#[cfg(unix)]
fn open(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    match OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o640)
        .open(path)
    {
        Ok(file) => {
            file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
            Ok(file)
        }
        // Non-blocking to open, so a FIFO with no reader fails with ENXIO
        // rather than holding the writer's lock; blocking again once it is
        // known to be a regular file.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            use std::os::fd::AsRawFd;
            let file = OpenOptions::new()
                .append(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::other("it is not a regular file"));
            }
            let fd = file.as_raw_fd();
            // SAFETY: `fd` is `file`'s, open for the duration of both calls.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(file)
        }
        Err(e) => Err(e),
    }
}

/// Created unshared, so nothing can open it before its DACL is set; then held
/// sharing read and delete but not write, since the rotation renames it by path.
#[cfg(windows)]
fn open(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ,
    };
    match OpenOptions::new()
        .append(true)
        .create_new(true)
        .share_mode(0)
        .open(path)
    {
        Ok(created) => {
            let restricted = wslib_file_atomic::administrators_read_and_delete(path);
            drop(created);
            if let Err(e) = restricted {
                std::fs::remove_file(path).ok();
                return Err(e);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let file = OpenOptions::new()
        .append(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other("it is not a regular file"));
    }
    crate::windows::owned_by_the_trusted(&file).map_err(std::io::Error::other)?;
    Ok(file)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::test_dir::TempDir;
    use std::os::unix::fs::PermissionsExt;

    fn log_dir() -> TempDir {
        TempDir::new("log")
    }

    #[test]
    fn a_file_that_exists_is_appended_to_and_keeps_its_mode() {
        let dir = log_dir();
        let path = dir.join("service.log");
        std::fs::write(&path, "earlier\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        writeln!(open(&path).unwrap(), "later").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "earlier\nlater\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_link_or_anything_but_a_regular_file_is_refused() {
        let dir = log_dir();
        let target = dir.join("elsewhere");
        std::fs::write(&target, "theirs\n").unwrap();
        let link = dir.join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open(&link).is_err(), "a link is not followed");
        assert!(open(dir.path()).is_err(), "a directory is refused");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "theirs\n");

        let fifo = dir.join("fifo.log");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `name` is a live NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (answer, answered) = std::sync::mpsc::channel();
        std::thread::spawn(move || answer.send(open(&fifo).is_err()).ok());
        assert!(
            answered
                .recv_timeout(Duration::from_secs(5))
                .expect("a FIFO with no reader does not block the open"),
            "a FIFO is refused"
        );
    }

    #[test]
    fn a_write_after_rotation_lands_in_a_new_file_at_the_path() {
        let dir = log_dir();
        let path = dir.join("service.log");
        let rotated = dir.join("service.log.0");
        let log = LogFile::builder()
            .check_every(Duration::ZERO)
            .rotate_at(None)
            .open(&path)
            .unwrap();

        writeln!(&log, "before").unwrap();
        std::fs::rename(&path, &rotated).unwrap();
        writeln!(&log, "after").unwrap();

        assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "before\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use crate::test_dir::TempDir;
    use crate::windows::icacls;

    #[test]
    fn a_new_file_administrators_may_read_and_delete_and_one_that_exists_keeps_its_dacl() {
        let dir = TempDir::new("log");
        let path = dir.join("service.log");
        writeln!(open(&path).unwrap(), "earlier").unwrap();
        wslib_file_atomic::testing::assert_administrators_read_and_delete(&path);

        wslib_file_atomic::owner_only(&path).unwrap();
        writeln!(open(&path).unwrap(), "later").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "earlier\nlater\n");
        wslib_file_atomic::testing::assert_owner_only(&path);
    }

    #[test]
    fn a_reader_sharing_write_may_open_it_while_it_is_held_and_a_writer_may_not() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let dir = TempDir::new("log");
        let path = dir.join("service.log");
        let mut held = open(&path).unwrap();
        writeln!(held, "written").unwrap();

        let reader = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path);
        assert_eq!(
            std::io::read_to_string(reader.unwrap()).unwrap(),
            "written\n"
        );
        let writer = OpenOptions::new().append(true).open(&path);
        assert_eq!(
            writer.unwrap_err().raw_os_error(),
            Some(32),
            "a sharing violation"
        );
    }

    #[test]
    fn a_directory_is_refused() {
        let dir = TempDir::new("log");
        assert!(open(dir.path()).is_err());
    }

    #[test]
    fn a_folder_users_may_add_to_is_refused_naming_it_and_one_they_may_read_is_not() {
        let dir = TempDir::new("log");
        let logs = dir.join("logs");
        std::fs::create_dir(&logs).unwrap();
        let path = logs.join("service.log");
        icacls(&logs, &["/grant", "*S-1-5-32-545:(RX)"]);
        LogFile::builder()
            .rotate_at(None)
            .open(&path)
            .expect("others may read it");

        icacls(&logs, &["/grant", "*S-1-5-32-545:(WD)"]);
        let said = LogFile::builder()
            .rotate_at(None)
            .open(&path)
            .expect_err("refused")
            .to_string();
        assert!(
            said.starts_with(&format!("refusing {}: ", logs.display())) && said.contains(";;;BU)"),
            "{said}"
        );
    }

    #[ignore = "needs an elevated shell, to give the file another owner"]
    #[test]
    fn a_file_another_owns_is_refused() {
        let dir = TempDir::new("log");
        let path = dir.join("service.log");
        std::fs::write(&path, "").unwrap();
        icacls(&path, &["/setowner", "*S-1-5-32-545"]);
        let said = open(&path).expect_err("refused").to_string();
        assert!(said.starts_with("it is owned by O:BU"), "{said}");
    }

    #[test]
    fn a_reader_that_does_not_share_delete_puts_the_rotation_off_and_loses_no_line() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let dir = TempDir::new("log");
        let path = dir.join("service.log");
        let old = dir.join("service.log.1");
        let log = LogFile::builder()
            .check_every(Duration::ZERO)
            .rotate_at(Some(10))
            .open(&path)
            .unwrap();
        writeln!(&log, "ten bytes").unwrap();

        let reader = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap();
        writeln!(&log, "held").unwrap();
        assert!(!old.exists());
        drop(reader);
        writeln!(&log, "rotated").unwrap();

        assert_eq!(std::fs::read_to_string(&old).unwrap(), "ten bytes\nheld\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "rotated\n");
    }

    #[test]
    fn with_posix_rename_a_reader_of_the_old_file_sharing_delete_does_not_put_the_rotation_off() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let dir = TempDir::new("log");
        let path = dir.join("service.log");
        let old = dir.join("service.log.1");
        std::fs::write(&old, "oldest\n").unwrap();
        let log = LogFile::builder()
            .check_every(Duration::ZERO)
            .rotate_at(Some(10))
            .open(&path)
            .unwrap();
        writeln!(&log, "ten bytes").unwrap();

        let reader = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&old)
            .unwrap();
        writeln!(&log, "rotated").unwrap();

        assert_eq!(std::fs::read_to_string(&old).unwrap(), "ten bytes\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "rotated\n");
        assert_eq!(std::io::read_to_string(reader).unwrap(), "oldest\n");
    }

    #[test]
    fn a_held_file_left_delete_pending_is_let_go_of_and_replaced() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_DISPOSITION_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FileDispositionInfo, SetFileInformationByHandle,
        };
        let dir = TempDir::new("log");
        let path = dir.join("service.log");
        let log = LogFile::builder()
            .check_every(Duration::ZERO)
            .rotate_at(None)
            .open(&path)
            .unwrap();
        writeln!(&log, "before").unwrap();

        let doomed = OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: the handle is open, and `disposition` is the structure the class
        // names; without POSIX semantics the name stays until the log lets go.
        let set = unsafe {
            SetFileInformationByHandle(
                doomed.as_raw_handle(),
                FileDispositionInfo,
                (&raw const disposition).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        assert_ne!(set, 0, "{}", std::io::Error::last_os_error());
        drop(doomed);
        let held = log.current.lock().unwrap();
        assert!(delete_pending(held.file.as_ref().unwrap()));
        drop(held);

        writeln!(&log, "after").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::test_dir::TempDir;

    #[test]
    fn a_file_at_the_size_rotates_over_the_one_old_file_at_open_and_at_a_write() {
        let dir = TempDir::new("log");
        let path = dir.join("service.log");
        let old = dir.join("service.log.1");
        std::fs::write(&old, "oldest\n").unwrap();
        std::fs::write(&path, "ten bytes\n").unwrap();

        let log = LogFile::builder()
            .check_every(Duration::ZERO)
            .rotate_at(Some(10))
            .open(&path)
            .unwrap();
        assert_eq!(std::fs::read_to_string(&old).unwrap(), "ten bytes\n");
        writeln!(&log, "nine").unwrap();
        writeln!(&log, "and more").unwrap();
        writeln!(&log, "rotated").unwrap();

        assert_eq!(std::fs::read_to_string(&old).unwrap(), "nine\nand more\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "rotated\n");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o640);
        }
    }
}
