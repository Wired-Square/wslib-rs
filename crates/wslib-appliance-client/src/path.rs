//! Which pipe paths are on this machine. A `\\server\pipe\…` path would open a
//! pipe on another machine and authenticate to it as the user.

use std::ffi::OsStr;

const LOCAL_PIPES: &str = r"\\.\pipe\";

/// Whether `path` names a pipe on this machine. A component that is empty or
/// all dots, or holds a NUL, is refused too: Win32 resolves dots in a `\\.\`
/// path, so `\\.\pipe\..\UNC\…` leaves the pipe namespace, and a NUL ends the
/// name early.
pub(crate) fn is_local_pipe(path: &OsStr) -> bool {
    let path = path.to_string_lossy();
    let Some(name) = path
        .get(..LOCAL_PIPES.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(LOCAL_PIPES))
        .map(|_| &path[LOCAL_PIPES.len()..])
    else {
        return false;
    };
    name.split(['\\', '/'])
        .all(|part| !part.is_empty() && !part.chars().all(|c| c == '.') && !part.contains('\0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(path: &str) -> bool {
        is_local_pipe(OsStr::new(path))
    }

    #[test]
    fn a_pipe_on_this_machine_is_local() {
        assert!(local(r"\\.\pipe\hello-admin"));
        assert!(local(r"\\.\PIPE\hello-admin"));
        assert!(local(r"\\.\pipe\hello\admin"));
        assert!(local(r"\\.\pipe\hello.admin"));
    }

    #[test]
    fn a_pipe_on_another_machine_is_not() {
        assert!(!local(r"\\server\pipe\hello-admin"));
        assert!(!local(r"\\?\UNC\server\pipe\hello-admin"));
        assert!(!local(r"\\.\UNC\server\pipe\hello-admin"));
    }

    #[test]
    fn a_path_that_climbs_out_of_the_pipe_namespace_is_not() {
        assert!(!local(r"\\.\pipe\..\UNC\server\pipe\hello-admin"));
        assert!(!local(r"\\.\pipe\./..\UNC\server\pipe\hello-admin"));
        assert!(!local(r"\\.\pipe\hello\..\..\C:\x"));
    }

    #[test]
    fn anything_else_is_not() {
        assert!(!local(r"\\.\pipe\"));
        assert!(!local(r"\\.\pipe\hello\\admin"));
        assert!(!local("\\\\.\\pipe\\hello\0admin"));
        assert!(!local("hello-admin"));
        assert!(!local(r"C:\hello-admin"));
        assert!(!local("//./pipe/hello-admin"));
    }
}
