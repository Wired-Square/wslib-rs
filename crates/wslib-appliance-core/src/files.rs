//! File handling beyond writing (which is `wslib-file-atomic`'s): keep a
//! directory at its mode, and hand a file to a browser.

use std::path::Path;

use axum::body::Body;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

/// Put `dir` at `mode`, only when it is not: a no-op `chmod` still dirties the
/// inode, and a real one is logged because it undoes a mode somebody chose.
#[cfg(unix)]
pub fn keep_mode(dir: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let current = std::fs::metadata(dir)?.permissions().mode() & 0o777;
    if current != mode {
        tracing::info!(
            dir = %dir.display(),
            was = format!("{current:o}"),
            now = format!("{mode:o}"),
            "the directory's mode was not what the appliance keeps it at; making it so"
        );
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn keep_mode(_dir: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// A file as an uncached download saved under `filename`, which goes into the
/// header unescaped so must not contain `"`; an invalid header value falls back
/// to a fixed name.
pub fn attachment(content_type: &'static str, filename: &str, body: impl Into<Body>) -> Response {
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"download\""));
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body.into(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn keep_mode_sets_only_what_differs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mode = || std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        keep_mode(dir.path(), 0o700).expect("mode");
        assert_eq!(mode(), 0o700);
        keep_mode(dir.path(), 0o755).expect("mode");
        assert_eq!(mode(), 0o755);
    }

    #[test]
    fn a_download_names_its_file_and_asks_not_to_be_kept() {
        let response = attachment("application/json", "box-backup.json", "{}");
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"box-backup.json\""
        );
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
}
