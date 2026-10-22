#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use wslib_systemd_journal::{Error, Priority, Query, Since, Source};

const ENTRIES: &str = r#"{"__REALTIME_TIMESTAMP":"3000000","PRIORITY":"4","_SYSTEMD_UNIT":"widget.service","MESSAGE":"third"}
{"__REALTIME_TIMESTAMP":"2000000","PRIORITY":"6","MESSAGE":"second"}
{"__REALTIME_TIMESTAMP":"1000000","PRIORITY":"6","MESSAGE":"first"}"#;

/// Every script is written before any is run: a child forked while another
/// thread holds a script open for writing can't exec it.
fn fake(name: &str) -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("wslib-journal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in [
            ("entries", format!("cat <<'EOF'\n{ENTRIES}\nEOF")),
            ("args", r#"printf '%s\n' "$@" > "$0.seen""#.to_string()),
            (
                "flood",
                r#"exec yes '{"__REALTIME_TIMESTAMP":"1","MESSAGE":"again"}'"#.to_string(),
            ),
            ("slow", "exec sleep 5".to_string()),
            ("fails", "exit 1".to_string()),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    });
    dir.join(name)
}

#[tokio::test]
async fn entries_come_back_newest_first_and_whole() {
    let excerpt = Query::default()
        .with_program(fake("entries"))
        .read()
        .await
        .unwrap();
    assert!(!excerpt.truncated);
    let messages: Vec<_> = excerpt.entries.iter().map(|e| e.message.as_str()).collect();
    assert_eq!(messages, ["third", "second", "first"]);
    assert_eq!(excerpt.entries[0].priority, Priority::Warning);
}

#[tokio::test]
async fn more_entries_than_the_line_bound_is_reported_as_truncated() {
    let excerpt = Query::default()
        .with_program(fake("entries"))
        .with_lines(2)
        .read()
        .await
        .unwrap();
    assert!(excerpt.truncated);
    assert_eq!(excerpt.entries.len(), 2);
    assert_eq!(excerpt.entries[1].message, "second");
}

#[tokio::test]
async fn the_query_reaches_journalctl_as_separate_arguments() {
    let program = fake("args");
    Query::default()
        .with_program(&program)
        .with_source(Source::Units(vec![
            "a.service".into(),
            "b@*.service".into(),
        ]))
        .with_since(Since::Ago(Duration::from_secs(3600)))
        .read()
        .await
        .unwrap();
    let seen = std::fs::read_to_string(program.with_extension("seen")).unwrap();
    let seen: Vec<_> = seen.lines().collect();
    for wanted in [
        "--output=json",
        "--since=-3600s",
        "--unit=a.service",
        "--unit=b@*.service",
    ] {
        assert!(seen.contains(&wanted), "{wanted} missing from {seen:?}");
    }
}

#[tokio::test]
async fn output_past_its_bound_is_cut_and_journalctl_killed() {
    let excerpt = Query::default()
        .with_program(fake("flood"))
        .with_max_output(1000)
        .read()
        .await
        .unwrap();
    assert!(excerpt.truncated);
    assert!(!excerpt.entries.is_empty() && excerpt.entries.len() < 1000 / 40);
}

#[tokio::test]
async fn failures_are_kept_apart() {
    let read = |program: PathBuf| async move {
        Query::default()
            .with_program(program)
            .with_timeout(Duration::from_millis(200))
            .read()
            .await
            .unwrap_err()
    };
    assert!(matches!(read(fake("slow")).await, Error::Timeout));
    assert!(matches!(read(fake("fails")).await, Error::Exited(s) if s.code() == Some(1)));
    assert!(matches!(read(fake("missing")).await, Error::NotInstalled));
}
