//! Turning a checked `appliance.toml` into files, and comparing what is on
//! disk against what it should be.
//!
//! Templates are compiled in and take `{{placeholder}}` with no template
//! language: everything that varies is decided in Rust. A placeholder nobody
//! supplied is an error, never a literal.

use std::path::{Path, PathBuf};

/// One file the chassis owns, at a path relative to the directory rendered
/// into.
#[derive(Debug)]
pub struct Artefact {
    pub path: PathBuf,
    pub body: String,
}

/// Why a scaffold could not be rendered or written.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error(
        "{template}: nothing was supplied for {{{{{placeholder}}}}} — the template and the \
         renderer are out of step"
    )]
    Unfilled {
        template: String,
        placeholder: String,
    },

    #[error("{}: {because}", path.display())]
    Write { path: PathBuf, because: String },
}

/// Fill one template, substituting and checking in a single pass, so a
/// placeholder inside a supplied value stays a value.
pub fn fill(
    template_name: &str,
    template: &str,
    values: &[(&str, String)],
) -> Result<String, RenderError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let (key, tail) = after.split_once("}}").unwrap_or((after, ""));

        let value = values
            .iter()
            .find_map(|(k, value)| (*k == key).then_some(value))
            .ok_or_else(|| RenderError::Unfilled {
                template: template_name.to_string(),
                placeholder: key.to_string(),
            })?;
        out.push_str(value);
        rest = tail;
    }

    out.push_str(rest);
    Ok(out)
}

/// Fill several templates whose rendered path is fixed, and doubles as the
/// template's name in a [`fill`] error.
pub fn fixed(
    templates: &[(&str, &str)],
    values: &[(&str, String)],
) -> Result<Vec<Artefact>, RenderError> {
    templates
        .iter()
        .map(|(path, template)| {
            Ok(Artefact {
                path: PathBuf::from(path),
                body: fill(path, template, values)?,
            })
        })
        .collect()
}

/// What is on disk, against what should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// On disk and identical.
    Same,
    /// On disk and not what this chassis renders.
    Differs,
    /// Not there at all.
    Missing,
    /// There, and could not be read as text.
    Unreadable,
}

impl State {
    /// Whether this is a state `packaging render` would change.
    pub fn is_drift(self) -> bool {
        self != State::Same
    }

    /// What to tell somebody looking at a report.
    pub fn because(self) -> &'static str {
        match self {
            State::Same => "is in step",
            State::Differs => "is not what this chassis renders",
            State::Missing => "is not there",
            State::Unreadable => "could not be read",
        }
    }
}

/// Compare every chassis-owned file against the directory it is rendered into;
/// a file that cannot be read is reported rather than raised.
pub fn compare<'a>(root: &Path, artefacts: &'a [Artefact]) -> Vec<(&'a Path, State)> {
    artefacts
        .iter()
        .map(|artefact| {
            let state = match std::fs::read_to_string(root.join(&artefact.path)) {
                Ok(on_disk) if on_disk == artefact.body => State::Same,
                Ok(_) => State::Differs,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::Missing,
                Err(_) => State::Unreadable,
            };
            (artefact.path.as_path(), state)
        })
        .collect()
}

/// Write every chassis-owned file, unconditionally.
pub fn write(root: &Path, artefacts: &[Artefact]) -> Result<(), RenderError> {
    for artefact in artefacts {
        let path = root.join(&artefact.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RenderError::Write {
                path: parent.to_path_buf(),
                because: e.to_string(),
            })?;
        }
        std::fs::write(&path, &artefact.body).map_err(|e| RenderError::Write {
            path: path.clone(),
            because: e.to_string(),
        })?;
        if artefact.body.starts_with("#!") {
            make_executable(&path)?;
        }
    }
    Ok(())
}

/// A rendered file whose first line is a shebang is one somebody runs. The mode
/// is not part of [`compare`].
#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), RenderError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(|e| {
        RenderError::Write {
            path: path.to_path_buf(),
            because: e.to_string(),
        }
    })
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), RenderError> {
    Ok(())
}

#[cfg(test)]
pub(crate) fn body(artefacts: &[Artefact], path: &str) -> String {
    artefacts
        .iter()
        .find(|a| a.path.to_str() == Some(path))
        .unwrap_or_else(|| panic!("{path} is rendered"))
        .body
        .clone()
}

/// A rendered script with its comments removed, so an assertion cannot pass on
/// the prose that explains a command.
#[cfg(test)]
pub(crate) fn commands(script: &str) -> String {
    script
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn artefact(path: &str, body: &str) -> Artefact {
        Artefact {
            path: PathBuf::from(path),
            body: body.to_string(),
        }
    }

    fn states(root: &Path, artefacts: &[Artefact]) -> Vec<State> {
        compare(root, artefacts)
            .into_iter()
            .map(|(_, s)| s)
            .collect()
    }

    fn in_step(root: &Path, artefacts: &[Artefact]) -> bool {
        compare(root, artefacts).iter().all(|(_, s)| !s.is_drift())
    }

    #[test]
    fn a_placeholder_nobody_supplied_is_an_error_rather_than_a_literal() {
        let filled = fill(
            "t",
            "User={{user}}\nGroup={{group}}\n",
            &[("user", "a".into()), ("group", "b".into())],
        )
        .expect("both supplied");
        assert_eq!(filled, "User=a\nGroup=b\n");

        let e = fill("t", "User={{user}}\n", &[]).expect_err("nothing supplied");
        assert!(e.to_string().contains("user"), "{e}");
    }

    #[test]
    fn a_value_that_contains_a_placeholder_is_a_value() {
        let filled = fill("t", "name={{name}}\n", &[("name", "{{binary}}".into())])
            .expect("substituted once, not rescanned");
        assert_eq!(filled, "name={{binary}}\n");
    }

    #[test]
    fn what_is_written_is_what_compare_then_calls_in_step() {
        let dir = TempDir::new().expect("tempdir");
        let artefacts = [
            artefact("systemd/x.service", "[Unit]\n"),
            artefact("systemd/x.service.d/00-example.conf.sample", "# hello\n"),
        ];

        assert_eq!(states(dir.path(), &artefacts), [State::Missing; 2]);

        write(dir.path(), &artefacts).expect("writes");
        assert!(in_step(dir.path(), &artefacts));

        std::fs::write(dir.path().join("systemd/x.service"), "[Unit]\n# mine\n").expect("edit");
        assert_eq!(
            states(dir.path(), &artefacts),
            [State::Differs, State::Same]
        );

        write(dir.path(), &artefacts).expect("writes");
        assert!(in_step(dir.path(), &artefacts));
    }

    #[cfg(unix)]
    #[test]
    fn a_rendered_script_is_executable_and_a_rendered_document_is_not() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("tempdir");
        let artefacts = [
            artefact("packaging/x.sh", "#!/bin/sh\nexit 0\n"),
            artefact("debian/hooks.README", "# Adding your own steps\n"),
        ];
        write(dir.path(), &artefacts).expect("writes");

        let mode = |path: &str| {
            std::fs::metadata(dir.path().join(path))
                .expect("stat")
                .permissions()
                .mode()
        };
        assert_eq!(mode("packaging/x.sh") & 0o777, 0o755);
        assert_eq!(mode("debian/hooks.README") & 0o111, 0);

        std::fs::set_permissions(
            dir.path().join("packaging/x.sh"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod");
        assert!(in_step(dir.path(), &artefacts));
    }

    #[test]
    fn a_products_own_file_beside_a_chassis_one_is_not_compared() {
        let dir = TempDir::new().expect("tempdir");
        let artefacts = [artefact("systemd/x.service", "[Unit]\n")];
        write(dir.path(), &artefacts).expect("writes");

        std::fs::write(dir.path().join("systemd/10-local.conf"), "[Service]\n").expect("theirs");
        assert!(in_step(dir.path(), &artefacts));
    }

    #[test]
    fn a_file_that_cannot_be_read_says_so_rather_than_claiming_it_differs() {
        let dir = TempDir::new().expect("tempdir");
        let artefacts = [artefact("systemd/x.service", "[Unit]\n")];
        std::fs::write(dir.path().join("systemd"), []).ok();
        std::fs::remove_file(dir.path().join("systemd")).ok();
        std::fs::create_dir_all(dir.path().join("systemd")).expect("dir");
        std::fs::write(dir.path().join("systemd/x.service"), [0xff, 0xfe]).expect("bytes");

        assert_eq!(states(dir.path(), &artefacts), [State::Unreadable]);
        assert_eq!(State::Unreadable.because(), "could not be read");
    }
}
