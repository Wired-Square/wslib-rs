//! Stamps the commit an artefact was built from into the artefact.
//!
//! A version names a release, not a build: two binaries can carry `0.1.0`. This
//! crate carries the *pieces* of a build's identity and renders one per audience,
//! because the three that need it spell it differently and are not
//! interchangeable — a `.deb` version may contain neither a space nor a
//! parenthesis, so the `--version` form is unusable there.
//!
//! Both a build-dependency and an ordinary one. The whole of `build.rs`:
//!
//! ```no_run
//! wslib_build_id::emit();
//! ```
//!
//! and then, at runtime:
//!
//! ```ignore
//! println!("{} {}", env!("CARGO_PKG_NAME"), wslib_build_id::build_version!());
//! // my-app 0.1.0 (g4bf526d44891)
//! ```
//!
//! A binary that *can* name a commit names the one it was built from, and says so
//! when that tree had been modified. A build from a tarball or a container with no
//! `.git` has nothing to read and renders as [`UNKNOWN`]; refusing to ship that is
//! the packaging step's job, not this crate's.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// How a build with no commit to name renders.
///
/// The parentheses belong to [`build_version!`], not to this value — baking them
/// in renders `0.1.0 ((unknown))` and stops matching the `" (unknown)"` that a
/// packaging step greps for to refuse the package.
pub const UNKNOWN: &str = "unknown";

/// The environment variable carrying a pre-computed build id.
///
/// A build with no `.git` sets this instead.
pub const ENV: &str = "WSLIB_BUILD_ID";

/// Where a build id came from, and the pieces each source can supply.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// Read from a checkout.
    Git {
        /// Abbreviated commit, 12 hex digits.
        sha: String,
        /// Committer date of that commit as `YYYYMMDD`, for the package version.
        date: Option<String>,
        /// Whether tracked files had been modified.
        dirty: bool,
    },
    /// Handed to us through [`ENV`], and used verbatim.
    Supplied(String),
    /// Nothing to name this build by.
    Unknown,
}

/// The identity of one build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildId(Source);

impl BuildId {
    /// Works out the identity of the build happening now.
    ///
    /// [`ENV`] wins over the working tree: a container or CI build often has a
    /// `.git` belonging to whatever the host checked out rather than to what is
    /// being built, and whoever set the variable knows something the tree does not.
    pub fn detect() -> Self {
        if let Some(supplied) = std::env::var(ENV)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return Self(Source::Supplied(supplied));
        }
        let Some(sha) = git(&["rev-parse", "--short=12", "HEAD"]) else {
            return Self(Source::Unknown);
        };
        Self(Source::Git {
            date: git(&["log", "-1", "--format=%cd", "--date=format:%Y%m%d"]),
            // `--untracked-files=no`: a scratch file is not a modification to what
            // was built. A git that fails here having just succeeded above is not
            // evidence of a clean tree, so `None` reads as dirty.
            dirty: git(&["status", "--porcelain", "--untracked-files=no"])
                .is_none_or(|s| !s.is_empty()),
            sha,
        })
    }

    /// Whether this build can name itself at all.
    pub fn is_known(&self) -> bool {
        !matches!(self.0, Source::Unknown)
    }

    /// Whether this build was read from a checkout with no tracked file
    /// modified: the only build a release version may name.
    pub fn is_clean_checkout(&self) -> bool {
        matches!(self.0, Source::Git { dirty: false, .. })
    }

    /// The Debian version suffix for a snapshot build, as `~git20260907.4bf526d44891`
    /// with `.dirty` appended when the tree was modified.
    ///
    /// Three details the format depends on:
    ///
    /// - **`~`, not `+`** — a snapshot must sort *below* the release, so the
    ///   release installs over a box running one. `+` sorts above and strands it.
    /// - **The date leads the sha**, because a bare sha has no order: dpkg reads
    ///   `0.1.0~gf00` as newer than `0.1.0~g0ff`.
    /// - **`.dirty`, not `-dirty`** — a hyphen separates the Debian revision.
    ///
    /// `None` when there is no commit to build a version from; the caller is then
    /// packaging something that cannot say what it is, and should refuse.
    pub fn snapshot_suffix(&self) -> Option<String> {
        let Source::Git { sha, date, dirty } = &self.0 else {
            return None;
        };
        let date = date.as_deref()?;
        Some(format!(
            "~git{date}.{sha}{}",
            if *dirty { ".dirty" } else { "" }
        ))
    }
}

/// The `--version` form: `g4bf526d44891`, `g4bf526d44891-dirty`, or [`UNKNOWN`].
impl fmt::Display for BuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Source::Git { sha, dirty, .. } => {
                write!(f, "g{sha}{}", if *dirty { "-dirty" } else { "" })
            }
            Source::Supplied(s) => f.write_str(s),
            Source::Unknown => f.write_str(UNKNOWN),
        }
    }
}

/// Call from `build.rs`. Emits [`ENV`] for [`build_version!`], plus the rerun
/// triggers that keep it from going stale.
pub fn emit() {
    println!("cargo:rerun-if-env-changed={ENV}");
    for path in git_ref_watches(Path::new(".")) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    // The calling crate's own sources, because an edit is when `-dirty` stops
    // being true. Relative, so it resolves against whichever crate called us.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rustc-env={ENV}={}", BuildId::detect());
}

/// The files git rewrites when HEAD moves in the checkout at `dir`: the existing
/// ones among [`ref_watches`].
///
/// Asks git for the layout rather than guessing: consumers are other repositories
/// whose directory shapes are unknown, and naming a path that does not exist makes
/// cargo re-run the build script on every build.
///
/// Watching `HEAD` alone is not enough. It holds `ref: refs/heads/main` and is
/// rewritten on *checkout*; an ordinary commit rewrites the branch's ref file
/// instead, so watching only `HEAD` goes on stamping the commit before last.
fn git_ref_watches(dir: &Path) -> Vec<PathBuf> {
    let Some(dirs) = git_in(
        dir,
        &["rev-parse", "--absolute-git-dir", "--git-common-dir"],
    ) else {
        return Vec::new();
    };
    let mut dirs = dirs.lines();
    let (Some(git_dir), Some(common_dir)) = (dirs.next(), dirs.next()) else {
        return Vec::new();
    };
    // The common dir is relative to `dir` in a main checkout; `--path-format=absolute`
    // needs git 2.31.
    let resolve = |path: &str| {
        let path = dir.join(path);
        std::fs::canonicalize(&path).unwrap_or(path)
    };
    let (git_dir, common_dir) = (resolve(git_dir), resolve(common_dir));
    let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) else {
        return Vec::new();
    };
    let mut watches = ref_watches(&git_dir, &common_dir, &head);
    watches.retain(|path| path.exists());
    watches.dedup();
    watches
}

/// `HEAD`, its reflog and a worktree's own reftable live in `git_dir`; branch
/// refs, `packed-refs` and the shared reftable live in `common_dir`, which is
/// `git_dir` in a main checkout.
///
/// `head` is `ref: refs/heads/main` on a branch, a bare sha when detached. The
/// reflog catches a commit on a branch whose ref was only packed.
fn ref_watches(git_dir: &Path, common_dir: &Path, head: &str) -> Vec<PathBuf> {
    let mut paths = vec![git_dir.join("HEAD"), within(git_dir, "logs/HEAD")];
    if let Some(reference) = head.trim().strip_prefix("ref: ") {
        paths.push(within(common_dir, reference));
    }
    paths.push(common_dir.join("packed-refs"));
    paths.push(within(git_dir, "reftable/tables.list"));
    paths.push(within(common_dir, "reftable/tables.list"));
    paths
}

/// Joins a `/`-separated relative path one component at a time: `/` is not a
/// separator inside a Windows verbatim path, which `canonicalize` returns.
fn within(dir: &Path, relative: &str) -> PathBuf {
    relative
        .split('/')
        .fold(dir.to_path_buf(), |path, part| path.join(part))
}

fn git(args: &[&str]) -> Option<String> {
    git_in(Path::new("."), args)
}

/// Runs git in `dir`, returning trimmed stdout, or `None` if git is absent, this
/// is not a repository, or the command failed.
fn git_in(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The crate version and the commit it was built from, as one `&'static str`.
///
/// Expands in the *caller's* crate, so it reports that crate's
/// `CARGO_PKG_VERSION` and the id its own `build.rs` emitted — which is why
/// [`emit`] must be called there rather than here.
#[macro_export]
macro_rules! build_version {
    () => {
        concat!(
            env!("CARGO_PKG_VERSION"),
            " (",
            env!(
                "WSLIB_BUILD_ID",
                "WSLIB_BUILD_ID is unset — call wslib_build_id::emit() from build.rs"
            ),
            ")"
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "4bf526d44891";

    fn git_id(dirty: bool) -> BuildId {
        BuildId(Source::Git {
            sha: SHA.to_string(),
            date: Some("20260907".to_string()),
            dirty,
        })
    }

    /// What `build_version!` renders. The macro is `concat!` of `env!` so it
    /// cannot be evaluated here, but the shape is a contract with packaging.
    fn stamped(id: &BuildId) -> String {
        format!("0.1.0 ({id})")
    }

    #[test]
    fn the_version_stamp_names_the_commit() {
        assert_eq!(stamped(&git_id(false)), "0.1.0 (g4bf526d44891)");
    }

    #[test]
    fn only_an_unmodified_checkout_is_clean() {
        assert!(git_id(false).is_clean_checkout());
        assert!(!git_id(true).is_clean_checkout());
        assert!(!BuildId(Source::Supplied("g4bf526d44891".to_string())).is_clean_checkout());
        assert!(!BuildId(Source::Unknown).is_clean_checkout());
    }

    #[test]
    fn a_modified_tree_says_so_in_every_rendering() {
        assert_eq!(stamped(&git_id(true)), "0.1.0 (g4bf526d44891-dirty)");
        assert_eq!(
            git_id(true).snapshot_suffix().unwrap(),
            "~git20260907.4bf526d44891.dirty"
        );
    }

    #[test]
    fn an_unknown_build_renders_exactly_what_packaging_greps_for() {
        // Doubling the parentheses by baking them into UNKNOWN would render
        // "0.1.0 ((unknown))" and stop the packaging gate firing.
        assert_eq!(stamped(&BuildId(Source::Unknown)), "0.1.0 (unknown)");
        assert!(!BuildId(Source::Unknown).is_known());
        assert_eq!(BuildId(Source::Unknown).snapshot_suffix(), None);
    }

    #[test]
    fn a_supplied_id_is_used_verbatim_and_beats_the_working_tree() {
        let id = BuildId(Source::Supplied("gdeadbeefcafe".into()));
        assert_eq!(stamped(&id), "0.1.0 (gdeadbeefcafe)");
        assert!(id.is_known());
    }

    #[test]
    fn a_debian_snapshot_sorts_below_the_release_it_precedes() {
        let suffix = git_id(false).snapshot_suffix().unwrap();
        assert_eq!(suffix, "~git20260907.4bf526d44891");
        assert!(suffix.starts_with('~'));
        // `.dirty`, never `-dirty`: a hyphen separates the Debian revision.
        assert!(!suffix.contains('-'));
    }

    #[test]
    fn a_commit_with_no_readable_date_has_no_package_version() {
        // Better than inventing today's date, which would make two builds of one
        // commit sort differently.
        let id = BuildId(Source::Git {
            sha: SHA.to_string(),
            date: None,
            dirty: false,
        });
        assert_eq!(id.snapshot_suffix(), None);
        assert_eq!(stamped(&id), "0.1.0 (g4bf526d44891)");
    }

    #[test]
    fn detecting_in_this_tree_produces_something_renderable() {
        // In a checkout this names a commit, in an exported tarball it does not.
        // Both are legitimate, so assert only that the result is well-formed.
        let id = BuildId::detect();
        let rendered = id.to_string();
        assert!(!rendered.is_empty());
        if let Source::Git { sha, .. } = &id.0 {
            assert_eq!(sha.len(), 12, "expected 12 hex digits, got {sha:?}");
            assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    /// A throwaway repository with one commit on `main` and a worktree at `wt`
    /// on `feature`, removed on drop.
    struct Repo(PathBuf);

    impl Repo {
        fn new(name: &str) -> Self {
            Self::init(name, &[]).expect("git init")
        }

        /// `None` when this git refuses `init_args`.
        fn init(name: &str, init_args: &[&str]) -> Option<Self> {
            // Not canonicalised: a Windows verbatim cwd would reach git.
            let root =
                std::env::temp_dir().join(format!("wslib-build-id-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("main")).unwrap();
            let repo = Self(root);
            if !repo.run("main", &[&["init", "-q", "-b", "main"], init_args].concat()) {
                return None;
            }
            repo.git("main", &["commit", "-q", "--allow-empty", "-m", "one"]);
            repo.git("main", &["worktree", "add", "-q", "-b", "feature", "../wt"]);
            Some(repo)
        }

        fn git(&self, dir: &str, args: &[&str]) {
            assert!(self.run(dir, args), "git {args:?} failed");
        }

        fn run(&self, dir: &str, args: &[&str]) -> bool {
            let config = [
                "user.name=t",
                "user.email=t@t",
                "commit.gpgsign=false",
                "core.hooksPath=",
                "core.logAllRefUpdates=true",
                "init.defaultRefFormat=files",
            ];
            Command::new("git")
                .args(config.iter().flat_map(|c| ["-c", c]))
                .args(args)
                .current_dir(self.0.join(dir))
                .env_remove("GIT_DIR")
                .env_remove("GIT_WORK_TREE")
                .env_remove("GIT_INDEX_FILE")
                .env_remove("GIT_COMMON_DIR")
                .env_remove("GIT_DEFAULT_REF_FORMAT")
                .status()
                .unwrap()
                .success()
        }

        /// Compared canonicalised: git's spelling of a path is not the test's
        /// (`/private/var` on macOS, `C:/` against `\\?\C:\` on Windows).
        fn assert_watches(&self, dir: &str, expected: &[&str]) {
            let canonical = |path: &Path| std::fs::canonicalize(path).unwrap();
            let actual: Vec<_> = git_ref_watches(&self.0.join(dir))
                .iter()
                .map(|path| canonical(path))
                .collect();
            let expected: Vec<_> = expected
                .iter()
                .map(|path| canonical(&within(&self.0, path)))
                .collect();
            assert_eq!(actual, expected);
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_main_checkout_watches_head_and_its_branch_ref() {
        Repo::new("main").assert_watches(
            "main",
            &[
                "main/.git/HEAD",
                "main/.git/logs/HEAD",
                "main/.git/refs/heads/main",
            ],
        );
    }

    #[test]
    fn a_worktree_watches_the_branch_ref_in_the_common_dir() {
        Repo::new("worktree").assert_watches(
            "wt",
            &[
                "main/.git/worktrees/wt/HEAD",
                "main/.git/worktrees/wt/logs/HEAD",
                "main/.git/refs/heads/feature",
            ],
        );
    }

    #[test]
    fn a_detached_worktree_watches_no_branch_ref() {
        let repo = Repo::new("detached");
        repo.git("wt", &["checkout", "-q", "--detach"]);
        repo.assert_watches(
            "wt",
            &[
                "main/.git/worktrees/wt/HEAD",
                "main/.git/worktrees/wt/logs/HEAD",
            ],
        );
    }

    #[test]
    fn a_packed_only_branch_is_watched_through_its_reflog_and_packed_refs() {
        let repo = Repo::new("packed");
        repo.git("main", &["pack-refs", "--all"]);
        repo.assert_watches(
            "main",
            &[
                "main/.git/HEAD",
                "main/.git/logs/HEAD",
                "main/.git/packed-refs",
            ],
        );
        repo.assert_watches(
            "wt",
            &[
                "main/.git/worktrees/wt/HEAD",
                "main/.git/worktrees/wt/logs/HEAD",
                "main/.git/packed-refs",
            ],
        );
    }

    #[test]
    fn a_reftable_repository_watches_its_table_lists() {
        let Some(repo) = Repo::init("reftable", &["--ref-format=reftable"]) else {
            eprintln!("skipped: this git has no reftable");
            return;
        };
        repo.assert_watches(
            "main",
            &["main/.git/HEAD", "main/.git/reftable/tables.list"],
        );
        repo.assert_watches(
            "wt",
            &[
                "main/.git/worktrees/wt/HEAD",
                "main/.git/worktrees/wt/reftable/tables.list",
                "main/.git/reftable/tables.list",
            ],
        );
    }
}
