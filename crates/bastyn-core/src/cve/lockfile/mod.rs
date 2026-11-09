//! Lockfile parsing.
//!
//! A lockfile records the exact version every dependency resolved to,
//! transitive ones included, which a manifest range cannot. Each format has
//! its own parser submodule; this module holds the shared result types and the
//! dispatch by file name.
//!
//! Nothing here guesses. A package record is returned as a [`Dependency`] only
//! when the lockfile names an exact version and a registry source. A record
//! that resolves to a git checkout, a URL or a local path is returned as an
//! [`UnresolvedSource`], never dropped and never matched against advisories.
//! First-party packages (the project itself and its workspace members) are
//! neither: they are the code being scanned, not a dependency of it.

use std::path::{Path, PathBuf};

use super::manifest::{Dependency, Ecosystem};

mod npm;
mod pnpm;
mod poetry;
mod uv;
mod yarn;

/// A lockfile format this module can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockKind {
    /// `uv.lock`.
    Uv,
    /// `poetry.lock`.
    Poetry,
    /// `package-lock.json`.
    NpmPackageLock,
    /// `pnpm-lock.yaml`.
    Pnpm,
    /// `yarn.lock`, classic (v1) or berry.
    Yarn,
}

impl LockKind {
    /// The kind for a file name, or `None` if it is not a supported lockfile.
    #[must_use]
    pub fn from_file_name(name: &str) -> Option<Self> {
        match name {
            "uv.lock" => Some(Self::Uv),
            "poetry.lock" => Some(Self::Poetry),
            "package-lock.json" => Some(Self::NpmPackageLock),
            "pnpm-lock.yaml" => Some(Self::Pnpm),
            "yarn.lock" => Some(Self::Yarn),
            _ => None,
        }
    }

    /// The registry the packages in this kind of lockfile come from.
    #[must_use]
    pub const fn ecosystem(self) -> Ecosystem {
        match self {
            Self::Uv | Self::Poetry => Ecosystem::PyPi,
            Self::NpmPackageLock | Self::Pnpm | Self::Yarn => Ecosystem::Npm,
        }
    }
}

/// A dependency a lockfile resolves to something other than a registry
/// version, so no advisory can be matched against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedSource {
    /// Package name.
    pub name: String,
    /// What the lockfile says it resolves to, in a few words: `git`, `url`,
    /// `path`, or `directory`.
    pub source: String,
    /// The lockfile, relative to the scanned root.
    pub file: PathBuf,
    /// 1-indexed line of the package record.
    pub line: usize,
}

/// A successfully parsed lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    /// Which format it is.
    pub kind: LockKind,
    /// The lockfile, relative to the scanned root.
    pub file: PathBuf,
    /// Every package with an exact registry version, deduplicated by
    /// `(name, version)`, in file order. `file` and `line` point into the
    /// lockfile; `declaration` is the trimmed line.
    pub packages: Vec<Dependency>,
    /// Packages that resolve to a non-registry source, deduplicated by
    /// `(name, source)`, in file order.
    pub unresolved_sources: Vec<UnresolvedSource>,
    /// Project directories this lockfile resolves besides its own, relative to
    /// the lockfile's directory, forward slashes, e.g. `packages/api`. Empty
    /// for a lockfile that covers one project.
    pub members: Vec<String>,
    /// Workspace glob patterns the lockfile's workspace declares (`packages/*`),
    /// for formats whose lockfile does not enumerate members itself. Empty
    /// otherwise.
    pub workspace_globs: Vec<String>,
}

/// Why a lockfile could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// The file is not valid for its format.
    Malformed {
        /// The lockfile, relative to the scanned root.
        file: PathBuf,
        /// What was wrong, in a few words.
        reason: String,
    },
    /// The file is valid-looking but a format or version this module does not
    /// read.
    Unsupported {
        /// The lockfile, relative to the scanned root.
        file: PathBuf,
        /// What is unsupported, e.g. `lockfileVersion 4`.
        reason: String,
    },
}

impl LockError {
    /// The lockfile this error is about.
    #[must_use]
    pub fn file(&self) -> &Path {
        match self {
            Self::Malformed { file, .. } | Self::Unsupported { file, .. } => file,
        }
    }
}

/// True if `path`'s file name is a lockfile this module can parse.
#[must_use]
pub fn is_lockfile(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(LockKind::from_file_name)
        .is_some()
}

/// Parse one lockfile.
///
/// `relative_path` selects the parser by file name and is stamped onto every
/// record. `sibling_package_json` is the contents of the `package.json` in the
/// same directory, if any; only the `yarn.lock` parser reads it (to find the
/// workspace globs a classic `yarn.lock` does not record).
///
/// # Errors
/// [`LockError::Malformed`] if the content is not valid for the format,
/// [`LockError::Unsupported`] if the file name is not a lockfile or the
/// format version is not read.
pub fn parse_lockfile(
    relative_path: &Path,
    contents: &str,
    sibling_package_json: Option<&str>,
) -> Result<Lockfile, LockError> {
    let kind = relative_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(LockKind::from_file_name)
        .ok_or_else(|| LockError::Unsupported {
            file: relative_path.to_path_buf(),
            reason: "not a recognised lockfile".to_owned(),
        })?;
    match kind {
        LockKind::Uv => uv::parse(relative_path, contents),
        LockKind::Poetry => poetry::parse(relative_path, contents),
        LockKind::NpmPackageLock => npm::parse(relative_path, contents),
        LockKind::Pnpm => pnpm::parse(relative_path, contents),
        LockKind::Yarn => yarn::parse(relative_path, contents, sibling_package_json),
    }
}
