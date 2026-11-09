//! Combining manifests with the lockfiles that resolve them.
//!
//! A manifest declares what a project asks for; a lockfile records what it
//! got, transitive packages included. When a lockfile applies to a manifest,
//! the lockfile's records stand in for the manifest's entries for every name
//! the lockfile knows. Names the lockfile does not know (a stale lockfile, or
//! a tool that is not locked) keep the manifest handling.
//!
//! This is pure: it takes parsed inputs and returns the combined result, so
//! the output order depends only on the input order.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::lockfile::{LockError, LockKind, Lockfile, UnresolvedSource};
use super::manifest::{Dependency, Ecosystem, UnresolvedDependency};

/// What one parsed manifest yielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestInput {
    /// The manifest, relative to the scanned root.
    pub file: PathBuf,
    /// The registry its dependencies live in.
    pub ecosystem: Ecosystem,
    /// Dependencies pinned to an exact version.
    pub resolved: Vec<Dependency>,
    /// Dependencies declared as a range.
    pub unresolved: Vec<UnresolvedDependency>,
}

/// The combined dependency picture for a scan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reconciled {
    /// Dependencies to look up against the advisory database.
    pub dependencies: Vec<Dependency>,
    /// Manifest ranges that no lockfile resolved, so remain unchecked.
    pub gaps: Vec<UnresolvedDependency>,
    /// Lockfile records that resolve to a non-registry source, from the
    /// lockfiles that were used.
    pub unresolved_sources: Vec<UnresolvedSource>,
    /// Every lockfile that failed to parse, in input order.
    pub lock_errors: Vec<LockError>,
}

/// Combine manifests with lockfiles.
///
/// All paths are relative to the scanned root. For each manifest the nearest
/// applicable lockfile of the same ecosystem is chosen, looking in the
/// manifest's directory first and then each ancestor. A lockfile applies to a
/// manifest in its own directory, or to a manifest in a directory it lists as
/// a workspace member or matches with a workspace glob.
///
/// Where a lockfile covers a manifest, the manifest's entries for names the
/// lockfile records are dropped in favour of the lockfile's own records; the
/// rest stay as the manifest declared them. Every lockfile contributes its
/// packages, except one that sits next to a more-preferred lockfile of the
/// same ecosystem, which describes the same project. Every lockfile error is
/// returned.
///
/// Ordering is deterministic: kept manifest dependencies in manifest order,
/// then lockfile packages in lockfile order.
#[must_use]
pub fn reconcile(manifests: &[ManifestInput], locks: &[Result<Lockfile, LockError>]) -> Reconciled {
    let parsed: Vec<&Lockfile> = locks.iter().filter_map(|l| l.as_ref().ok()).collect();
    let mut out = Reconciled {
        lock_errors: locks
            .iter()
            .filter_map(|l| l.as_ref().err().cloned())
            .collect(),
        ..Reconciled::default()
    };

    for manifest in manifests {
        let covering = select_lock(manifest, &parsed);
        let known: Option<HashSet<String>> = covering.map(|lock| {
            lock.packages
                .iter()
                .map(|p| p.name.as_str())
                .chain(lock.unresolved_sources.iter().map(|u| u.name.as_str()))
                .map(|name| normalise(manifest.ecosystem, name))
                .collect()
        });
        let is_known = |name: &str| {
            known
                .as_ref()
                .is_some_and(|set| set.contains(&normalise(manifest.ecosystem, name)))
        };
        out.dependencies.extend(
            manifest
                .resolved
                .iter()
                .filter(|d| !is_known(&d.name))
                .cloned(),
        );
        out.gaps.extend(
            manifest
                .unresolved
                .iter()
                .filter(|d| !is_known(&d.name))
                .cloned(),
        );
    }

    for lock in &parsed {
        if superseded(lock, &parsed) {
            continue;
        }
        out.dependencies.extend(lock.packages.iter().cloned());
        out.unresolved_sources
            .extend(lock.unresolved_sources.iter().cloned());
    }
    out
}

/// Lower is more preferred, within one ecosystem.
const fn preference(kind: LockKind) -> u8 {
    match kind {
        LockKind::Uv | LockKind::NpmPackageLock => 0,
        LockKind::Poetry | LockKind::Pnpm => 1,
        LockKind::Yarn => 2,
    }
}

/// The directory a file sits in; empty for a file at the root.
fn dir_of(file: &Path) -> &Path {
    file.parent().unwrap_or_else(|| Path::new(""))
}

/// True if a more-preferred lockfile of the same ecosystem is in the same
/// directory.
fn superseded(lock: &Lockfile, all: &[&Lockfile]) -> bool {
    all.iter().any(|other| {
        other.kind.ecosystem() == lock.kind.ecosystem()
            && dir_of(&other.file) == dir_of(&lock.file)
            && preference(other.kind) < preference(lock.kind)
    })
}

/// The lockfile that covers `manifest`, if any.
fn select_lock<'a>(manifest: &ManifestInput, locks: &[&'a Lockfile]) -> Option<&'a Lockfile> {
    if manifest.ecosystem == Ecosystem::CratesIo {
        return None;
    }
    let manifest_dir = dir_of(&manifest.file);
    for dir in manifest_dir.ancestors() {
        let mut candidates: Vec<&'a Lockfile> = locks
            .iter()
            .copied()
            .filter(|l| l.kind.ecosystem() == manifest.ecosystem && dir_of(&l.file) == dir)
            .collect();
        // Stable sort keeps input order among equally preferred kinds.
        candidates.sort_by_key(|l| preference(l.kind));
        if let Some(found) = candidates.into_iter().find(|l| covers(l, manifest_dir)) {
            return Some(found);
        }
    }
    None
}

/// True if `lock` resolves the project in `manifest_dir`.
fn covers(lock: &Lockfile, manifest_dir: &Path) -> bool {
    let lock_dir = dir_of(&lock.file);
    if lock_dir == manifest_dir {
        return true;
    }
    let Ok(relative) = manifest_dir.strip_prefix(lock_dir) else {
        return false;
    };
    let segments: Vec<&str> = relative.iter().filter_map(|s| s.to_str()).collect();
    let joined = segments.join("/");
    lock.members.iter().any(|m| trim_dot(m) == joined)
        || lock
            .workspace_globs
            .iter()
            .any(|g| glob_matches(g, &segments))
}

fn trim_dot(s: &str) -> &str {
    s.strip_prefix("./").unwrap_or(s).trim_end_matches('/')
}

/// Segment-wise workspace glob match. `*` matches within one segment, `**`
/// matches any number of segments, everything else is literal. A pattern
/// starting with `!` is an exclusion and never matches.
fn glob_matches(pattern: &str, segments: &[&str]) -> bool {
    if pattern.starts_with('!') {
        return false;
    }
    let pattern = trim_dot(pattern);
    let parts: Vec<&str> = pattern.split('/').filter(|p| !p.is_empty()).collect();
    match_segments(&parts, segments)
}

fn match_segments(pattern: &[&str], segments: &[&str]) -> bool {
    match pattern.split_first() {
        None => segments.is_empty(),
        Some((&"**", rest)) => (0..=segments.len()).any(|n| match_segments(rest, &segments[n..])),
        Some((part, rest)) => segments
            .split_first()
            .is_some_and(|(seg, tail)| segment_matches(part, seg) && match_segments(rest, tail)),
    }
}

/// Match one path segment against a pattern segment with `*` wildcards.
fn segment_matches(pattern: &str, segment: &str) -> bool {
    let pieces: Vec<&str> = pattern.split('*').collect();
    let [first, middle @ .., last] = pieces.as_slice() else {
        return pattern == segment;
    };
    let Some(mut rest) = segment.strip_prefix(first) else {
        return false;
    };
    for piece in middle {
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// Normalise a package name for comparison: PEP 503 for `PyPI`, exact
/// otherwise.
fn normalise(ecosystem: Ecosystem, name: &str) -> String {
    if ecosystem != Ecosystem::PyPi {
        return name.to_owned();
    }
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_run {
                out.push('-');
            }
            in_run = true;
        } else {
            in_run = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, version: &str, eco: Ecosystem, file: &str) -> Dependency {
        Dependency {
            name: name.to_owned(),
            version: version.to_owned(),
            ecosystem: eco,
            file: PathBuf::from(file),
            line: 1,
            declaration: format!("{name} {version}"),
        }
    }

    fn range(name: &str, eco_file: &str) -> UnresolvedDependency {
        UnresolvedDependency {
            name: name.to_owned(),
            constraint: ">=1".to_owned(),
            file: PathBuf::from(eco_file),
            line: 1,
            dev: false,
        }
    }

    fn manifest(
        file: &str,
        eco: Ecosystem,
        resolved: Vec<Dependency>,
        unresolved: Vec<UnresolvedDependency>,
    ) -> ManifestInput {
        ManifestInput {
            file: PathBuf::from(file),
            ecosystem: eco,
            resolved,
            unresolved,
        }
    }

    fn lock(kind: LockKind, file: &str, pkgs: &[(&str, &str)]) -> Lockfile {
        Lockfile {
            kind,
            file: PathBuf::from(file),
            packages: pkgs
                .iter()
                .map(|(n, v)| dep(n, v, kind.ecosystem(), file))
                .collect(),
            unresolved_sources: Vec::new(),
            members: Vec::new(),
            workspace_globs: Vec::new(),
        }
    }

    fn names(deps: &[Dependency]) -> Vec<(&str, &str)> {
        deps.iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect()
    }

    fn gap_names(gaps: &[UnresolvedDependency]) -> Vec<&str> {
        gaps.iter().map(|g| g.name.as_str()).collect()
    }

    #[test]
    fn same_dir_lock_covers_pyproject_and_drops_gap() {
        let m = manifest(
            "pyproject.toml",
            Ecosystem::PyPi,
            vec![],
            vec![range("requests", "pyproject.toml")],
        );
        let l = lock(
            LockKind::Uv,
            "uv.lock",
            &[("requests", "2.31.0"), ("idna", "3.7")],
        );
        let r = reconcile(&[m], &[Ok(l)]);
        assert_eq!(r.gaps.len(), 0);
        assert_eq!(
            names(&r.dependencies),
            [("requests", "2.31.0"), ("idna", "3.7")]
        );
    }

    #[test]
    fn member_manifest_is_covered_by_root_lock() {
        let m = manifest(
            "packages/api/package.json",
            Ecosystem::Npm,
            vec![],
            vec![range("left-pad", "packages/api/package.json")],
        );
        let mut l = lock(
            LockKind::NpmPackageLock,
            "package-lock.json",
            &[("left-pad", "1.3.0")],
        );
        l.members = vec!["packages/api".to_owned()];
        let r = reconcile(&[m], &[Ok(l)]);
        assert_eq!(r.gaps.len(), 0);
        assert_eq!(names(&r.dependencies), [("left-pad", "1.3.0")]);
    }

    #[test]
    fn non_member_nested_manifest_is_uncovered() {
        let m = manifest(
            "tools/cli/package.json",
            Ecosystem::Npm,
            vec![],
            vec![range("left-pad", "tools/cli/package.json")],
        );
        let mut l = lock(
            LockKind::NpmPackageLock,
            "package-lock.json",
            &[("left-pad", "1.3.0")],
        );
        l.members = vec!["packages/api".to_owned()];
        let r = reconcile(&[m], &[Ok(l)]);
        assert_eq!(gap_names(&r.gaps), ["left-pad"]);
    }

    #[test]
    fn workspace_glob_covers_matching_dirs_only() {
        let inside = manifest(
            "packages/web/package.json",
            Ecosystem::Npm,
            vec![],
            vec![range("react", "packages/web/package.json")],
        );
        let outside = manifest(
            "other/web/package.json",
            Ecosystem::Npm,
            vec![],
            vec![range("react", "other/web/package.json")],
        );
        let mut l = lock(LockKind::Pnpm, "pnpm-lock.yaml", &[("react", "18.2.0")]);
        l.workspace_globs = vec!["packages/*".to_owned(), "!packages/skip".to_owned()];
        let r = reconcile(&[inside, outside], &[Ok(l)]);
        assert_eq!(r.gaps.len(), 1);
        assert_eq!(r.gaps[0].file, PathBuf::from("other/web/package.json"));
    }

    #[test]
    fn glob_matcher_cases() {
        assert!(glob_matches("packages/**", &["packages", "a", "b"]));
        assert!(glob_matches("./apps/*-web", &["apps", "x-web"]));
        assert!(glob_matches("a/*", &["a", "b"]));
        assert!(!glob_matches("a/*", &["a", "b", "c"]));
        assert!(!glob_matches("a/*", &["a"]));
        assert!(glob_matches("**/x", &["x"]));
        assert!(glob_matches("pre*", &["prefix"]));
        assert!(!glob_matches("pre*", &["xpre"]));
    }

    #[test]
    fn dep_absent_from_lock_keeps_gap() {
        let m = manifest(
            "pyproject.toml",
            Ecosystem::PyPi,
            vec![],
            vec![
                range("requests", "pyproject.toml"),
                range("ruff", "pyproject.toml"),
            ],
        );
        let l = lock(LockKind::Uv, "uv.lock", &[("requests", "2.31.0")]);
        let r = reconcile(&[m], &[Ok(l)]);
        assert_eq!(gap_names(&r.gaps), ["ruff"]);
    }

    #[test]
    fn pypi_names_are_normalised() {
        let m = manifest(
            "pyproject.toml",
            Ecosystem::PyPi,
            vec![],
            vec![range("Typing_Extensions", "pyproject.toml")],
        );
        let l = lock(LockKind::Uv, "uv.lock", &[("typing-extensions", "4.12.0")]);
        let r = reconcile(&[m], &[Ok(l)]);
        assert_eq!(r.gaps.len(), 0);
        assert_eq!(normalise(Ecosystem::PyPi, "A..b__C"), "a-b-c");
        assert_eq!(normalise(Ecosystem::Npm, "Foo_Bar"), "Foo_Bar");
    }

    #[test]
    fn manifest_pin_is_replaced_by_lock_version() {
        let m = manifest(
            "pyproject.toml",
            Ecosystem::PyPi,
            vec![dep("flask", "2.0.0", Ecosystem::PyPi, "pyproject.toml")],
            vec![],
        );
        let l = lock(LockKind::Uv, "uv.lock", &[("flask", "3.0.0")]);
        let r = reconcile(&[m], &[Ok(l)]);
        assert_eq!(names(&r.dependencies), [("flask", "3.0.0")]);
    }

    #[test]
    fn malformed_lock_is_reported_and_manifest_falls_back() {
        let m = manifest(
            "pyproject.toml",
            Ecosystem::PyPi,
            vec![dep("flask", "2.0.0", Ecosystem::PyPi, "pyproject.toml")],
            vec![range("requests", "pyproject.toml")],
        );
        let err = LockError::Malformed {
            file: PathBuf::from("uv.lock"),
            reason: "bad".to_owned(),
        };
        let r = reconcile(&[m], &[Err(err.clone())]);
        assert_eq!(r.lock_errors, [err]);
        assert_eq!(names(&r.dependencies), [("flask", "2.0.0")]);
        assert_eq!(gap_names(&r.gaps), ["requests"]);
    }

    #[test]
    fn uv_preferred_over_poetry_in_same_dir() {
        let m = manifest(
            "pyproject.toml",
            Ecosystem::PyPi,
            vec![],
            vec![range("requests", "pyproject.toml")],
        );
        let poetry = lock(
            LockKind::Poetry,
            "poetry.lock",
            &[("requests", "2.0.0"), ("only-poetry", "1.0")],
        );
        let uv = lock(LockKind::Uv, "uv.lock", &[("requests", "2.31.0")]);
        let r = reconcile(&[m], &[Ok(poetry), Ok(uv)]);
        assert_eq!(names(&r.dependencies), [("requests", "2.31.0")]);
        assert_eq!(r.gaps.len(), 0);
    }

    #[test]
    fn nearest_directory_wins() {
        let m = manifest(
            "svc/pyproject.toml",
            Ecosystem::PyPi,
            vec![],
            vec![range("requests", "svc/pyproject.toml")],
        );
        let mut root = lock(LockKind::Uv, "uv.lock", &[("requests", "1.0.0")]);
        root.members = vec!["svc".to_owned()];
        let near = lock(
            LockKind::Poetry,
            "svc/poetry.lock",
            &[("requests", "2.0.0")],
        );
        let r = reconcile(&[m], &[Ok(root), Ok(near)]);
        // Both locks contribute (different directories), and the manifest gap is dropped.
        assert_eq!(r.gaps.len(), 0);
        assert_eq!(
            names(&r.dependencies),
            [("requests", "1.0.0"), ("requests", "2.0.0")]
        );
    }

    #[test]
    fn nearest_lock_decides_coverage() {
        // The nearer lock lacks the name, so the gap stays even though the
        // farther lock records it.
        let m = manifest(
            "svc/pyproject.toml",
            Ecosystem::PyPi,
            vec![],
            vec![range("requests", "svc/pyproject.toml")],
        );
        let mut root = lock(LockKind::Uv, "uv.lock", &[("requests", "1.0.0")]);
        root.members = vec!["svc".to_owned()];
        let near = lock(LockKind::Poetry, "svc/poetry.lock", &[("other", "2.0.0")]);
        let r = reconcile(&[m], &[Ok(root), Ok(near)]);
        assert_eq!(gap_names(&r.gaps), ["requests"]);
    }

    #[test]
    fn lock_only_repo_contributes() {
        let mut l = lock(LockKind::Pnpm, "pnpm-lock.yaml", &[("react", "18.2.0")]);
        l.unresolved_sources.push(UnresolvedSource {
            name: "pkg".to_owned(),
            source: "git".to_owned(),
            file: PathBuf::from("pnpm-lock.yaml"),
            line: 3,
        });
        let r = reconcile(&[], &[Ok(l)]);
        assert_eq!(names(&r.dependencies), [("react", "18.2.0")]);
        assert_eq!(r.unresolved_sources.len(), 1);
    }

    #[test]
    fn cargo_manifest_is_unaffected() {
        let m = manifest(
            "Cargo.toml",
            Ecosystem::CratesIo,
            vec![dep("serde", "1.0.0", Ecosystem::CratesIo, "Cargo.toml")],
            vec![range("tokio", "Cargo.toml")],
        );
        let l = lock(
            LockKind::Uv,
            "uv.lock",
            &[("serde", "9.9.9"), ("tokio", "9.9.9")],
        );
        let r = reconcile(&[m], &[Ok(l)]);
        assert_eq!(gap_names(&r.gaps), ["tokio"]);
        assert_eq!(
            names(&r.dependencies),
            [("serde", "1.0.0"), ("serde", "9.9.9"), ("tokio", "9.9.9")]
        );
    }

    #[test]
    fn output_order_is_manifests_then_locks() {
        let m1 = manifest(
            "a/package.json",
            Ecosystem::Npm,
            vec![dep("m1", "1.0.0", Ecosystem::Npm, "a/package.json")],
            vec![range("g1", "a/package.json")],
        );
        let m2 = manifest(
            "b/package.json",
            Ecosystem::Npm,
            vec![dep("m2", "1.0.0", Ecosystem::Npm, "b/package.json")],
            vec![range("g2", "b/package.json")],
        );
        let l1 = lock(
            LockKind::NpmPackageLock,
            "x/package-lock.json",
            &[("l1", "1.0.0")],
        );
        let l2 = lock(
            LockKind::NpmPackageLock,
            "y/package-lock.json",
            &[("l2", "1.0.0")],
        );
        let err = LockError::Unsupported {
            file: PathBuf::from("z/yarn.lock"),
            reason: "v".to_owned(),
        };
        let r = reconcile(&[m1, m2], &[Ok(l1), Err(err.clone()), Ok(l2)]);
        assert_eq!(
            names(&r.dependencies),
            [
                ("m1", "1.0.0"),
                ("m2", "1.0.0"),
                ("l1", "1.0.0"),
                ("l2", "1.0.0")
            ]
        );
        assert_eq!(gap_names(&r.gaps), ["g1", "g2"]);
        assert_eq!(r.lock_errors, [err]);
    }
}
