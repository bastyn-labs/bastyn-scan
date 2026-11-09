//! `pnpm-lock.yaml` parser.
//!
//! Reads lockfile versions 5, 6 and 9. The `packages` mapping holds one record
//! per resolved package; its key encodes the name and version in a shape that
//! differs by lockfile version, and its `resolution` mapping says where the
//! package came from. The `importers` mapping, when present, lists the project
//! directories the lockfile covers.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde_yaml_ng::{Mapping, Value};

use super::{LockError, LockKind, Lockfile, UnresolvedSource};
use crate::cve::manifest::{Dependency, Ecosystem};

/// Where a package record says its contents come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// A registry tarball with an integrity hash.
    Registry,
    /// A git repository or commit.
    Git,
    /// A local directory.
    Path,
    /// A tarball URL without an integrity hash.
    Url,
}

impl Source {
    /// The label stored in [`UnresolvedSource::source`], or `None` for a
    /// registry package.
    const fn label(self) -> Option<&'static str> {
        match self {
            Self::Registry => None,
            Self::Git => Some("git"),
            Self::Path => Some("path"),
            Self::Url => Some("url"),
        }
    }
}

/// Parse the lockfile.
pub(super) fn parse(relative_path: &Path, contents: &str) -> Result<Lockfile, LockError> {
    let malformed = |reason: String| LockError::Malformed {
        file: relative_path.to_path_buf(),
        reason,
    };
    let document: Value = serde_yaml_ng::from_str(contents)
        .map_err(|error| malformed(format!("invalid YAML: {error}")))?;
    let Value::Mapping(root) = document else {
        return Err(malformed("top level is not a mapping".to_owned()));
    };

    let version_text = match root.get("lockfileVersion") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => return Err(malformed("missing lockfileVersion".to_owned())),
    };
    let major = version_text
        .split('.')
        .next()
        .and_then(|part| part.trim().parse::<u64>().ok())
        .ok_or_else(|| malformed(format!("unreadable lockfileVersion {version_text}")))?;
    if !matches!(major, 5 | 6 | 9) {
        return Err(LockError::Unsupported {
            file: relative_path.to_path_buf(),
            reason: format!("lockfileVersion {version_text}"),
        });
    }

    let members = members(root.get("importers"));

    let records = match root.get("packages") {
        None | Some(Value::Null) => None,
        Some(Value::Mapping(records)) => Some(records),
        Some(_) => return Err(malformed("`packages` is not a mapping".to_owned())),
    };

    let mut packages = Vec::new();
    let mut unresolved_sources = Vec::new();
    if let Some(records) = records.filter(|records| !records.is_empty()) {
        let lines = record_lines(contents);
        let file = relative_path.to_path_buf();
        let mut seen_packages: HashSet<(String, String)> = HashSet::new();
        let mut seen_unresolved: HashSet<(String, &'static str)> = HashSet::new();
        for (key, record) in records {
            let Some(key) = key.as_str() else { continue };
            let (name, version) = split_key(key, major);
            let mut source = classify(record);
            if source == Source::Registry && !is_exact_version(&version) {
                source = Source::Url;
            }
            let line = lines.get(key).copied().unwrap_or(1);
            if let Some(label) = source.label() {
                if seen_unresolved.insert((name.clone(), label)) {
                    unresolved_sources.push(UnresolvedSource {
                        name,
                        source: label.to_owned(),
                        file: file.clone(),
                        line,
                    });
                }
            } else if seen_packages.insert((name.clone(), version.clone())) {
                packages.push(Dependency {
                    name,
                    version,
                    ecosystem: Ecosystem::Npm,
                    file: file.clone(),
                    line,
                    declaration: declaration_at(contents, line),
                });
            }
        }
    }

    Ok(Lockfile {
        kind: LockKind::Pnpm,
        file: relative_path.to_path_buf(),
        packages,
        unresolved_sources,
        members,
        workspace_globs: Vec::new(),
    })
}

/// Project directories listed under `importers`, other than the root.
fn members(importers: Option<&Value>) -> Vec<String> {
    let Some(Value::Mapping(importers)) = importers else {
        return Vec::new();
    };
    let mut members: Vec<String> = Vec::new();
    for key in importers.keys().filter_map(Value::as_str) {
        let mut directory = key.replace('\\', "/");
        while let Some(rest) = directory.strip_prefix("./") {
            directory = rest.to_owned();
        }
        let directory = directory.trim_end_matches('/');
        if directory.is_empty() || directory == "." {
            continue;
        }
        if !members.iter().any(|existing| existing == directory) {
            members.push(directory.to_owned());
        }
    }
    members
}

/// Classify a package record by its `resolution` mapping.
fn classify(record: &Value) -> Source {
    let Some(Value::Mapping(resolution)) = record.get("resolution") else {
        return Source::Registry;
    };
    let has = |field: &str| has_field(resolution, field);
    if has("repo") || has("commit") {
        Source::Git
    } else if has("directory") {
        Source::Path
    } else if has("tarball") && !has("integrity") {
        Source::Url
    } else {
        Source::Registry
    }
}

/// True if `mapping` has `field` with a non-null value.
fn has_field(mapping: &Mapping, field: &str) -> bool {
    mapping.get(field).is_some_and(|value| !value.is_null())
}

/// Split a `packages` key into `(name, version)`.
///
/// Version 9 keys look like `name@1.2.3`; version 6 keys add a leading slash
/// and may end in a parenthesised peer suffix; version 5 keys look like
/// `/name/1.2.3` with an optional `_peer` suffix on the version. A key that
/// does not fit its version's shape comes back whole as the name with an empty
/// version.
fn split_key(key: &str, major: u64) -> (String, String) {
    if major == 5 {
        return split_key_v5(key);
    }
    let trimmed = key.strip_prefix('/').unwrap_or(key);
    let trimmed = trimmed.split_once('(').map_or(trimmed, |(head, _)| head);
    // A package name has no `@` except a scope prefix, so the first `@` after
    // the first character separates name from version even when the version
    // part is a URL that contains further `@` characters.
    let separator = trimmed
        .char_indices()
        .skip(1)
        .find(|&(_, character)| character == '@')
        .map(|(index, _)| index);
    match separator {
        Some(index) if index > 0 => (trimmed[..index].to_owned(), trimmed[index + 1..].to_owned()),
        _ => (key.to_owned(), String::new()),
    }
}

/// Version 5 form of [`split_key`].
fn split_key_v5(key: &str) -> (String, String) {
    let Some(rest) = key.strip_prefix('/') else {
        return (key.to_owned(), String::new());
    };
    match rest.rsplit_once('/') {
        Some((name, version)) if !name.is_empty() => {
            let version = version.split_once('_').map_or(version, |(head, _)| head);
            (name.to_owned(), version.to_owned())
        }
        _ => (key.to_owned(), String::new()),
    }
}

/// True if `version` looks like one exact version rather than a URL, a path
/// or a range.
fn is_exact_version(version: &str) -> bool {
    version.starts_with(|character: char| character.is_ascii_digit())
        && !version.contains(['/', ':'])
}

/// Map each key of the top-level `packages:` section to its 1-indexed line,
/// in one pass over the text. Only lines at the section's first indentation
/// level count as keys; the first line seen for a key wins.
fn record_lines(contents: &str) -> HashMap<String, usize> {
    let mut lines = HashMap::new();
    let mut in_section = false;
    let mut key_indent: Option<usize> = None;
    for (index, line) in contents.lines().enumerate() {
        let text = line.trim_end();
        if !in_section {
            if text == "packages:" {
                in_section = true;
            }
            continue;
        }
        let trimmed = text.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = text.len() - trimmed.len();
        if indent == 0 {
            break;
        }
        let expected = *key_indent.get_or_insert(indent);
        if indent != expected || trimmed.starts_with("- ") {
            continue;
        }
        if let Some(key) = key_text(trimmed) {
            lines.entry(key).or_insert(index + 1);
        }
    }
    lines
}

/// The key of a `key:` or `key: value` line, with any quoting removed.
fn key_text(line: &str) -> Option<String> {
    if let Some(quote) = line.chars().next().filter(|c| matches!(c, '\'' | '"')) {
        let body = &line[1..];
        let mut key = String::new();
        let mut chars = body.char_indices().peekable();
        while let Some((index, character)) = chars.next() {
            if character == quote {
                if quote == '\'' && chars.peek().is_some_and(|&(_, next)| next == '\'') {
                    key.push('\'');
                    chars.next();
                    continue;
                }
                let after = body[index + 1..].trim_start();
                return after.starts_with(':').then_some(key);
            }
            if character == '\\' && quote == '"' {
                if let Some((_, escaped)) = chars.next() {
                    key.push(escaped);
                }
                continue;
            }
            key.push(character);
        }
        return None;
    }
    if let Some((key, _)) = line.split_once(": ") {
        return Some(key.to_owned());
    }
    line.strip_suffix(':').map(str::to_owned)
}

/// The trimmed text of 1-indexed `line`, or an empty string past the end.
fn declaration_at(contents: &str, line: usize) -> String {
    contents
        .lines()
        .nth(line.saturating_sub(1))
        .map(|text| text.trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn run(contents: &str) -> Result<Lockfile, LockError> {
        parse(Path::new("pnpm-lock.yaml"), contents)
    }

    fn names(lockfile: &Lockfile) -> Vec<(&str, &str)> {
        lockfile
            .packages
            .iter()
            .map(|dep| (dep.name.as_str(), dep.version.as_str()))
            .collect()
    }

    const V9: &str = "\
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      left-pad:
        specifier: ^1.3.0
        version: 1.3.0

  packages/api:
    dependencies:
      '@scope/util':
        specifier: ^2.0.0
        version: 2.0.1

packages:

  '@scope/util@2.0.1':
    resolution: {integrity: sha512-aaa}

  left-pad@1.3.0:
    resolution: {integrity: sha512-bbb}
    deprecated: use String.prototype.padStart()

  react-dom@18.2.0:
    resolution: {integrity: sha512-ccc}
    peerDependencies:
      react: ^18.2.0

snapshots:

  '@scope/util@2.0.1': {}

  left-pad@1.3.0: {}

  react-dom@18.2.0(react@18.2.0): {}
";

    #[test]
    fn parses_v9_packages_and_members() {
        let lockfile = run(V9).expect("parses");
        assert_eq!(lockfile.kind, LockKind::Pnpm);
        assert_eq!(
            names(&lockfile),
            vec![
                ("@scope/util", "2.0.1"),
                ("left-pad", "1.3.0"),
                ("react-dom", "18.2.0"),
            ]
        );
        assert_eq!(lockfile.members, vec!["packages/api".to_owned()]);
        assert_eq!(lockfile.unresolved_sources.len(), 0);
        assert_eq!(lockfile.workspace_globs.len(), 0);
        assert_eq!(lockfile.packages[0].ecosystem, Ecosystem::Npm);
        assert_eq!(lockfile.packages[0].file, Path::new("pnpm-lock.yaml"));
    }

    #[test]
    fn reports_line_numbers_within_packages_section() {
        let lockfile = run(V9).expect("parses");
        let lines: Vec<usize> = lockfile.packages.iter().map(|dep| dep.line).collect();
        let expected: Vec<usize> = [
            "  '@scope/util@2.0.1':",
            "  left-pad@1.3.0:",
            "  react-dom@18.2.0:",
        ]
        .iter()
        .map(|needle| {
            V9.lines()
                .position(|line| line == *needle)
                .expect("present")
                + 1
        })
        .collect();
        assert_eq!(lines, expected);
        assert_eq!(lockfile.packages[1].declaration, "left-pad@1.3.0:");
        // The same key under `snapshots:` is not mistaken for the record.
        assert!(lockfile.packages.iter().all(|dep| dep.line < 30));
    }

    #[test]
    fn parses_v6_with_leading_slash_and_peer_suffix() {
        let lockfile = run("\
lockfileVersion: '6.0'

packages:

  /@babel/core@7.22.0(supports-color@8.1.1):
    resolution: {integrity: sha512-a}
    dev: true

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-b}
    dev: false
")
        .expect("parses");
        assert_eq!(
            names(&lockfile),
            vec![("@babel/core", "7.22.0"), ("react-dom", "18.2.0")]
        );
        assert_eq!(lockfile.members.len(), 0);
    }

    #[test]
    fn parses_v5_slash_separated_keys() {
        let lockfile = run("\
lockfileVersion: 5.4

specifiers:
  foo: ^1.0.0

packages:

  /@scope/name/1.2.3:
    resolution: {integrity: sha512-a}
    dev: false

  /foo/1.0.0_react@18.0.0:
    resolution: {integrity: sha512-b}
    dev: false

  /bar/2.0.0:
    resolution: {integrity: sha512-c, tarball: https://registry.example.com/bar.tgz}
    dev: false
")
        .expect("parses");
        assert_eq!(
            names(&lockfile),
            vec![("@scope/name", "1.2.3"), ("foo", "1.0.0"), ("bar", "2.0.0")]
        );
    }

    #[test]
    fn v5_multi_project_importers_become_members() {
        let lockfile = run("\
lockfileVersion: 5.3

importers:
  .:
    specifiers: {}
  ./tools/cli:
    specifiers: {}
  packages/api:
    specifiers: {}
")
        .expect("parses");
        assert_eq!(
            lockfile.members,
            vec!["tools/cli".to_owned(), "packages/api".to_owned()]
        );
        assert_eq!(lockfile.packages.len(), 0);
    }

    #[test]
    fn non_registry_resolutions_are_unresolved_sources() {
        let lockfile = run("\
lockfileVersion: '9.0'

packages:

  from-git@https://codeload.github.com/org/from-git/tar.gz/abc123:
    resolution: {tarball: https://codeload.github.com/org/from-git/tar.gz/abc123}
    version: 1.0.0

  git-repo@github.com/org/git-repo/0123456789abcdef:
    resolution: {commit: 0123456789abcdef, repo: https://github.com/org/git-repo.git, type: git}
    version: 1.0.0

  local-dir@file:../local-dir:
    resolution: {directory: ../local-dir, type: directory}

  url-pkg@1.0.0:
    resolution: {tarball: https://example.com/url-pkg-1.0.0.tgz}

  plain@1.0.0:
    resolution: {integrity: sha512-a}
")
        .expect("parses");
        assert_eq!(names(&lockfile), vec![("plain", "1.0.0")]);
        let found: Vec<(&str, &str)> = lockfile
            .unresolved_sources
            .iter()
            .map(|source| (source.name.as_str(), source.source.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("from-git", "url"),
                ("git-repo", "git"),
                ("local-dir", "path"),
                ("url-pkg", "url"),
            ]
        );
        assert_eq!(lockfile.unresolved_sources[0].line, 5);
    }

    #[test]
    fn registry_key_with_url_version_is_unresolved() {
        let lockfile = run("\
lockfileVersion: '9.0'

packages:

  name@https://example.com/x.tgz:
    resolution: {integrity: sha512-a, tarball: https://example.com/x.tgz}
")
        .expect("parses");
        assert_eq!(lockfile.packages.len(), 0);
        assert_eq!(lockfile.unresolved_sources.len(), 1);
        assert_eq!(lockfile.unresolved_sources[0].name, "name");
        assert_eq!(lockfile.unresolved_sources[0].source, "url");
    }

    #[test]
    fn v5_unparseable_key_uses_whole_key_as_name() {
        let lockfile = run("\
lockfileVersion: 5.4

packages:

  github.com/org/repo/0123abc:
    resolution: {tarball: https://codeload.github.com/org/repo/tar.gz/0123abc}
    name: repo
    version: 1.0.0
")
        .expect("parses");
        assert_eq!(lockfile.packages.len(), 0);
        assert_eq!(
            lockfile.unresolved_sources[0].name,
            "github.com/org/repo/0123abc"
        );
        assert_eq!(lockfile.unresolved_sources[0].source, "url");
    }

    #[test]
    fn deduplicates_by_name_and_version_keeping_first() {
        let lockfile = run("\
lockfileVersion: '6.0'

packages:

  /a@1.0.0(x@1.0.0):
    resolution: {integrity: sha512-a}

  /b@1.0.0:
    resolution: {integrity: sha512-b}

  /a@1.0.0(y@1.0.0):
    resolution: {integrity: sha512-a}

  /a@2.0.0:
    resolution: {integrity: sha512-c}
")
        .expect("parses");
        assert_eq!(
            names(&lockfile),
            vec![("a", "1.0.0"), ("b", "1.0.0"), ("a", "2.0.0")]
        );
        assert_eq!(lockfile.packages[0].line, 5);
    }

    #[test]
    fn unsupported_major_version() {
        for text in ["'10.0'", "4"] {
            let error = run(&format!("lockfileVersion: {text}\n")).expect_err("unsupported");
            assert!(matches!(error, LockError::Unsupported { .. }), "{text}");
        }
        let LockError::Unsupported { reason, .. } =
            run("lockfileVersion: '10.0'\n").expect_err("unsupported")
        else {
            panic!("expected Unsupported");
        };
        assert_eq!(reason, "lockfileVersion 10.0");
    }

    #[test]
    fn malformed_inputs() {
        for text in [
            "lockfileVersion: [unclosed\n  - x: : :\n",
            "- just\n- a list\n",
            "packages:\n  a@1.0.0:\n    resolution: {integrity: x}\n",
            "lockfileVersion: banana\n",
            "lockfileVersion: '9.0'\npackages: 3\n",
        ] {
            let error = run(text).expect_err("malformed");
            assert!(matches!(error, LockError::Malformed { .. }), "{text}");
        }
    }

    #[test]
    fn lockfile_without_packages_is_empty() {
        let lockfile = run("lockfileVersion: '9.0'\n").expect("parses");
        assert_eq!(lockfile.packages.len(), 0);
        assert_eq!(lockfile.unresolved_sources.len(), 0);
        assert_eq!(lockfile.members.len(), 0);
    }

    #[test]
    fn key_text_handles_quoting() {
        assert_eq!(key_text("'@a/b@1.0.0':").as_deref(), Some("@a/b@1.0.0"));
        assert_eq!(key_text("\"x@1\": {}").as_deref(), Some("x@1"));
        assert_eq!(key_text("'it''s@1.0.0':").as_deref(), Some("it's@1.0.0"));
        assert_eq!(key_text("a@1.0.0: {}").as_deref(), Some("a@1.0.0"));
        assert_eq!(key_text("a@1.0.0:").as_deref(), Some("a@1.0.0"));
        assert_eq!(key_text("'unterminated").as_deref(), None);
    }
}
