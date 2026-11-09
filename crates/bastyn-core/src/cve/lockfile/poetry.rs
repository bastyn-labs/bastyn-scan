//! `poetry.lock` parser.
//!
//! The file is TOML: one `[[package]]` table per resolved package with a
//! `name` and an exact `version`, and an optional `[package.source]` table.
//! A package with no source table, or a `legacy` source (a package index), is
//! a registry package. Any other source type resolves to something other than
//! a registry version and is reported as an [`UnresolvedSource`].

use std::collections::HashSet;
use std::path::Path;

use super::{Dependency, Ecosystem, LockError, LockKind, Lockfile, UnresolvedSource};

/// The lock-file format major versions this parser reads.
const SUPPORTED_MAJORS: [&str; 2] = ["1", "2"];

/// Parse the lockfile.
pub(super) fn parse(relative_path: &Path, contents: &str) -> Result<Lockfile, LockError> {
    let malformed = |reason: String| LockError::Malformed {
        file: relative_path.to_path_buf(),
        reason,
    };
    let unsupported = |reason: String| LockError::Unsupported {
        file: relative_path.to_path_buf(),
        reason,
    };

    let root: toml::Table = contents
        .parse()
        .map_err(|err: toml::de::Error| malformed(format!("invalid TOML: {}", err.message())))?;

    let lock_version = root
        .get("metadata")
        .and_then(toml::Value::as_table)
        .and_then(|metadata| metadata.get("lock-version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| unsupported("no lock-version".to_owned()))?;
    let major = lock_version.split('.').next().unwrap_or_default();
    if !SUPPORTED_MAJORS.contains(&major) {
        return Err(unsupported(format!(
            "poetry.lock lock-version {lock_version}"
        )));
    }

    let records: &[toml::Value] = match root.get("package") {
        None => &[],
        Some(toml::Value::Array(records)) => records,
        Some(_) => return Err(malformed("`package` is not an array of tables".to_owned())),
    };
    let lines = record_lines(contents);
    let lines_match = lines.len() == records.len();

    let mut packages = Vec::new();
    let mut unresolved_sources = Vec::new();
    let mut seen_packages: HashSet<(String, String)> = HashSet::new();
    let mut seen_unresolved: HashSet<(String, String)> = HashSet::new();

    for (index, record) in records.iter().enumerate() {
        let table = record
            .as_table()
            .ok_or_else(|| malformed("package record is not a table".to_owned()))?;
        let name = string_field(table, "name")
            .ok_or_else(|| malformed("package record without a name".to_owned()))?;
        let version = string_field(table, "version")
            .ok_or_else(|| malformed(format!("package `{name}` without a version")))?;
        let (line, declaration) = if lines_match {
            lines[index].clone()
        } else {
            (
                1,
                contents
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
            )
        };

        let source = table
            .get("source")
            .and_then(toml::Value::as_table)
            .and_then(|source| string_field(source, "type"));
        match source {
            None | Some("legacy") => {
                if seen_packages.insert((name.to_owned(), version.to_owned())) {
                    packages.push(Dependency {
                        name: name.to_owned(),
                        version: version.to_owned(),
                        ecosystem: Ecosystem::PyPi,
                        file: relative_path.to_path_buf(),
                        line,
                        declaration,
                    });
                }
            }
            Some(kind) => {
                let source = match kind {
                    "file" => "path",
                    other => other,
                };
                if seen_unresolved.insert((name.to_owned(), source.to_owned())) {
                    unresolved_sources.push(UnresolvedSource {
                        name: name.to_owned(),
                        source: source.to_owned(),
                        file: relative_path.to_path_buf(),
                        line,
                    });
                }
            }
        }
    }

    Ok(Lockfile {
        kind: LockKind::Poetry,
        file: relative_path.to_path_buf(),
        packages,
        unresolved_sources,
        members: Vec::new(),
        workspace_globs: Vec::new(),
    })
}

/// A string-valued key of a table.
fn string_field<'a>(table: &'a toml::Table, key: &str) -> Option<&'a str> {
    table.get(key).and_then(toml::Value::as_str)
}

/// The 1-indexed line and trimmed text of each package record's `name = ...`
/// entry (or of its `[[package]]` header if it has none), in file order, found
/// in one forward pass.
fn record_lines(contents: &str) -> Vec<(usize, String)> {
    let mut records: Vec<(usize, String)> = Vec::new();
    let mut awaiting_name = false;
    for (index, raw) in contents.lines().enumerate() {
        let text = raw.trim();
        if text == "[[package]]" {
            records.push((index + 1, text.to_owned()));
            awaiting_name = true;
        } else if text.starts_with('[') {
            awaiting_name = false;
        } else if awaiting_name && is_name_entry(text) {
            if let Some(last) = records.last_mut() {
                *last = (index + 1, text.to_owned());
            }
            awaiting_name = false;
        }
    }
    records
}

/// True if a trimmed line is a `name = ...` key assignment.
fn is_name_entry(text: &str) -> bool {
    text.strip_prefix("name")
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    const LOCK: &str = r#"# This file is automatically @generated by Poetry 2.1.0 and should not be changed by hand.

[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
files = []

[package.dependencies]
certifi = ">=2017.4.17"
urllib3 = ">=1.21.1,<3"

[[package]]
name = "certifi"
version = "2024.2.2"
description = "Certificates"
optional = false
python-versions = ">=3.6"
files = []

[[package]]
name = "urllib3"
version = "2.2.1"
description = "HTTP library"
optional = false
python-versions = ">=3.8"
files = []

[metadata]
lock-version = "2.1"
python-versions = "^3.11"
content-hash = "abc"
"#;

    fn parse_str(contents: &str) -> Result<Lockfile, LockError> {
        parse(Path::new("poetry.lock"), contents)
    }

    fn with_metadata(body: &str) -> String {
        format!("{body}\n[metadata]\nlock-version = \"2.1\"\n")
    }

    #[test]
    fn registry_packages_including_transitive() {
        let lock = parse_str(LOCK).unwrap();
        assert_eq!(lock.kind, LockKind::Poetry);
        assert_eq!(lock.file, Path::new("poetry.lock"));
        let pairs: Vec<(&str, &str)> = lock
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("requests", "2.31.0"),
                ("certifi", "2024.2.2"),
                ("urllib3", "2.2.1")
            ]
        );
        assert!(lock.packages.iter().all(|p| p.ecosystem == Ecosystem::PyPi));
        assert_eq!(lock.unresolved_sources.len(), 0);
        assert_eq!(lock.members.len(), 0);
        assert_eq!(lock.workspace_globs.len(), 0);
    }

    #[test]
    fn line_numbers_point_at_name_entries() {
        let lock = parse_str(LOCK).unwrap();
        let lines: Vec<(usize, &str)> = lock
            .packages
            .iter()
            .map(|p| (p.line, p.declaration.as_str()))
            .collect();
        assert_eq!(
            lines,
            [
                (4, "name = \"requests\""),
                (16, "name = \"certifi\""),
                (24, "name = \"urllib3\"")
            ]
        );
        for package in &lock.packages {
            assert_eq!(
                LOCK.lines().nth(package.line - 1).unwrap().trim(),
                package.declaration
            );
        }
    }

    #[test]
    fn legacy_source_is_a_registry_package() {
        let contents = with_metadata(
            r#"[[package]]
name = "internal"
version = "1.0.0"

[package.source]
type = "legacy"
url = "https://example.com/simple"
reference = "private"
"#,
        );
        let lock = parse_str(&contents).unwrap();
        assert_eq!(lock.packages.len(), 1);
        assert_eq!(lock.packages[0].name, "internal");
        assert_eq!(lock.unresolved_sources.len(), 0);
    }

    #[test]
    fn non_registry_sources_are_unresolved() {
        let contents = with_metadata(
            r#"[[package]]
name = "from-git"
version = "0.1.0"

[package.source]
type = "git"
url = "https://example.com/repo.git"
reference = "main"
resolved_reference = "0123456789abcdef"

[[package]]
name = "from-url"
version = "0.2.0"

[package.source]
type = "url"
url = "https://example.com/pkg.whl"

[[package]]
name = "from-dir"
version = "0.3.0"

[package.source]
type = "directory"
url = "../local"

[[package]]
name = "from-file"
version = "0.4.0"

[package.source]
type = "file"
url = "dist/pkg.tar.gz"

[[package]]
name = "from-other"
version = "0.5.0"

[package.source]
type = "mystery"
url = "x"
"#,
        );
        let lock = parse_str(&contents).unwrap();
        assert_eq!(lock.packages.len(), 0);
        let found: Vec<(&str, &str, usize)> = lock
            .unresolved_sources
            .iter()
            .map(|u| (u.name.as_str(), u.source.as_str(), u.line))
            .collect();
        assert_eq!(
            found,
            [
                ("from-git", "git", 2),
                ("from-url", "url", 12),
                ("from-dir", "directory", 20),
                ("from-file", "path", 28),
                ("from-other", "mystery", 36)
            ]
        );
        assert!(
            lock.unresolved_sources
                .iter()
                .all(|u| u.file == Path::new("poetry.lock"))
        );
    }

    #[test]
    fn duplicates_keep_the_first() {
        let contents = with_metadata(
            r#"[[package]]
name = "dup"
version = "1.0.0"

[[package]]
name = "dup"
version = "1.0.0"

[[package]]
name = "dup"
version = "2.0.0"

[[package]]
name = "g"
version = "1"

[package.source]
type = "git"
url = "a"

[[package]]
name = "g"
version = "2"

[package.source]
type = "git"
url = "b"
"#,
        );
        let lock = parse_str(&contents).unwrap();
        let pairs: Vec<(&str, &str, usize)> = lock
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.line))
            .collect();
        assert_eq!(pairs, [("dup", "1.0.0", 2), ("dup", "2.0.0", 10)]);
        assert_eq!(lock.unresolved_sources.len(), 1);
        assert_eq!(lock.unresolved_sources[0].line, 14);
    }

    #[test]
    fn older_supported_major_is_read() {
        let contents =
            "[[package]]\nname = \"a\"\nversion = \"1\"\n\n[metadata]\nlock-version = \"1.1\"\n";
        assert_eq!(parse_str(contents).unwrap().packages.len(), 1);
    }

    #[test]
    fn newer_major_is_unsupported() {
        let contents = "[metadata]\nlock-version = \"3.0\"\n";
        match parse_str(contents) {
            Err(LockError::Unsupported { reason, .. }) => {
                assert_eq!(reason, "poetry.lock lock-version 3.0");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn missing_metadata_is_unsupported() {
        let contents = "[[package]]\nname = \"a\"\nversion = \"1\"\n";
        match parse_str(contents) {
            Err(LockError::Unsupported { reason, .. }) => assert_eq!(reason, "no lock-version"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
        match parse_str("[metadata]\ncontent-hash = \"x\"\n") {
            Err(LockError::Unsupported { reason, .. }) => assert_eq!(reason, "no lock-version"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn invalid_toml_is_malformed() {
        let result = parse_str("[[package]\nname = ");
        assert!(
            matches!(result, Err(LockError::Malformed { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn package_without_version_is_malformed() {
        let contents = with_metadata("[[package]]\nname = \"a\"\n");
        let result = parse_str(&contents);
        assert!(
            matches!(result, Err(LockError::Malformed { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn package_without_name_is_malformed() {
        let contents = with_metadata("[[package]]\nversion = \"1\"\n");
        let result = parse_str(&contents);
        assert!(
            matches!(result, Err(LockError::Malformed { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn lockfile_without_packages_is_empty() {
        let lock = parse_str("[metadata]\nlock-version = \"2.0\"\n").unwrap();
        assert_eq!(lock.packages.len(), 0);
        assert_eq!(lock.unresolved_sources.len(), 0);
    }
}
