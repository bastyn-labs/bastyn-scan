//! `uv` lockfile parser.
//!
//! `uv.lock` is TOML: a top-level integer `version` and an array of
//! `[[package]]` tables. Each record has a `name`, an optional `version` and a
//! `source` inline table with exactly one key naming where it resolves from.

use std::collections::HashSet;
use std::path::Path;

use super::{Dependency, Ecosystem, LockError, LockKind, Lockfile, UnresolvedSource};

/// The only `uv.lock` format version this parser reads.
const SUPPORTED_VERSION: i64 = 1;

/// Where the lines of one `[[package]]` record are in the file.
#[derive(Clone, Copy)]
struct RecordLines {
    /// 1-indexed line of the `name = ...` entry, or of the header if the record
    /// has no `name` entry before its first nested table.
    line: usize,
}

/// Parse the lockfile.
pub(super) fn parse(relative_path: &Path, contents: &str) -> Result<Lockfile, LockError> {
    let malformed = |reason: &str| LockError::Malformed {
        file: relative_path.to_path_buf(),
        reason: reason.to_owned(),
    };

    let root: toml::Table = toml::from_str(contents).map_err(|_| malformed("invalid TOML"))?;

    let version = root
        .get("version")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| malformed("missing or non-integer version"))?;
    if version != SUPPORTED_VERSION {
        return Err(LockError::Unsupported {
            file: relative_path.to_path_buf(),
            reason: format!("uv.lock version {version}"),
        });
    }

    let records: &[toml::Value] = match root.get("package") {
        None => &[],
        Some(toml::Value::Array(records)) => records,
        Some(_) => return Err(malformed("package is not an array of tables")),
    };

    let lines = record_lines(contents);
    let lines = (lines.len() == records.len()).then_some(lines);

    let mut packages: Vec<Dependency> = Vec::new();
    let mut seen_packages: HashSet<(String, String)> = HashSet::new();
    let mut unresolved_sources: Vec<UnresolvedSource> = Vec::new();
    let mut seen_unresolved: HashSet<(String, String)> = HashSet::new();
    let mut members: Vec<String> = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let table = record
            .as_table()
            .ok_or_else(|| malformed("package record is not a table"))?;
        let name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| malformed("package record without a name"))?;
        let source = table
            .get("source")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| malformed("package record without a source"))?;
        let mut source_entries = source.iter();
        let (Some((kind, value)), None) = (source_entries.next(), source_entries.next()) else {
            return Err(malformed("package source is not a single entry"));
        };
        let line = lines
            .as_ref()
            .and_then(|lines| lines.get(index))
            .map_or(1, |record| record.line);

        match kind.as_str() {
            "registry" => {
                let version = table
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| malformed("registry package without a version"))?;
                if seen_packages.insert((name.to_owned(), version.to_owned())) {
                    packages.push(Dependency {
                        name: name.to_owned(),
                        version: version.to_owned(),
                        ecosystem: Ecosystem::PyPi,
                        file: relative_path.to_path_buf(),
                        line,
                        declaration: line_text(contents, line),
                    });
                }
            }
            "virtual" | "editable" => {
                if let Some(directory) = value.as_str().map(normalise_directory)
                    && !directory.is_empty()
                {
                    members.push(directory);
                }
            }
            "git" | "url" | "path" | "directory" => {
                if seen_unresolved.insert((name.to_owned(), kind.clone())) {
                    unresolved_sources.push(UnresolvedSource {
                        name: name.to_owned(),
                        source: kind.clone(),
                        file: relative_path.to_path_buf(),
                        line,
                    });
                }
            }
            _ => return Err(malformed("package source of an unknown kind")),
        }
    }

    members.sort();
    members.dedup();

    Ok(Lockfile {
        kind: LockKind::Uv,
        file: relative_path.to_path_buf(),
        packages,
        unresolved_sources,
        members,
        workspace_globs: Vec::new(),
    })
}

/// Normalise a project directory from the lockfile: forward slashes, no
/// leading `./`, no trailing `/`. The project root (`.`) becomes empty.
fn normalise_directory(directory: &str) -> String {
    let mut directory = directory.replace('\\', "/");
    while let Some(rest) = directory.strip_prefix("./") {
        directory = rest.to_owned();
    }
    let trimmed = directory.trim_end_matches('/');
    if trimmed == "." {
        String::new()
    } else {
        trimmed.to_owned()
    }
}

/// The trimmed text of the 1-indexed `line`, or empty if it is out of range.
fn line_text(contents: &str, line: usize) -> String {
    contents
        .lines()
        .nth(line.saturating_sub(1))
        .map(|text| text.trim().to_owned())
        .unwrap_or_default()
}

/// One forward pass over the file recording, for each `[[package]]` header in
/// order, the line of its `name = ...` entry (or of the header if none is found
/// before the next table header).
fn record_lines(contents: &str) -> Vec<RecordLines> {
    let mut records: Vec<RecordLines> = Vec::new();
    let mut awaiting_name = false;
    for (index, text) in contents.lines().enumerate() {
        let text = text.trim();
        let line = index + 1;
        if text == "[[package]]" {
            records.push(RecordLines { line });
            awaiting_name = true;
        } else if text.starts_with('[') {
            awaiting_name = false;
        } else if awaiting_name
            && text
                .strip_prefix("name")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        {
            if let Some(last) = records.last_mut() {
                last.line = line;
            }
            awaiting_name = false;
        }
    }
    records
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "certifi"
version = "2024.2.2"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://example.invalid/certifi.tar.gz", hash = "sha256:00" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "certifi" },
]

[[package]]
name = "myapp"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "api"
version = "0.2.0"
source = { editable = "./packages/api/" }
"#;

    fn parse_str(contents: &str) -> Result<Lockfile, LockError> {
        parse(Path::new("uv.lock"), contents)
    }

    #[test]
    fn registry_packages_become_dependencies() {
        let lock = parse_str(SAMPLE).unwrap();
        let found: Vec<(&str, &str)> = lock
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert_eq!(found, [("certifi", "2024.2.2"), ("requests", "2.31.0")]);
        assert_eq!(lock.kind, LockKind::Uv);
        assert_eq!(lock.file, Path::new("uv.lock"));
        assert!(
            lock.packages
                .iter()
                .all(|p| p.ecosystem == Ecosystem::PyPi && p.file == Path::new("uv.lock"))
        );
        assert_eq!(lock.workspace_globs, Vec::<String>::new());
    }

    #[test]
    fn root_virtual_is_skipped_and_editable_member_recorded() {
        let lock = parse_str(SAMPLE).unwrap();
        assert!(lock.packages.iter().all(|p| p.name != "myapp"));
        assert_eq!(lock.unresolved_sources, Vec::<_>::new());
        assert_eq!(lock.members, ["packages/api"]);
    }

    #[test]
    fn non_registry_sources_are_unresolved() {
        let contents = r#"version = 1

[[package]]
name = "a"
version = "1.0.0"
source = { git = "https://example.invalid/a.git?rev=abc#abc" }

[[package]]
name = "b"
source = { url = "https://example.invalid/b.whl" }

[[package]]
name = "c"
version = "0.1.0"
source = { path = "../c" }

[[package]]
name = "d"
version = "0.1.0"
source = { directory = "../d" }

[[package]]
name = "a"
version = "1.0.1"
source = { git = "https://example.invalid/a.git?rev=def#def" }
"#;
        let lock = parse_str(contents).unwrap();
        assert_eq!(lock.packages, Vec::<_>::new());
        let found: Vec<(&str, &str, usize)> = lock
            .unresolved_sources
            .iter()
            .map(|u| (u.name.as_str(), u.source.as_str(), u.line))
            .collect();
        assert_eq!(
            found,
            [
                ("a", "git", 4),
                ("b", "url", 9),
                ("c", "path", 13),
                ("d", "directory", 18)
            ]
        );
    }

    #[test]
    fn duplicates_are_removed_keeping_the_first() {
        let contents = r#"version = 1

[[package]]
name = "x"
version = "1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "x"
version = "1.0"
source = { registry = "https://mirror.invalid/simple" }

[[package]]
name = "x"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let lock = parse_str(contents).unwrap();
        let found: Vec<(&str, usize)> = lock
            .packages
            .iter()
            .map(|p| (p.version.as_str(), p.line))
            .collect();
        assert_eq!(found, [("1.0", 4), ("2.0", 14)]);
    }

    #[test]
    fn line_and_declaration_point_at_the_name_entry() {
        let lock = parse_str(SAMPLE).unwrap();
        let requests = &lock.packages[1];
        assert_eq!(requests.line, 11);
        assert_eq!(requests.declaration, r#"name = "requests""#);
        assert_eq!(lock.packages[0].line, 5);
    }

    #[test]
    fn other_version_is_unsupported() {
        let err = parse_str("version = 2\n").unwrap_err();
        assert_eq!(
            err,
            LockError::Unsupported {
                file: "uv.lock".into(),
                reason: "uv.lock version 2".to_owned(),
            }
        );
    }

    #[test]
    fn missing_version_is_malformed() {
        assert!(matches!(
            parse_str("[[package]]\nname = \"a\"\n"),
            Err(LockError::Malformed { .. })
        ));
    }

    #[test]
    fn invalid_toml_is_malformed() {
        assert!(matches!(
            parse_str("version = 1\n[[package\nname = "),
            Err(LockError::Malformed { .. })
        ));
    }

    #[test]
    fn registry_without_version_is_malformed() {
        let contents = "version = 1\n\n[[package]]\nname = \"a\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
        assert!(matches!(
            parse_str(contents),
            Err(LockError::Malformed { .. })
        ));
    }

    #[test]
    fn package_without_name_or_source_is_malformed() {
        let no_name =
            "version = 1\n\n[[package]]\nversion = \"1\"\nsource = { registry = \"r\" }\n";
        let no_source = "version = 1\n\n[[package]]\nname = \"a\"\nversion = \"1\"\n";
        assert!(matches!(
            parse_str(no_name),
            Err(LockError::Malformed { .. })
        ));
        assert!(matches!(
            parse_str(no_source),
            Err(LockError::Malformed { .. })
        ));
    }

    #[test]
    fn empty_lockfile_has_no_packages() {
        let lock = parse_str("version = 1\n").unwrap();
        assert_eq!(lock.packages, Vec::<_>::new());
        assert_eq!(lock.members, Vec::<String>::new());
    }
}
