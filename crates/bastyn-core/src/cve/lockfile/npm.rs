//! `package-lock.json` parser.
//!
//! Lockfile versions 2 and 3 list every installed package in a flat
//! `packages` map keyed by install path (`node_modules/a/node_modules/b`).
//! Version 1 nests the same information in a `dependencies` tree. Version 2
//! files carry both; only `packages` is read for them.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::{LockError, LockKind, Lockfile, UnresolvedSource};
use crate::cve::manifest::{Dependency, Ecosystem};

/// The path segment that separates install locations in a `packages` key.
const NODE_MODULES: &str = "node_modules/";

/// Where a lockfile record says its package comes from.
enum Resolution {
    /// A registry tarball with an exact version.
    Registry,
    /// Something advisories cannot be matched against, named in a few words.
    Unresolved(&'static str),
    /// Not enough information to say; the record is ignored.
    Skip,
}

/// A package record found in the file, before deduplication.
struct Found {
    name: String,
    version: String,
    line: usize,
    declaration: String,
}

/// Collects the records of one lockfile.
struct Collector<'a> {
    file: &'a Path,
    lines: Vec<&'a str>,
    line_of_key: HashMap<&'a str, usize>,
    found: Vec<Found>,
    unresolved: Vec<UnresolvedSource>,
    members: BTreeSet<String>,
}

/// Parse the lockfile.
pub(super) fn parse(relative_path: &Path, contents: &str) -> Result<Lockfile, LockError> {
    let malformed = |reason: &str| LockError::Malformed {
        file: relative_path.to_path_buf(),
        reason: reason.to_owned(),
    };
    let value: Value = serde_json::from_str(contents).map_err(|e| LockError::Malformed {
        file: relative_path.to_path_buf(),
        reason: format!("invalid JSON: {e}"),
    })?;
    let root = value
        .as_object()
        .ok_or_else(|| malformed("top level is not an object"))?;
    let packages = root.get("packages").and_then(Value::as_object);
    let dependencies = root.get("dependencies").and_then(Value::as_object);

    let mut collector = Collector::new(relative_path, contents);
    match root.get("lockfileVersion") {
        Some(version) => match version.as_u64() {
            Some(2 | 3) => {
                collector.read_packages(packages.ok_or_else(|| malformed("no `packages` map"))?);
            }
            Some(1) => {
                collector
                    .read_tree(dependencies.ok_or_else(|| malformed("no `dependencies` tree"))?);
            }
            Some(other) => {
                return Err(LockError::Unsupported {
                    file: relative_path.to_path_buf(),
                    reason: format!("lockfileVersion {other}"),
                });
            }
            None => return Err(malformed("`lockfileVersion` is not a number")),
        },
        None => match (packages, dependencies) {
            (Some(packages), _) => collector.read_packages(packages),
            (None, Some(dependencies)) => collector.read_tree(dependencies),
            (None, None) => return Err(malformed("no `packages` or `dependencies`")),
        },
    }
    Ok(collector.finish())
}

impl<'a> Collector<'a> {
    /// Index the lines of `contents` by the object key that opens on each.
    fn new(file: &'a Path, contents: &'a str) -> Self {
        let lines: Vec<&str> = contents.lines().collect();
        let mut line_of_key: HashMap<&str, usize> = HashMap::new();
        for (index, line) in lines.iter().enumerate() {
            let Some(rest) = line.trim_start().strip_prefix('"') else {
                continue;
            };
            if let Some((key, _)) = rest.split_once("\": {") {
                line_of_key.entry(key).or_insert(index + 1);
            }
        }
        Self {
            file,
            lines,
            line_of_key,
            found: Vec::new(),
            unresolved: Vec::new(),
            members: BTreeSet::new(),
        }
    }

    /// The 1-indexed line and trimmed text of the record keyed `key`, or the
    /// first line when the key is not on a line of its own.
    fn locate(&self, key: &str) -> (usize, String) {
        let line = self.line_of_key.get(key).copied().unwrap_or(1);
        let text = self.lines.get(line - 1).map_or("", |l| l.trim());
        (line, text.to_owned())
    }

    /// Read a version 2 or 3 `packages` map.
    fn read_packages(&mut self, packages: &Map<String, Value>) {
        for (key, entry) in packages {
            if key.is_empty() {
                continue;
            }
            let Some(entry) = entry.as_object() else {
                continue;
            };
            let resolved = entry.get("resolved").and_then(Value::as_str);
            if entry.get("link").and_then(Value::as_bool) == Some(true) {
                if let Some(dir) = resolved {
                    self.members.insert(normalise_dir(dir));
                }
                continue;
            }
            let Some(installed) = key.rsplit_once(NODE_MODULES).map(|(_, name)| name) else {
                self.members.insert(normalise_dir(key));
                continue;
            };
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .unwrap_or(installed);
            if name.is_empty() {
                continue;
            }
            let version = entry.get("version").and_then(Value::as_str);
            self.record(key, name, resolved, version);
        }
    }

    /// Read a version 1 `dependencies` tree, depth first in key order.
    fn read_tree(&mut self, dependencies: &Map<String, Value>) {
        for (name, entry) in dependencies {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            let resolved = entry.get("resolved").and_then(Value::as_str);
            let version = entry.get("version").and_then(Value::as_str);
            self.record(name, name, resolved, version);
            if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
                self.read_tree(nested);
            }
        }
    }

    /// File one record under packages or unresolved sources.
    fn record(&mut self, key: &str, name: &str, resolved: Option<&str>, version: Option<&str>) {
        let (line, declaration) = self.locate(key);
        match classify(resolved, version) {
            Resolution::Skip => {}
            Resolution::Unresolved(source) => self.unresolved.push(UnresolvedSource {
                name: name.to_owned(),
                source: source.to_owned(),
                file: self.file.to_path_buf(),
                line,
            }),
            Resolution::Registry => {
                if let Some(version) = version {
                    self.found.push(Found {
                        name: name.to_owned(),
                        version: version.to_owned(),
                        line,
                        declaration,
                    });
                }
            }
        }
    }

    /// Order by line, drop repeats and build the result.
    fn finish(mut self) -> Lockfile {
        // Sorting by line keeps file order whatever order the JSON map yields.
        self.found.sort_by_key(|f| f.line);
        self.unresolved.sort_by_key(|u| u.line);
        let mut seen = HashSet::new();
        let packages = self
            .found
            .into_iter()
            .filter(|f| seen.insert((f.name.clone(), f.version.clone())))
            .map(|f| Dependency {
                name: f.name,
                version: f.version,
                ecosystem: Ecosystem::Npm,
                file: self.file.to_path_buf(),
                line: f.line,
                declaration: f.declaration,
            })
            .collect();
        let mut seen = HashSet::new();
        let unresolved_sources = self
            .unresolved
            .into_iter()
            .filter(|u| seen.insert((u.name.clone(), u.source.clone())))
            .collect();
        Lockfile {
            kind: LockKind::NpmPackageLock,
            file: PathBuf::from(self.file),
            packages,
            unresolved_sources,
            members: self.members.into_iter().collect(),
            workspace_globs: Vec::new(),
        }
    }
}

/// A directory as it is recorded in `members`: forward slashes only.
fn normalise_dir(dir: &str) -> String {
    dir.replace('\\', "/")
}

/// Decide where a record comes from, from its `resolved` URL and `version`.
fn classify(resolved: Option<&str>, version: Option<&str>) -> Resolution {
    for hint in [resolved, version].into_iter().flatten() {
        if hint.starts_with("git") || hint.starts_with("ssh://") {
            return Resolution::Unresolved("git");
        }
        if hint.starts_with("file:") {
            return Resolution::Unresolved("path");
        }
    }
    match resolved {
        Some(url) if url.starts_with("http://") || url.starts_with("https://") => {
            // Registry tarballs live at `<package>/-/<file>.tgz`.
            if !url.contains("/-/") {
                return Resolution::Unresolved("url");
            }
        }
        Some(_) => return Resolution::Unresolved("url"),
        None => {
            if version.is_some_and(|v| v.starts_with("http://") || v.starts_with("https://")) {
                return Resolution::Unresolved("url");
            }
        }
    }
    match version {
        Some(version) if is_exact(version) => Resolution::Registry,
        Some(_) => Resolution::Unresolved("url"),
        None => Resolution::Skip,
    }
}

/// True for a concrete version such as `1.2.3` or `2.0.0-beta.1`, false for
/// ranges, tags and specifiers.
fn is_exact(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit())
        && !version.contains(|c: char| {
            c.is_whitespace() || matches!(c, '^' | '~' | '<' | '>' | '=' | '|' | '*' | '/' | ':')
        })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn parse_ok(contents: &str) -> Lockfile {
        parse(Path::new("package-lock.json"), contents).expect("parses")
    }

    fn names(lock: &Lockfile) -> Vec<(&str, &str)> {
        lock.packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect()
    }

    const V3: &str = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "app",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "^4.17.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
      "integrity": "sha512-x"
    },
    "node_modules/@scope/pkg": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"
    },
    "node_modules/a/node_modules/@scope/b": {
      "version": "3.1.0-beta.1",
      "resolved": "https://registry.npmjs.org/@scope/b/-/b-3.1.0-beta.1.tgz"
    },
    "node_modules/a/node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}
"#;

    #[test]
    fn v3_nested_and_scoped_names() {
        let lock = parse_ok(V3);
        assert_eq!(lock.kind, LockKind::NpmPackageLock);
        assert_eq!(lock.file, Path::new("package-lock.json"));
        assert_eq!(
            names(&lock),
            [
                ("lodash", "4.17.20"),
                ("@scope/pkg", "2.0.0"),
                ("@scope/b", "3.1.0-beta.1"),
                ("lodash", "4.17.21"),
            ]
        );
        assert_eq!(lock.unresolved_sources.len(), 0);
        assert_eq!(lock.members.len(), 0);
        assert_eq!(lock.workspace_globs.len(), 0);
        assert!(lock.packages.iter().all(|p| p.ecosystem == Ecosystem::Npm));
    }

    #[test]
    fn line_numbers_and_declarations() {
        let lock = parse_ok(V3);
        let lines: Vec<(usize, &str)> = lock
            .packages
            .iter()
            .map(|p| (p.line, p.declaration.as_str()))
            .collect();
        assert_eq!(
            lines,
            [
                (13, "\"node_modules/lodash\": {"),
                (18, "\"node_modules/@scope/pkg\": {"),
                (22, "\"node_modules/a/node_modules/@scope/b\": {"),
                (26, "\"node_modules/a/node_modules/lodash\": {"),
            ]
        );
        assert!(lock.packages.iter().all(|p| p.file == lock.file));
    }

    #[test]
    fn alias_uses_name_field() {
        let lock = parse_ok(
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/my-alias": {
      "name": "real-pkg",
      "version": "1.2.3",
      "resolved": "https://registry.npmjs.org/real-pkg/-/real-pkg-1.2.3.tgz"
    }
  }
}"#,
        );
        assert_eq!(names(&lock), [("real-pkg", "1.2.3")]);
        assert_eq!(lock.packages[0].line, 4);
    }

    #[test]
    fn workspace_member_and_link_are_members() {
        let lock = parse_ok(
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "workspaces": ["packages/*"]
    },
    "node_modules/api": {
      "resolved": "packages/api",
      "link": true
    },
    "packages/api": {
      "name": "api",
      "version": "1.0.0",
      "dependencies": { "lodash": "^4" }
    },
    "packages/web": {
      "version": "1.0.0"
    },
    "packages/api/node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    }
  }
}"#,
        );
        assert_eq!(lock.members, ["packages/api", "packages/web"]);
        assert_eq!(names(&lock), [("left-pad", "1.3.0")]);
        assert_eq!(lock.unresolved_sources.len(), 0);
    }

    #[test]
    fn non_registry_sources_are_unresolved() {
        let lock = parse_ok(
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/from-git": {
      "version": "1.0.0",
      "resolved": "git+ssh://git@github.com/o/r.git#abc123"
    },
    "node_modules/from-github": {
      "version": "1.0.0",
      "resolved": "github:o/r#abc123"
    },
    "node_modules/from-file": {
      "version": "1.0.0",
      "resolved": "file:../local"
    },
    "node_modules/from-url": {
      "version": "1.0.0",
      "resolved": "https://example.com/pkg.tgz"
    },
    "node_modules/range": {
      "version": "^1.0.0"
    },
    "node_modules/fine": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/fine/-/fine-1.0.0.tgz"
    }
  }
}"#,
        );
        assert_eq!(names(&lock), [("fine", "1.0.0")]);
        let got: Vec<(&str, &str, usize)> = lock
            .unresolved_sources
            .iter()
            .map(|u| (u.name.as_str(), u.source.as_str(), u.line))
            .collect();
        assert_eq!(
            got,
            [
                ("from-git", "git", 4),
                ("from-github", "git", 8),
                ("from-file", "path", 12),
                ("from-url", "url", 16),
                ("range", "url", 20),
            ]
        );
    }

    #[test]
    fn bundled_dependency_without_resolved_is_a_package() {
        let lock = parse_ok(
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/bundler/node_modules/inner": {
      "version": "0.5.0",
      "inBundle": true
    },
    "node_modules/stub": {
      "optional": true
    },
    "node_modules/optional-native": {
      "version": "1.0.0",
      "optional": true
    }
  }
}"#,
        );
        assert_eq!(
            names(&lock),
            [("inner", "0.5.0"), ("optional-native", "1.0.0")]
        );
        assert_eq!(lock.unresolved_sources.len(), 0);
    }

    #[test]
    fn v1_nested_tree() {
        let lock = parse_ok(
            r#"{
  "name": "app",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "a": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
      "dependencies": {
        "b": {
          "version": "2.0.0",
          "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"
        },
        "g": {
          "version": "github:o/r#abc"
        }
      }
    },
    "f": {
      "version": "file:../f"
    },
    "u": {
      "version": "https://example.com/u.tgz"
    }
  }
}"#,
        );
        assert_eq!(names(&lock), [("a", "1.0.0"), ("b", "2.0.0")]);
        assert_eq!(lock.packages[1].line, 10);
        assert_eq!(lock.packages[1].declaration, "\"b\": {");
        let got: Vec<(&str, &str)> = lock
            .unresolved_sources
            .iter()
            .map(|u| (u.name.as_str(), u.source.as_str()))
            .collect();
        assert_eq!(got, [("g", "git"), ("f", "path"), ("u", "url")]);
    }

    #[test]
    fn missing_version_with_dependencies_reads_tree() {
        let lock = parse_ok(
            r#"{
  "dependencies": {
    "a": { "version": "1.0.0" }
  }
}"#,
        );
        assert_eq!(names(&lock), [("a", "1.0.0")]);
    }

    #[test]
    fn duplicates_are_collapsed() {
        let lock = parse_ok(
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/a/node_modules/x": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"
    },
    "node_modules/b/node_modules/x": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"
    },
    "node_modules/c/node_modules/g": {
      "version": "1.0.0",
      "resolved": "git+https://example.com/g.git#1"
    },
    "node_modules/d/node_modules/g": {
      "version": "2.0.0",
      "resolved": "git+https://example.com/g.git#2"
    }
  }
}"#,
        );
        assert_eq!(names(&lock), [("x", "1.0.0")]);
        assert_eq!(lock.packages[0].line, 4);
        assert_eq!(lock.unresolved_sources.len(), 1);
        assert_eq!(lock.unresolved_sources[0].line, 12);
    }

    #[test]
    fn lockfile_version_4_is_unsupported() {
        let err = parse(
            Path::new("package-lock.json"),
            r#"{"lockfileVersion": 4, "packages": {}}"#,
        )
        .expect_err("unsupported");
        assert_eq!(
            err,
            LockError::Unsupported {
                file: PathBuf::from("package-lock.json"),
                reason: "lockfileVersion 4".to_owned(),
            }
        );
    }

    #[test]
    fn malformed_inputs() {
        for contents in [
            "{ not json",
            "[]",
            "\"text\"",
            "{}",
            r#"{"lockfileVersion": 3}"#,
            r#"{"lockfileVersion": 1}"#,
            r#"{"lockfileVersion": "3", "packages": {}}"#,
        ] {
            let err = parse(Path::new("package-lock.json"), contents).expect_err(contents);
            assert!(matches!(err, LockError::Malformed { .. }), "{contents}");
            assert_eq!(err.file(), Path::new("package-lock.json"));
        }
    }

    #[test]
    fn unexpected_entry_shapes_do_not_panic() {
        let lock = parse_ok(
            r#"{"lockfileVersion": 3, "packages": {"node_modules/a": 5, "node_modules/b": {"version": 7}, "node_modules/": {"version": "1.0.0"}, "node_modules/c": {"version": "1.0.0"}}}"#,
        );
        assert_eq!(names(&lock), [("c", "1.0.0")]);
        assert_eq!(lock.packages[0].line, 1);
    }
}
