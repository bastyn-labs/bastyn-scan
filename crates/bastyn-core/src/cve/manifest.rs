//! Dependency manifest parsing.
//!
//! Turns a manifest file's contents into `(name, version, ecosystem)`
//! triples the OSV lookup can query. A version that is a range rather than a
//! pin — `>=2.0`, `^1.2.3`, `*` — is never guessed at: it comes back as an
//! [`UnresolvedDependency`] instead, because matching CVEs against a guessed
//! version produces confident nonsense.

use std::path::{Path, PathBuf};

/// Errors from parsing a dependency manifest.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file name is not one this module knows how to parse.
    #[error("{path}: not a recognised dependency manifest")]
    UnsupportedManifest {
        /// The path that was passed to [`parse_manifest`].
        path: PathBuf,
    },
    /// The file name matched a manifest this module parses, but its content
    /// is not valid TOML.
    #[error("{path}: invalid TOML")]
    InvalidToml {
        /// The file that failed to parse.
        path: PathBuf,
        /// The underlying parse failure.
        #[source]
        source: toml::de::Error,
    },
    /// The file name matched a manifest this module parses, but its content
    /// is not valid JSON.
    #[error("{path}: invalid JSON")]
    InvalidJson {
        /// The file that failed to parse.
        path: PathBuf,
        /// The underlying parse failure.
        #[source]
        source: serde_json::Error,
    },
}

/// A specialised [`std::result::Result`] for manifest parsing.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A package registry a dependency can live in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// The Python Package Index.
    PyPi,
    /// The npm registry.
    Npm,
    /// `crates.io`, the Rust registry.
    CratesIo,
}

impl Ecosystem {
    /// The ecosystem name exactly as `OSV.dev` expects it in a query.
    #[must_use]
    pub const fn osv_name(self) -> &'static str {
        match self {
            Self::PyPi => "PyPI",
            Self::Npm => "npm",
            Self::CratesIo => "crates.io",
        }
    }
}

/// A dependency we could resolve to an exact version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// Package name, as declared in the manifest.
    pub name: String,
    /// The exact version pinned in the manifest.
    pub version: String,
    /// Which package registry this dependency lives in.
    pub ecosystem: Ecosystem,
    /// The manifest file this was declared in, relative to the scanned root.
    pub file: PathBuf,
    /// 1-indexed line the dependency is declared on.
    pub line: usize,
    /// The trimmed source line the dependency was declared on. Used as the
    /// [`Finding`](crate::Finding) snippet if this dependency turns out to
    /// be vulnerable.
    pub declaration: String,
}

/// A dependency declared as a range we refuse to guess at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedDependency {
    /// Package name, as declared in the manifest.
    pub name: String,
    /// The version range or specifier exactly as written, e.g. `">=2.0"` or
    /// `"^1.2.3"`.
    pub constraint: String,
    /// The manifest file this was declared in, relative to the scanned root.
    pub file: PathBuf,
    /// 1-indexed line the dependency is declared on.
    pub line: usize,
    /// True for a dependency declared in a dev/test-only section —
    /// `package.json`'s `devDependencies` is the one manifest shape this
    /// module parses that separates the two. Every other manifest this
    /// module reads (`requirements.txt`, `pyproject.toml`'s
    /// `project.dependencies` and `tool.poetry.dependencies`, `Cargo.toml`'s
    /// `[dependencies]`) already only reads the production section, so this
    /// is always `false` for those. A caller building a finding out of the
    /// declared *framework* — not any dependency, e.g. `BAS-LLM04-001` —
    /// uses this to keep a wildcard on `eslint` or `pytest` from reading the
    /// same as one on `langchain` itself.
    pub dev: bool,
}

/// True if `path`'s file name is a manifest this module can parse.
#[must_use]
pub fn is_manifest(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("requirements.txt" | "pyproject.toml" | "package.json" | "Cargo.toml")
    )
}

/// The registry a manifest's dependencies live in, selected by file name.
///
/// `None` for a path [`is_manifest`] does not recognise.
#[must_use]
pub fn manifest_ecosystem(path: &Path) -> Option<Ecosystem> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("requirements.txt" | "pyproject.toml") => Some(Ecosystem::PyPi),
        Some("package.json") => Some(Ecosystem::Npm),
        Some("Cargo.toml") => Some(Ecosystem::CratesIo),
        _ => None,
    }
}

/// Parse one manifest file. Returns the dependencies pinned to an exact
/// version, and separately the ones declared as a range this module refuses
/// to guess at.
///
/// `relative_path` selects the parser by file name (`requirements.txt`,
/// `pyproject.toml`, `package.json`, or `Cargo.toml`) and is stamped onto
/// every dependency returned, so a caller aggregating dependencies from many
/// manifests across a tree can still trace each one back to its file.
///
/// # Errors
/// [`Error::UnsupportedManifest`] if the file name is not recognised,
/// [`Error::InvalidToml`] or [`Error::InvalidJson`] if the content does not
/// parse as the format its name implies.
pub fn parse_manifest(
    relative_path: &Path,
    contents: &str,
) -> Result<(Vec<Dependency>, Vec<UnresolvedDependency>)> {
    match relative_path.file_name().and_then(|name| name.to_str()) {
        Some("requirements.txt") => Ok(parse_requirements_txt(relative_path, contents)),
        Some("pyproject.toml") => parse_pyproject_toml(relative_path, contents),
        Some("package.json") => parse_package_json(relative_path, contents),
        Some("Cargo.toml") => parse_cargo_toml(relative_path, contents),
        _ => Err(Error::UnsupportedManifest {
            path: relative_path.to_path_buf(),
        }),
    }
}

// ---------------------------------------------------------------------
// requirements.txt
// ---------------------------------------------------------------------

fn parse_requirements_txt(
    relative_path: &Path,
    contents: &str,
) -> (Vec<Dependency>, Vec<UnresolvedDependency>) {
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();

    for (idx, raw_line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_inline_comment(raw_line).trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') || line.contains("://")
        {
            continue;
        }
        let Some((name, version, constraint)) = parse_pep508(line) else {
            continue;
        };
        match version {
            Some(version) => resolved.push(Dependency {
                name,
                version,
                ecosystem: Ecosystem::PyPi,
                file: relative_path.to_path_buf(),
                line: line_no,
                declaration: line.to_string(),
            }),
            None => unresolved.push(UnresolvedDependency {
                name,
                constraint,
                file: relative_path.to_path_buf(),
                line: line_no,
                dev: false,
            }),
        }
    }

    (resolved, unresolved)
}

/// Drop everything from the first `#` onward — a `requirements.txt` inline
/// comment. Package specifiers never contain `#`, so this is unambiguous.
fn strip_inline_comment(line: &str) -> &str {
    line.find('#').map_or(line, |i| &line[..i])
}

/// Drop a PEP 508 environment marker (`; python_version < "3.8"`). Marker
/// expressions never contain `;` themselves, so splitting on the first one
/// is exact.
fn strip_marker(spec: &str) -> &str {
    spec.find(';').map_or(spec, |i| &spec[..i])
}

/// Parse one PEP 508-ish requirement specifier — `"requests==2.19.1"`,
/// `"requests[socks]>=2.0,<3"`, or a bare `"requests"` with no version at
/// all.
///
/// Not a full PEP 508 parser: environment markers and extras are discarded
/// rather than modelled. That is enough to name the package and decide
/// whether its version is pinned, which is all this module needs.
///
/// Returns `(name, exact_version, raw_constraint)`. `exact_version` is
/// `Some` only for a single unqualified `==` pin; every other shape —
/// ranges, multiple constraints, wildcards, or no version at all — comes
/// back as `None`, with `raw_constraint` holding what was declared.
fn parse_pep508(spec: &str) -> Option<(String, Option<String>, String)> {
    let spec = strip_marker(spec).trim();
    if spec.is_empty() {
        return None;
    }

    let name_end = spec
        .find(|c: char| {
            c == '['
                || c == '='
                || c == '<'
                || c == '>'
                || c == '!'
                || c == '~'
                || c.is_whitespace()
        })
        .unwrap_or(spec.len());
    let name = spec[..name_end].trim();
    if name.is_empty() {
        return None;
    }

    let mut rest = spec[name_end..].trim();
    if let Some(after_bracket) = rest.strip_prefix('[') {
        rest = after_bracket
            .split_once(']')
            .map_or("", |(_, after)| after.trim());
    }

    if rest.is_empty() {
        return Some((name.to_string(), None, "*".to_string()));
    }

    if let Some(version) = rest.strip_prefix("==") {
        let version = version.trim();
        if !version.is_empty() && !version.contains(',') && !version.contains('*') {
            return Some((
                name.to_string(),
                Some(version.to_string()),
                rest.to_string(),
            ));
        }
    }

    Some((name.to_string(), None, rest.to_string()))
}

// ---------------------------------------------------------------------
// pyproject.toml / Cargo.toml shared helpers
// ---------------------------------------------------------------------

/// True if `version` is a plain dotted-numeric literal — e.g. `"2.19.1"` or
/// `"1.0.0-beta.1"` — with no range operator, caret, tilde, or wildcard.
fn is_exact_literal(version: &str) -> bool {
    let core = version.split(['-', '+']).next().unwrap_or("");
    !core.is_empty()
        && core
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

/// Resolve a Cargo- or Poetry-style version field to an exact pin, or `None`
/// if it is a range.
///
/// Cargo and Poetry both treat a bare version (`"1.0"`) as a caret-compatible
/// range by default — only a leading `=` is a true exact pin in their own
/// semantics. This module deliberately does not follow that rule: it treats
/// a bare dotted-numeric literal as the declared version for every
/// ecosystem, where it resolves to an exact pin. Following Cargo/Poetry's
/// own caret-by-default convention would mean almost no `Cargo.toml` or
/// Poetry dependency is ever resolvable from the manifest alone, since that
/// is by far the most common way either is written. `^`, `~`, comparison
/// operators, wildcards, and comma-separated constraints are still treated
/// as unresolvable ranges either way.
fn exact_pin_version(version: &str) -> Option<String> {
    let trimmed = version.trim();
    let stripped = trimmed.strip_prefix('=').unwrap_or(trimmed).trim();
    is_exact_literal(stripped).then(|| stripped.to_string())
}

/// Extract the version requirement from a Cargo/Poetry dependency value: a
/// bare string (`"^2.28"`) or a table with a `version` key
/// (`{ version = "^2.28", features = [...] }`). `None` for a path/git
/// dependency with no `version` field at all — there is nothing to look up
/// on OSV for those, so they are silently skipped rather than reported as
/// unresolved.
fn version_field(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        _ => None,
    }
}

/// 1-indexed line number containing byte offset `idx` in `contents`.
fn line_at(contents: &str, idx: usize) -> usize {
    let idx = idx.min(contents.len());
    contents[..idx].matches('\n').count() + 1
}

/// Best-effort 1-indexed line of the first occurrence of `needle`. Falls
/// back to line 1 — a manifest still parses correctly even when its
/// location can only be approximated.
fn line_of_first(contents: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 1;
    }
    contents
        .find(needle)
        .map_or(1, |idx| line_at(contents, idx))
}

/// Best-effort 1-indexed line where `key` is assigned inside the TOML table
/// headed by `[section]` (e.g. `"tool.poetry.dependencies"`). Falls back to
/// the section header's line, or line 1 if the section itself is not found.
fn line_of_toml_key(contents: &str, section: &str, key: &str) -> usize {
    let header = format!("[{section}]");
    let section_start = contents.find(&header).unwrap_or(0);
    let search_space = &contents[section_start..];
    for candidate in [
        format!("{key} ="),
        format!("{key}="),
        format!("\"{key}\" ="),
        format!("\"{key}\"="),
    ] {
        if let Some(rel) = search_space.find(candidate.as_str()) {
            return line_at(contents, section_start + rel);
        }
    }
    line_at(contents, section_start)
}

/// Best-effort 1-indexed line where `"key"` is declared inside the JSON
/// object named `section` (e.g. `"devDependencies"`). Falls back to line 1.
fn line_of_json_key(contents: &str, section: &str, key: &str) -> usize {
    let section_marker = format!("\"{section}\"");
    let section_start = contents.find(&section_marker).unwrap_or(0);
    let key_marker = format!("\"{key}\"");
    contents[section_start..]
        .find(key_marker.as_str())
        .map_or_else(
            || line_of_first(contents, &key_marker),
            |rel| line_at(contents, section_start + rel),
        )
}

/// The trimmed source line at 1-indexed `line_no`, or an empty string if it
/// is out of range. Used only for the `Finding` snippet, never for
/// correctness of parsing itself.
fn declaration_at(contents: &str, line_no: usize) -> String {
    contents
        .lines()
        .nth(line_no.saturating_sub(1))
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------
// pyproject.toml
// ---------------------------------------------------------------------

fn parse_pyproject_toml(
    relative_path: &Path,
    contents: &str,
) -> Result<(Vec<Dependency>, Vec<UnresolvedDependency>)> {
    let doc: toml::Value = toml::from_str(contents).map_err(|source| Error::InvalidToml {
        path: relative_path.to_path_buf(),
        source,
    })?;

    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();

    if let Some(deps) = doc
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        for entry in deps {
            let Some(spec) = entry.as_str() else { continue };
            let Some((name, version, constraint)) = parse_pep508(spec) else {
                continue;
            };
            let line = line_of_first(contents, spec);
            let declaration = declaration_at(contents, line);
            match version {
                Some(version) => resolved.push(Dependency {
                    name,
                    version,
                    ecosystem: Ecosystem::PyPi,
                    file: relative_path.to_path_buf(),
                    line,
                    declaration,
                }),
                None => unresolved.push(UnresolvedDependency {
                    name,
                    constraint,
                    file: relative_path.to_path_buf(),
                    line,
                    dev: false,
                }),
            }
        }
    }

    if let Some(deps) = doc
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        for (name, value) in deps {
            // The interpreter constraint, not a package dependency.
            if name == "python" {
                continue;
            }
            let Some(version_str) = version_field(value) else {
                continue;
            };
            let line = line_of_toml_key(contents, "tool.poetry.dependencies", name);
            let declaration = declaration_at(contents, line);
            match exact_pin_version(&version_str) {
                Some(version) => resolved.push(Dependency {
                    name: name.clone(),
                    version,
                    ecosystem: Ecosystem::PyPi,
                    file: relative_path.to_path_buf(),
                    line,
                    declaration,
                }),
                None => unresolved.push(UnresolvedDependency {
                    name: name.clone(),
                    constraint: version_str,
                    file: relative_path.to_path_buf(),
                    line,
                    dev: false,
                }),
            }
        }
    }

    Ok((resolved, unresolved))
}

// ---------------------------------------------------------------------
// Cargo.toml
// ---------------------------------------------------------------------

fn parse_cargo_toml(
    relative_path: &Path,
    contents: &str,
) -> Result<(Vec<Dependency>, Vec<UnresolvedDependency>)> {
    let doc: toml::Value = toml::from_str(contents).map_err(|source| Error::InvalidToml {
        path: relative_path.to_path_buf(),
        source,
    })?;

    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();

    if let Some(deps) = doc.get("dependencies").and_then(toml::Value::as_table) {
        for (name, value) in deps {
            let Some(version_str) = version_field(value) else {
                continue;
            };
            let line = line_of_toml_key(contents, "dependencies", name);
            let declaration = declaration_at(contents, line);
            match exact_pin_version(&version_str) {
                Some(version) => resolved.push(Dependency {
                    name: name.clone(),
                    version,
                    ecosystem: Ecosystem::CratesIo,
                    file: relative_path.to_path_buf(),
                    line,
                    declaration,
                }),
                None => unresolved.push(UnresolvedDependency {
                    name: name.clone(),
                    constraint: version_str,
                    file: relative_path.to_path_buf(),
                    line,
                    dev: false,
                }),
            }
        }
    }

    Ok((resolved, unresolved))
}

// ---------------------------------------------------------------------
// package.json
// ---------------------------------------------------------------------

fn parse_package_json(
    relative_path: &Path,
    contents: &str,
) -> Result<(Vec<Dependency>, Vec<UnresolvedDependency>)> {
    let doc: serde_json::Value =
        serde_json::from_str(contents).map_err(|source| Error::InvalidJson {
            path: relative_path.to_path_buf(),
            source,
        })?;

    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();

    for section in ["dependencies", "devDependencies"] {
        let Some(deps) = doc.get(section).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (name, value) in deps {
            let Some(spec) = value.as_str() else { continue };
            let line = line_of_json_key(contents, section, name);
            let declaration = declaration_at(contents, line);
            match exact_pin_version(spec) {
                Some(version) => resolved.push(Dependency {
                    name: name.clone(),
                    version,
                    ecosystem: Ecosystem::Npm,
                    file: relative_path.to_path_buf(),
                    line,
                    declaration,
                }),
                None => unresolved.push(UnresolvedDependency {
                    name: name.clone(),
                    constraint: spec.to_string(),
                    file: relative_path.to_path_buf(),
                    line,
                    dev: section == "devDependencies",
                }),
            }
        }
    }

    Ok((resolved, unresolved))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    fn dep<'a>(deps: &'a [Dependency], name: &str) -> &'a Dependency {
        deps.iter().find(|d| d.name == name).unwrap()
    }

    fn unresolved<'a>(deps: &'a [UnresolvedDependency], name: &str) -> &'a UnresolvedDependency {
        deps.iter().find(|d| d.name == name).unwrap()
    }

    #[test]
    fn requirements_txt_pins_and_ranges() {
        let contents = "requests==2.19.1\nflask>=2.0\n# comment\n\n-e .\nurllib3 @ https://example.com/x.whl\n";
        let path = Path::new("requirements.txt");

        let (resolved, unresolved_deps) = parse_manifest(path, contents).unwrap();

        assert_eq!(resolved.len(), 1, "resolved: {resolved:?}");
        let requests = dep(&resolved, "requests");
        assert_eq!(requests.version, "2.19.1");
        assert_eq!(requests.ecosystem, Ecosystem::PyPi);
        assert_eq!(requests.line, 1);

        assert_eq!(unresolved_deps.len(), 1, "unresolved: {unresolved_deps:?}");
        let flask = unresolved(&unresolved_deps, "flask");
        assert_eq!(flask.constraint, ">=2.0");
        assert_eq!(flask.line, 2);
    }

    #[test]
    fn pyproject_toml_both_dependency_styles() {
        let contents = r#"
[project]
name = "demo"
dependencies = [
    "requests==2.19.1",
    "flask>=2.0",
]

[tool.poetry.dependencies]
python = "^3.10"
django = "4.2.1"
celery = "^5.3"
"#;
        let path = Path::new("pyproject.toml");

        let (resolved, unresolved_deps) = parse_manifest(path, contents).unwrap();

        let requests = dep(&resolved, "requests");
        assert_eq!(requests.version, "2.19.1");
        assert_eq!(requests.ecosystem, Ecosystem::PyPi);

        let django = dep(&resolved, "django");
        assert_eq!(django.version, "4.2.1");

        assert!(
            resolved.iter().all(|d| d.name != "python"),
            "python interpreter constraint must not be treated as a dependency"
        );

        let flask = unresolved(&unresolved_deps, "flask");
        assert_eq!(flask.constraint, ">=2.0");

        let celery = unresolved(&unresolved_deps, "celery");
        assert_eq!(celery.constraint, "^5.3");
    }

    #[test]
    fn package_json_dependencies_and_dev_dependencies() {
        let contents = r#"{
  "name": "demo",
  "dependencies": {
    "lodash": "4.17.21",
    "react": "^18.2.0"
  },
  "devDependencies": {
    "jest": "29.7.0"
  }
}
"#;
        let path = Path::new("package.json");

        let (resolved, unresolved_deps) = parse_manifest(path, contents).unwrap();

        let lodash = dep(&resolved, "lodash");
        assert_eq!(lodash.version, "4.17.21");
        assert_eq!(lodash.ecosystem, Ecosystem::Npm);

        let jest = dep(&resolved, "jest");
        assert_eq!(jest.version, "29.7.0");

        let react = unresolved(&unresolved_deps, "react");
        assert_eq!(react.constraint, "^18.2.0");
    }

    #[test]
    fn package_json_marks_dev_dependencies_as_dev() {
        // BAS-LLM04-001 (wildcard-version agent-framework dependency) must
        // not fire on a dev-only or test-only wildcard the same way it does
        // on the framework itself — this is the field that lets it tell the
        // two apart.
        let contents = r#"{
  "dependencies": {
    "langchain": "*"
  },
  "devDependencies": {
    "eslint": "*"
  }
}
"#;
        let path = Path::new("package.json");

        let (_, unresolved_deps) = parse_manifest(path, contents).unwrap();

        let langchain = unresolved(&unresolved_deps, "langchain");
        assert!(!langchain.dev, "a production dependency was marked dev");

        let eslint = unresolved(&unresolved_deps, "eslint");
        assert!(eslint.dev, "a devDependencies entry was not marked dev");
    }

    #[test]
    fn cargo_toml_dependencies() {
        let contents = r#"
[package]
name = "demo"

[dependencies]
serde = "1.0.219"
tokio = { version = "1.38.0", features = ["full"] }
regex = "1"
local = { path = "../local" }
"#;
        let path = Path::new("Cargo.toml");

        let (resolved, unresolved_deps) = parse_manifest(path, contents).unwrap();

        let serde_dep = dep(&resolved, "serde");
        assert_eq!(serde_dep.version, "1.0.219");
        assert_eq!(serde_dep.ecosystem, Ecosystem::CratesIo);

        let tokio = dep(&resolved, "tokio");
        assert_eq!(tokio.version, "1.38.0");

        let regex_dep = dep(&resolved, "regex");
        assert_eq!(regex_dep.version, "1");

        assert!(
            resolved.iter().all(|d| d.name != "local")
                && unresolved_deps.iter().all(|d| d.name != "local"),
            "a path dependency with no version has nothing to look up and should be skipped"
        );

        assert!(
            unresolved_deps.is_empty(),
            "no range-style Cargo dependency in this fixture: {unresolved_deps:?}"
        );
    }

    #[test]
    fn is_manifest_recognises_known_names_only() {
        assert!(is_manifest(Path::new("requirements.txt")));
        assert!(is_manifest(Path::new("nested/pyproject.toml")));
        assert!(is_manifest(Path::new("package.json")));
        assert!(is_manifest(Path::new("Cargo.toml")));
        assert!(!is_manifest(Path::new("README.md")));
        assert!(!is_manifest(Path::new("setup.py")));
    }

    #[test]
    fn unsupported_manifest_is_an_error() {
        let error = parse_manifest(Path::new("README.md"), "").unwrap_err();
        assert!(matches!(error, Error::UnsupportedManifest { .. }));
    }

    #[test]
    fn invalid_toml_is_an_error() {
        let error = parse_manifest(Path::new("Cargo.toml"), "not = [valid").unwrap_err();
        assert!(matches!(error, Error::InvalidToml { .. }));
    }

    #[test]
    fn invalid_json_is_an_error() {
        let error = parse_manifest(Path::new("package.json"), "{not valid").unwrap_err();
        assert!(matches!(error, Error::InvalidJson { .. }));
    }
}
