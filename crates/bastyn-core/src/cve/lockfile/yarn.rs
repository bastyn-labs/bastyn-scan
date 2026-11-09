//! `yarn.lock` parser.
//!
//! Two formats share the file name. Classic (v1) is a line-oriented text
//! format that is not YAML, so it is read by hand. Berry (yarn 2 and later) is
//! YAML with a leading `__metadata` block. The format is chosen from the
//! content.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_yaml_ng::Value;

use super::{LockError, LockKind, Lockfile, UnresolvedSource};
use crate::cve::manifest::{Dependency, Ecosystem};

/// Berry `__metadata.version` values this parser reads.
const SUPPORTED_BERRY_VERSIONS: std::ops::RangeInclusive<u64> = 4..=8;

/// Parse the lockfile.
pub(super) fn parse(
    relative_path: &Path,
    contents: &str,
    sibling_package_json: Option<&str>,
) -> Result<Lockfile, LockError> {
    let is_berry = contents
        .lines()
        .any(|line| line.trim_end() == "__metadata:");
    let mut collector = Collector::new(relative_path);
    if is_berry {
        parse_berry(contents, &mut collector)?;
    } else {
        parse_classic(contents, &mut collector)?;
    }
    Ok(collector.finish(workspace_globs(sibling_package_json)))
}

/// Accumulates records while a parser walks the file.
struct Collector {
    /// The lockfile, relative to the scanned root.
    file: PathBuf,
    /// Registry packages in file order.
    packages: Vec<Dependency>,
    /// `(name, version)` pairs already in `packages`.
    seen_packages: HashSet<(String, String)>,
    /// Non-registry packages in file order.
    unresolved: Vec<UnresolvedSource>,
    /// `(name, source)` pairs already in `unresolved`.
    seen_unresolved: HashSet<(String, String)>,
    /// Workspace member directories.
    members: Vec<String>,
}

impl Collector {
    /// An empty collector for `file`.
    fn new(file: &Path) -> Self {
        Self {
            file: file.to_path_buf(),
            packages: Vec::new(),
            seen_packages: HashSet::new(),
            unresolved: Vec::new(),
            seen_unresolved: HashSet::new(),
            members: Vec::new(),
        }
    }

    /// A [`LockError::Malformed`] for this file.
    fn malformed(&self, reason: impl Into<String>) -> LockError {
        LockError::Malformed {
            file: self.file.clone(),
            reason: reason.into(),
        }
    }

    /// Record a package that resolves to a registry version. A version that
    /// is not exact is recorded as an unresolved `url` source instead.
    fn add_registry(&mut self, name: &str, version: &str, line: usize, declaration: &str) {
        if !is_exact_version(version) {
            self.add_unresolved(name, "url", line);
            return;
        }
        if !self
            .seen_packages
            .insert((name.to_owned(), version.to_owned()))
        {
            return;
        }
        self.packages.push(Dependency {
            name: name.to_owned(),
            version: version.to_owned(),
            ecosystem: Ecosystem::Npm,
            file: self.file.clone(),
            line,
            declaration: declaration.to_owned(),
        });
    }

    /// Record a package that resolves to something other than a registry
    /// version.
    fn add_unresolved(&mut self, name: &str, source: &str, line: usize) {
        if !self
            .seen_unresolved
            .insert((name.to_owned(), source.to_owned()))
        {
            return;
        }
        self.unresolved.push(UnresolvedSource {
            name: name.to_owned(),
            source: source.to_owned(),
            file: self.file.clone(),
            line,
        });
    }

    /// Record a first-party workspace member directory.
    fn add_member(&mut self, path: &str) {
        let mut path = path.replace('\\', "/");
        while let Some(stripped) = path.strip_prefix("./") {
            path = stripped.to_owned();
        }
        let path = path.trim_end_matches('/');
        if path.is_empty() || path == "." {
            return;
        }
        self.members.push(path.to_owned());
    }

    /// Assemble the result.
    fn finish(mut self, workspace_globs: Vec<String>) -> Lockfile {
        self.members.sort();
        self.members.dedup();
        Lockfile {
            kind: LockKind::Yarn,
            file: self.file,
            packages: self.packages,
            unresolved_sources: self.unresolved,
            members: self.members,
            workspace_globs,
        }
    }
}

/// True if `version` is a plain version number: starts with a digit and is
/// not a path, URL or other specifier.
fn is_exact_version(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit()) && !version.contains(['/', ':'])
}

/// The workspace patterns the sibling `package.json` declares, as written
/// (minus a leading `./`). Empty if there is no such file, it is not valid
/// JSON, or it declares none.
fn workspace_globs(sibling_package_json: Option<&str>) -> Vec<String> {
    let Some(text) = sibling_package_json else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let list = match json.get("workspaces") {
        Some(serde_json::Value::Array(items)) => Some(items),
        Some(serde_json::Value::Object(map)) => match map.get("packages") {
            Some(serde_json::Value::Array(items)) => Some(items),
            _ => None,
        },
        _ => None,
    };
    list.map(|items| {
        items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(|glob| glob.trim_start_matches("./").to_owned())
            .collect()
    })
    .unwrap_or_default()
}

/// Remove one pair of surrounding double or single quotes, if present.
fn unquote(text: &str) -> &str {
    let text = text.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = text
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    text
}

/// Split `name@reference` at the first `@` that is not at index 0, so a
/// scoped name keeps its leading `@`.
fn split_at_reference(text: &str) -> Option<(&str, &str)> {
    let at = text
        .char_indices()
        .skip(1)
        .find_map(|(i, c)| (c == '@').then_some(i))?;
    Some((&text[..at], &text[at + 1..]))
}

/// The package name a spec such as `lodash@^4.17.0`, `@scope/pkg@^1` or
/// `foo@npm:real@^1` installs. For an alias the installed package is the
/// aliased one.
fn spec_name(spec: &str) -> &str {
    let Some((name, range)) = split_at_reference(spec) else {
        return spec;
    };
    match range.strip_prefix("npm:").and_then(split_at_reference) {
        Some((real, _)) => real,
        None => name,
    }
}

// ---------------------------------------------------------------------------
// Classic (v1)
// ---------------------------------------------------------------------------

/// One block of a classic lockfile while it is being read.
struct ClassicBlock {
    /// 1-indexed line of the header.
    line: usize,
    /// The trimmed header line.
    declaration: String,
    /// The installed package's name.
    name: String,
    /// The `version` field.
    version: Option<String>,
    /// The `resolved` field.
    resolved: Option<String>,
}

/// Read a classic lockfile.
fn parse_classic(contents: &str, out: &mut Collector) -> Result<(), LockError> {
    let mut saw_header = false;
    let mut current: Option<ClassicBlock> = None;
    for (index, raw) in contents.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with('#') {
            if line.starts_with("# yarn lockfile v1") {
                saw_header = true;
            }
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            let Some(block) = current.as_mut() else {
                return Err(out.malformed(format!("indented line {line_no} outside a block")));
            };
            let indent = line.len() - line.trim_start().len();
            if indent == 2 {
                read_classic_field(block, line.trim_start());
            }
            continue;
        }
        if let Some(block) = current.take() {
            flush_classic(&block, out)?;
        }
        let Some(header) = line.strip_suffix(':') else {
            return Err(out.malformed(format!("line {line_no} is not a block header")));
        };
        let first_spec = header.split(',').next().map(unquote).unwrap_or_default();
        let name = spec_name(first_spec);
        if name.is_empty() {
            return Err(out.malformed(format!("empty package name at line {line_no}")));
        }
        current = Some(ClassicBlock {
            line: line_no,
            declaration: line.trim().to_owned(),
            name: name.to_owned(),
            version: None,
            resolved: None,
        });
    }
    if let Some(block) = current.take() {
        flush_classic(&block, out)?;
    }
    if !saw_header {
        return Err(out.malformed("missing `# yarn lockfile v1` header"));
    }
    Ok(())
}

/// Store a `version` or `resolved` field on the block. Other fields are
/// ignored; the first occurrence wins.
fn read_classic_field(block: &mut ClassicBlock, field: &str) {
    let Some((key, value)) = field.split_once(' ') else {
        return;
    };
    let slot = match key {
        "version" => &mut block.version,
        "resolved" => &mut block.resolved,
        _ => return,
    };
    if slot.is_none() {
        *slot = Some(unquote(value).to_owned());
    }
}

/// Classify a finished classic block and record it.
fn flush_classic(block: &ClassicBlock, out: &mut Collector) -> Result<(), LockError> {
    let Some(version) = block.version.as_deref() else {
        return Err(out.malformed(format!(
            "block `{}` at line {} has no version",
            block.name, block.line
        )));
    };
    match block.resolved.as_deref().map(classic_source) {
        Some(ClassicSource::Other(source)) => out.add_unresolved(&block.name, source, block.line),
        Some(ClassicSource::Registry) | None => {
            out.add_registry(&block.name, version, block.line, &block.declaration);
        }
    }
    Ok(())
}

/// What a classic `resolved` value points at.
enum ClassicSource {
    /// A registry tarball.
    Registry,
    /// Anything else, named by its short label.
    Other(&'static str),
}

/// Classify a classic `resolved` value.
fn classic_source(resolved: &str) -> ClassicSource {
    let lower = resolved.to_ascii_lowercase();
    let is_http = lower.starts_with("http://") || lower.starts_with("https://");
    let host = is_http
        .then(|| {
            lower
                .split_once("://")
                .map(|(_, rest)| rest.split(['/', '#', '?']).next().unwrap_or_default())
        })
        .flatten()
        .unwrap_or_default();
    if lower.starts_with("git+")
        || lower.starts_with("git:")
        || lower.starts_with("git@")
        || lower.starts_with("ssh://")
        || lower.starts_with("github:")
        || host == "codeload.github.com"
    {
        ClassicSource::Other("git")
    } else if lower.starts_with("file:") {
        ClassicSource::Other("path")
    } else if is_http && lower.contains("/-/") {
        ClassicSource::Registry
    } else {
        ClassicSource::Other("url")
    }
}

// ---------------------------------------------------------------------------
// Berry (yarn 2+)
// ---------------------------------------------------------------------------

/// Read a berry lockfile.
fn parse_berry(contents: &str, out: &mut Collector) -> Result<(), LockError> {
    let root: Value = serde_yaml_ng::from_str(contents)
        .map_err(|error| out.malformed(format!("invalid YAML: {error}")))?;
    let Value::Mapping(entries) = root else {
        return Err(out.malformed("top level is not a mapping"));
    };
    let version = entries
        .get("__metadata")
        .and_then(|meta| meta.get("version"))
        .and_then(|version| match version {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.trim().parse().ok(),
            _ => None,
        })
        .ok_or_else(|| out.malformed("`__metadata` has no version"))?;
    if !SUPPORTED_BERRY_VERSIONS.contains(&version) {
        return Err(LockError::Unsupported {
            file: out.file.clone(),
            reason: format!("yarn.lock berry metadata version {version}"),
        });
    }

    let headers = berry_header_lines(contents);
    for (key, record) in &entries {
        let Some(key) = key.as_str() else { continue };
        if key == "__metadata" {
            continue;
        }
        let Some(resolution) = record.get("resolution").and_then(Value::as_str) else {
            continue;
        };
        let field_version = record.get("version").and_then(|value| match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        });
        let (line, declaration) = headers
            .get(key)
            .map_or((1, key.to_owned()), |(line, text)| (*line, text.clone()));
        match berry_source(resolution, field_version) {
            BerrySource::Registry { name, version } => {
                out.add_registry(&name, &version, line, &declaration);
            }
            BerrySource::Other { name, source } => out.add_unresolved(&name, source, line),
            BerrySource::Member(path) => out.add_member(&path),
            BerrySource::Skip => {}
        }
    }
    Ok(())
}

/// For each unindented `key:` line, the 1-indexed line number and trimmed
/// text, keyed by the key with its quotes removed. The first line wins.
fn berry_header_lines(contents: &str) -> HashMap<String, (usize, String)> {
    let mut headers = HashMap::new();
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim_end();
        if line.starts_with(char::is_whitespace) || line.starts_with('#') {
            continue;
        }
        let Some(key) = line.strip_suffix(':') else {
            continue;
        };
        headers
            .entry(unquote(key).to_owned())
            .or_insert_with(|| (index + 1, line.trim().to_owned()));
    }
    headers
}

/// What a berry `resolution` points at.
enum BerrySource {
    /// A registry package.
    Registry {
        /// Installed package name.
        name: String,
        /// Version from the record (or the resolution when absent).
        version: String,
    },
    /// A non-registry package, named by its short source label.
    Other {
        /// Package name.
        name: String,
        /// Short label: `git`, `url` or `path`.
        source: &'static str,
    },
    /// A first-party workspace member at this path.
    Member(String),
    /// Nothing to record.
    Skip,
}

/// Classify a berry `resolution` of the form `<name>@<protocol>:<rest>`.
fn berry_source(resolution: &str, field_version: Option<String>) -> BerrySource {
    let Some((name, reference)) = split_at_reference(resolution) else {
        return BerrySource::Skip;
    };
    let other = |name: &str, source: &'static str| BerrySource::Other {
        name: name.to_owned(),
        source,
    };

    if let Some(rest) = reference.strip_prefix("npm:") {
        // `rest` is `1.2.3` or, for an alias, `real@1.2.3`.
        let (real_name, resolution_version) = split_at_reference(rest).unwrap_or((name, rest));
        return BerrySource::Registry {
            name: real_name.to_owned(),
            version: field_version.unwrap_or_else(|| resolution_version.to_owned()),
        };
    }
    if let Some(path) = reference.strip_prefix("workspace:") {
        return BerrySource::Member(path.to_owned());
    }
    if let Some(rest) = reference.strip_prefix("patch:") {
        let target = percent_decode(rest.split('#').next().unwrap_or_default());
        // The target is `<name>@<reference>`; a registry target is
        // `<name>@npm:<version>`, possibly with an alias name inside.
        let Some((_, target_ref)) = split_at_reference(&target) else {
            return other(name, "path");
        };
        if target_ref.starts_with("npm:") {
            return BerrySource::Registry {
                name: spec_name(&target).to_owned(),
                version: field_version.unwrap_or_default(),
            };
        }
        let source = berry_protocol_source(target_ref).unwrap_or("path");
        return other(name, source);
    }
    match berry_protocol_source(reference) {
        Some(source) => other(name, source),
        None => other(name, "url"),
    }
}

/// The short source label for a reference that starts with a protocol, or
/// `None` if the protocol is not recognised.
fn berry_protocol_source(reference: &str) -> Option<&'static str> {
    let lower = reference.to_ascii_lowercase();
    let protocol = lower.split_once(':').map_or(lower.as_str(), |(p, _)| p);
    match protocol {
        "git" | "github" | "gitlab" | "bitbucket" | "ssh" => Some("git"),
        p if p.starts_with("git+") || p.starts_with("git@") => Some("git"),
        "http" | "https" => Some("url"),
        "file" | "link" | "portal" | "exec" => Some("path"),
        _ => None,
    }
}

/// Decode `%XX` escapes. Invalid escapes are kept as written and invalid
/// UTF-8 is replaced.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = text.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn run(contents: &str, package_json: Option<&str>) -> Result<Lockfile, LockError> {
        parse(Path::new("yarn.lock"), contents, package_json)
    }

    fn names(lock: &Lockfile) -> Vec<(&str, &str)> {
        lock.packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect()
    }

    const CLASSIC: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.20.5"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.20.5.tgz#abc"
  integrity sha512-xyz
  dependencies:
    "@babel/types" "^7.20.5"
    lodash "^4.17.0"

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#def"
  integrity sha512-abc

"left-pad-alias@npm:left-pad@^1.0.0":
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#123"

from-git@^1.0.0:
  version "1.0.0"
  resolved "git+https://github.com/example/from-git.git#0123abc"

from-codeload@^1.0.0:
  version "1.0.0"
  resolved "https://codeload.github.com/example/from-codeload/tar.gz/0123abc"

local-dep@file:../local:
  version "0.0.1"
  resolved "file:../local"

from-url@^2.0.0:
  version "2.0.0"
  resolved "https://example.com/pkg/from-url.tgz"

no-resolved@^3.0.0:
  version "3.1.0"

range-version@latest:
  version "latest"
"#;

    #[test]
    fn classic_registry_packages_scoped_multi_spec_and_alias() {
        let lock = run(CLASSIC, None).unwrap();
        assert_eq!(lock.kind, LockKind::Yarn);
        assert_eq!(
            names(&lock),
            vec![
                ("@babel/core", "7.20.5"),
                ("lodash", "4.17.21"),
                ("left-pad", "1.3.0"),
                ("no-resolved", "3.1.0"),
            ]
        );
        assert_eq!(lock.members, Vec::<String>::new());
        assert_eq!(lock.workspace_globs, Vec::<String>::new());
    }

    #[test]
    fn classic_non_registry_sources_are_unresolved() {
        let lock = run(CLASSIC, None).unwrap();
        let got: Vec<(&str, &str)> = lock
            .unresolved_sources
            .iter()
            .map(|u| (u.name.as_str(), u.source.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("from-git", "git"),
                ("from-codeload", "git"),
                ("local-dep", "path"),
                ("from-url", "url"),
                ("range-version", "url"),
            ]
        );
    }

    #[test]
    fn classic_line_numbers_and_declaration() {
        let lock = run(CLASSIC, None).unwrap();
        let core = &lock.packages[0];
        assert_eq!(core.line, 5);
        assert_eq!(
            core.declaration,
            r#""@babel/core@^7.0.0", "@babel/core@^7.1.0":"#
        );
        assert_eq!(core.file, PathBuf::from("yarn.lock"));
        assert_eq!(core.ecosystem, Ecosystem::Npm);
        assert_eq!(lock.packages[1].line, 13);
        assert_eq!(lock.unresolved_sources[0].line, 22);
    }

    #[test]
    fn classic_duplicates_are_collapsed() {
        let text = "# yarn lockfile v1\n\n\
            a@^1.0.0:\n  version \"1.0.0\"\n\n\
            a@^1.1.0:\n  version \"1.0.0\"\n\n\
            b@git+ssh://x:\n  version \"1.0.0\"\n  resolved \"git+ssh://git@github.com/x/b.git#1\"\n\n\
            b@git+https://y:\n  version \"1.0.0\"\n  resolved \"git+https://github.com/y/b.git#2\"\n";
        let lock = run(text, None).unwrap();
        assert_eq!(names(&lock), vec![("a", "1.0.0")]);
        assert_eq!(lock.packages[0].line, 3);
        assert_eq!(lock.unresolved_sources.len(), 1);
    }

    #[test]
    fn classic_without_header_is_malformed() {
        let text = "a@^1.0.0:\n  version \"1.0.0\"\n";
        assert!(matches!(run(text, None), Err(LockError::Malformed { .. })));
    }

    #[test]
    fn classic_block_without_version_is_malformed() {
        let text = "# yarn lockfile v1\n\na@^1.0.0:\n  resolved \"https://r/a/-/a-1.tgz\"\n";
        assert!(matches!(run(text, None), Err(LockError::Malformed { .. })));
    }

    #[test]
    fn garbage_is_malformed() {
        for text in [
            "not a lockfile at all\nreally\n",
            "\u{0}\u{1}garbage",
            "  x\n",
        ] {
            assert!(matches!(run(text, None), Err(LockError::Malformed { .. })));
        }
    }

    const BERRY: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 6
  cacheKey: 8

"@scope/pkg@npm:^1.0.0, @scope/pkg@npm:^1.1.0":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"
  checksum: abc
  languageName: node
  linkType: hard

"alias@npm:foo@^2.0.0":
  version: 2.0.1
  resolution: "alias@npm:foo@2.0.1"
  languageName: node
  linkType: hard

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  linkType: soft

"api@workspace:packages/api":
  version: 0.0.0-use.local
  resolution: "api@workspace:packages/api"
  linkType: soft

"web@workspace:./packages/web":
  version: 0.0.0-use.local
  resolution: "web@workspace:./packages/web"
  linkType: soft

"typescript@patch:typescript@^5.0.0#~builtin<compat/typescript>":
  version: 5.0.4
  resolution: "typescript@patch:typescript@npm%3A5.0.4#~builtin<compat/typescript>::version=5.0.4&hash=abc"
  linkType: hard

"fsevents@patch:fsevents@~2.3.2#./patches/fsevents.patch":
  version: 2.3.2
  resolution: "fsevents@patch:fsevents@npm%3A2.3.2#./patches/fsevents.patch::version=2.3.2&hash=1"
  linkType: hard

"gitpkg@https://github.com/example/gitpkg.git#commit=abc":
  version: 1.0.0
  resolution: "gitpkg@https://github.com/example/gitpkg.git#commit=abc"
  linkType: hard

"ghpkg@example/ghpkg":
  version: 1.0.0
  resolution: "ghpkg@github:example/ghpkg#commit=abc"
  linkType: hard

"sshpkg@git+ssh://git@example.com/x.git":
  version: 1.0.0
  resolution: "sshpkg@git+ssh://git@example.com/x.git#commit=abc"
  linkType: hard

"urlpkg@https://example.com/pkg.tgz":
  version: 1.0.0
  resolution: "urlpkg@https://example.com/pkg.tgz"
  linkType: hard

"localpkg@file:../local":
  version: 1.0.0
  resolution: "localpkg@file:../local::locator=app%40workspace%3A."
  linkType: hard

"linkpkg@link:../l":
  version: 1.0.0
  resolution: "linkpkg@link:../l::locator=app%40workspace%3A."
  linkType: soft

"patchlocal@patch:patchlocal@file:../p#./x.patch":
  version: 1.0.0
  resolution: "patchlocal@patch:patchlocal@file%3A../p#./x.patch::version=1.0.0&hash=1"
  linkType: hard

"patchgit@patch:patchgit@https://github.com/x/y.git#./x.patch":
  version: 1.0.0
  resolution: "patchgit@patch:patchgit@git+https%3A//github.com/x/y.git#./x.patch::version=1.0.0&hash=1"
  linkType: hard
"#;

    #[test]
    fn berry_registry_packages_and_aliases() {
        let lock = run(BERRY, None).unwrap();
        assert_eq!(
            names(&lock),
            vec![
                ("@scope/pkg", "1.2.3"),
                ("foo", "2.0.1"),
                ("typescript", "5.0.4"),
                ("fsevents", "2.3.2"),
            ]
        );
    }

    #[test]
    fn berry_workspaces_become_members() {
        let lock = run(BERRY, None).unwrap();
        assert_eq!(lock.members, vec!["packages/api", "packages/web"]);
        assert!(lock.packages.iter().all(|p| p.name != "app"));
    }

    #[test]
    fn berry_non_registry_sources_are_unresolved() {
        let lock = run(BERRY, None).unwrap();
        let got: Vec<(&str, &str)> = lock
            .unresolved_sources
            .iter()
            .map(|u| (u.name.as_str(), u.source.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("gitpkg", "url"),
                ("ghpkg", "git"),
                ("sshpkg", "git"),
                ("urlpkg", "url"),
                ("localpkg", "path"),
                ("linkpkg", "path"),
                ("patchlocal", "path"),
                ("patchgit", "git"),
            ]
        );
    }

    #[test]
    fn berry_line_numbers_point_at_headers() {
        let lock = run(BERRY, None).unwrap();
        assert_eq!(lock.packages[0].line, 8);
        assert_eq!(
            lock.packages[0].declaration,
            r#""@scope/pkg@npm:^1.0.0, @scope/pkg@npm:^1.1.0":"#
        );
        assert_eq!(lock.packages[1].line, 15);
    }

    #[test]
    fn berry_duplicate_name_version_collapses() {
        let text = "__metadata:\n  version: 8\n\n\
            \"a@npm:^1.0.0\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n\n\
            \"a@npm:^1.0.1\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n";
        let lock = run(text, None).unwrap();
        assert_eq!(names(&lock), vec![("a", "1.0.0")]);
        assert_eq!(lock.packages[0].line, 4);
    }

    #[test]
    fn berry_unsupported_versions() {
        for version in [3, 9] {
            let text = format!("__metadata:\n  version: {version}\n  cacheKey: 7\n");
            assert_eq!(
                run(&text, None).unwrap_err(),
                LockError::Unsupported {
                    file: PathBuf::from("yarn.lock"),
                    reason: format!("yarn.lock berry metadata version {version}"),
                }
            );
        }
    }

    #[test]
    fn berry_invalid_yaml_is_malformed() {
        let text = "__metadata:\n  version: 6\n\t- bad: [\n";
        assert!(matches!(run(text, None), Err(LockError::Malformed { .. })));
    }

    #[test]
    fn workspace_globs_array_and_object_forms() {
        let array = r#"{"name":"r","workspaces":["./packages/*","apps/web"]}"#;
        let lock = run(CLASSIC, Some(array)).unwrap();
        assert_eq!(lock.workspace_globs, vec!["packages/*", "apps/web"]);

        let object = r#"{"workspaces":{"packages":["packages/*"],"nohoist":["x"]}}"#;
        let lock = run(CLASSIC, Some(object)).unwrap();
        assert_eq!(lock.workspace_globs, vec!["packages/*"]);
    }

    #[test]
    fn workspace_globs_ignore_bad_or_missing_package_json() {
        for pkg in [
            None,
            Some("{not json"),
            Some("{}"),
            Some(r#"{"workspaces":3}"#),
        ] {
            assert_eq!(
                run(CLASSIC, pkg).unwrap().workspace_globs,
                Vec::<String>::new()
            );
        }
    }

    #[test]
    fn spec_names() {
        assert_eq!(spec_name("lodash@^4.17.0"), "lodash");
        assert_eq!(spec_name("@scope/pkg@^1.0.0"), "@scope/pkg");
        assert_eq!(spec_name("foo@npm:bar@^1"), "bar");
        assert_eq!(spec_name("foo@npm:^1"), "foo");
        assert_eq!(spec_name("bare"), "bare");
    }
}
