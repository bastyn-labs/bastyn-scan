//! MCP (Model Context Protocol) configuration inspection.
//!
//! Finds `mcp.json` and its siblings in a scanned tree, parses them — JSON,
//! YAML, or TOML — into one common shape, and runs a fixed set of checks
//! against that shape. Because every format converges on the same
//! one internal model before any check runs, the same logical
//! configuration produces the same findings no matter which serialisation a
//! project happens to use.
//!
//! # Checks
//!
//! | Rule | What it flags | Category |
//! | --- | --- | --- |
//! | `BAS-MCP-000` | The file is not valid JSON/YAML/TOML | `ZT3` |
//! | `BAS-MCP-001` | A server's `args` grants root or a home directory | `ZT3` |
//! | `BAS-MCP-002` | A `url` server reached over unauthenticated `http://` | `ZT1` |
//! | `BAS-MCP-003` | A `tools`/`permissions`/`allowedTools` wildcard grant | `ZT2` |
//! | `BAS-MCP-004` | An `env` value shaped like a live credential | `ZT1` |
//! | `BAS-MCP-005` | A server launched from a registry with no version pin | `LLM04` |
//! | `BAS-LLM03-020` | A client-wide or per-server `autoApprove`/`alwaysAllow` wildcard | `LLM03` |

pub(crate) mod checks;
mod model;

use std::path::Path;

use crate::cve::{Dependency, Ecosystem};
use crate::error::Result;
use crate::finding::Finding;

/// Filenames recognised as MCP configuration files, across JSON, YAML and
/// TOML. `.mcp.*` dotfile variants are included because that is the
/// convention Claude Code and similar clients use for project-local config.
const RECOGNISED_NAMES: &[&str] = &[
    "mcp.json",
    ".mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "mcp.yaml",
    "mcp.yml",
    ".mcp.yaml",
    ".mcp.yml",
    "mcp_config.yaml",
    "mcp_config.yml",
    "claude_desktop_config.yaml",
    "claude_desktop_config.yml",
    "mcp.toml",
    ".mcp.toml",
    "mcp_config.toml",
    "claude_desktop_config.toml",
];

/// True if this path is an MCP configuration file we know how to inspect.
#[must_use]
pub fn is_mcp_config(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| RECOGNISED_NAMES.contains(&name))
}

/// Parse and inspect one MCP config file. `relative_path` is used in
/// findings, and its extension selects the parser (JSON, YAML, or TOML).
///
/// Returns findings, or an error only if the file is unreadable — a
/// malformed config is itself a reportable condition (`BAS-MCP-000`), not an
/// error, so this only ever returns `Err` for problems outside the config's
/// own content.
///
/// # Errors
///
/// This implementation has no I/O of its own — `contents` is already
/// in hand — so it always returns `Ok`. The `Result` return type is kept so
/// a future caller-side failure mode does not require an API change.
pub fn inspect(relative_path: &Path, contents: &str) -> Result<Vec<Finding>> {
    Ok(inspect_config(relative_path, contents).0)
}

/// As [`inspect`], and also says whether the config parsed.
///
/// The boolean is `true` when the contents parsed as the format the path's
/// extension names, and `false` when the only finding is the `BAS-MCP-000`
/// malformed-config defect. The parse happens once, so a caller that needs
/// both the findings and the verdict does not parse twice.
#[must_use]
pub fn inspect_config(relative_path: &Path, contents: &str) -> (Vec<Finding>, bool) {
    let format = model::Format::detect(relative_path);
    match model::parse(format, contents) {
        Ok(config) => (checks::run_all(&config, relative_path, contents), true),
        Err(reason) => (
            vec![checks::malformed_finding(relative_path, contents, &reason)],
            false,
        ),
    }
}

#[cfg(test)]
mod dependency_tests {
    use super::*;

    #[test]
    fn a_pinned_npx_server_becomes_an_npm_dependency() {
        let config = r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2026.7.10","/srv"]}}}"#;

        let deps = server_dependencies(Path::new("mcp.json"), config);

        assert_eq!(deps.len(), 1, "{deps:#?}");
        assert_eq!(deps[0].name, "@modelcontextprotocol/server-filesystem");
        assert_eq!(deps[0].version, "2026.7.10");
        assert_eq!(deps[0].ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn a_pinned_uvx_server_becomes_a_pypi_dependency() {
        let config = r#"{"mcpServers":{"rb":{"command":"uvx","args":["runbook-server@1.4.0"]}}}"#;

        let deps = server_dependencies(Path::new("mcp.json"), config);

        assert_eq!(deps.len(), 1, "{deps:#?}");
        assert_eq!(deps[0].name, "runbook-server");
        assert_eq!(deps[0].ecosystem, Ecosystem::PyPi);
    }

    #[test]
    fn an_unpinned_server_yields_no_dependency() {
        // Nothing to query, and BAS-MCP-005 already reports it.
        let config = r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}"#;

        assert_eq!(
            server_dependencies(Path::new("mcp.json"), config),
            Vec::<crate::cve::Dependency>::new()
        );
    }

    #[test]
    fn a_local_interpreter_yields_no_dependency() {
        let config = r#"{"mcpServers":{"own":{"command":"python","args":["-m","our_server"]}}}"#;

        assert_eq!(
            server_dependencies(Path::new("mcp.json"), config),
            Vec::<crate::cve::Dependency>::new()
        );
    }

    #[test]
    fn a_malformed_config_yields_no_dependency_rather_than_panicking() {
        // inspect() already reports the malformed file; reporting it twice
        // would be worse than reporting it once.
        assert_eq!(
            server_dependencies(Path::new("mcp.json"), "{ not json"),
            Vec::<crate::cve::Dependency>::new()
        );
    }

    #[test]
    fn scoped_names_keep_their_leading_at() {
        assert_eq!(
            split_pinned("@scope/name@1.2.3"),
            Some(("@scope/name".to_owned(), "1.2.3".to_owned()))
        );
        assert_eq!(split_pinned("@scope/name"), None);
        assert_eq!(
            split_pinned("plain@2.0.0"),
            Some(("plain".to_owned(), "2.0.0".to_owned()))
        );
        assert_eq!(split_pinned("plain"), None);
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Kind, Severity};

    #[test]
    fn recognises_known_names_and_rejects_others() {
        for name in RECOGNISED_NAMES {
            assert!(
                is_mcp_config(Path::new(name)),
                "{name} should be recognised"
            );
            assert!(
                is_mcp_config(Path::new(&format!("nested/dir/{name}"))),
                "{name} should be recognised in a subdirectory"
            );
        }
        assert!(!is_mcp_config(Path::new("package.json")));
        assert!(!is_mcp_config(Path::new("Cargo.toml")));
        assert!(!is_mcp_config(Path::new("config.yaml")));
    }

    #[test]
    fn malformed_config_reports_bas_mcp_000_not_an_error() {
        let result = inspect(Path::new("mcp.json"), "{ not valid json");
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "BAS-MCP-000");
        assert_eq!(findings[0].kind, Kind::Defect);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn empty_config_produces_no_findings() {
        let findings = inspect(Path::new("mcp.json"), r#"{"mcpServers": {}}"#).unwrap();
        assert_eq!(findings, Vec::<crate::finding::Finding>::new());
    }

    /// The headline test: one logical config, expressed in JSON, YAML and
    /// TOML, must produce the same findings — same rule, same kind, same
    /// severity, same confidence, same categories — regardless of format.
    /// Line numbers are allowed to differ between formats (the files are
    /// laid out differently), so the comparison ignores location.
    #[test]
    fn same_config_in_json_yaml_toml_produces_same_findings() {
        let json = r#"
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
              "env": { "API_TOKEN": "sk-live-abc123def456ghi789jkl" }
            },
            "remote": {
              "url": "http://internal.example.com/mcp",
              "headers": {},
              "tools": "*"
            }
          }
        }
        "#;

        let yaml = r#"
mcpServers:
  filesystem:
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/"
    env:
      API_TOKEN: sk-live-abc123def456ghi789jkl
  remote:
    url: http://internal.example.com/mcp
    headers: {}
    tools: "*"
"#;

        let toml = r#"
[mcpServers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/"]

[mcpServers.filesystem.env]
API_TOKEN = "sk-live-abc123def456ghi789jkl"

[mcpServers.remote]
url = "http://internal.example.com/mcp"
tools = "*"
headers = {}
"#;

        let json_findings = inspect(Path::new("mcp.json"), json).unwrap();
        let yaml_findings = inspect(Path::new("mcp.yaml"), yaml).unwrap();
        let toml_findings = inspect(Path::new("mcp.toml"), toml).unwrap();

        assert_eq!(json_findings.len(), 5, "json: {json_findings:#?}");

        let fingerprint = |findings: &[Finding]| -> Vec<(String, Kind, Severity, Confidence)> {
            let mut rows: Vec<_> = findings
                .iter()
                .map(|f| (f.rule_id.clone(), f.kind, f.severity, f.confidence))
                .collect();
            rows.sort();
            rows
        };

        let json_fp = fingerprint(&json_findings);
        let yaml_fp = fingerprint(&yaml_findings);
        let toml_fp = fingerprint(&toml_findings);

        assert_eq!(json_fp, yaml_fp, "json vs yaml diverged");
        assert_eq!(json_fp, toml_fp, "json vs toml diverged");

        let mut rule_ids: Vec<&str> = json_findings.iter().map(|f| f.rule_id.as_str()).collect();
        rule_ids.sort_unstable();
        assert_eq!(
            rule_ids,
            [
                "BAS-MCP-001",
                "BAS-MCP-002",
                "BAS-MCP-003",
                "BAS-MCP-004",
                "BAS-MCP-005",
            ],
            "this config is vulnerable on five independent axes, including an \
             unpinned registry launch"
        );
    }
}

/// The MCP servers this config launches from a package registry, as
/// dependencies the CVE lookup can query.
///
/// An MCP server is the one dependency nothing normally vets. It does not
/// appear in `package.json` or `requirements.txt`, so a manifest-driven CVE
/// scan never sees it — yet it runs inside the agent's trust boundary with
/// whatever scope this config grants it.
///
/// Only pinned servers are returned. An unpinned one has no version to query,
/// and is already reported by `BAS-MCP-005`.
///
/// A config this cannot parse yields nothing rather than an error: [`inspect`]
/// already reports it as a finding, and reporting one broken file twice is
/// worse than reporting it once.
#[must_use]
pub fn server_dependencies(relative_path: &Path, contents: &str) -> Vec<Dependency> {
    let format = model::Format::detect(relative_path);
    let Ok(config) = model::parse(format, contents) else {
        return Vec::new();
    };

    let mut servers: Vec<(&String, &model::ServerEntry)> = config.mcp_servers.iter().collect();
    servers.sort_by_key(|(name, _)| *name);

    servers
        .into_iter()
        .filter_map(|(_, entry)| launched_package(entry))
        .filter_map(|(ecosystem, specifier)| {
            let (name, version) = split_pinned(&specifier)?;
            let (line, declaration) = checks::locate(contents, &specifier);
            Some(Dependency {
                name,
                version,
                ecosystem,
                file: relative_path.to_path_buf(),
                line,
                declaration,
            })
        })
        .collect()
}

/// The registry and package specifier an entry launches, if any.
fn launched_package(entry: &model::ServerEntry) -> Option<(Ecosystem, String)> {
    let command = entry.command.as_deref()?;
    let launcher = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();

    let ecosystem = match launcher.as_str() {
        "npx" | "pnpx" | "bunx" => Ecosystem::Npm,
        "uvx" => Ecosystem::PyPi,
        // A local interpreter resolves nothing from a registry.
        _ => return None,
    };

    let package = entry.args.iter().find(|arg| !arg.starts_with('-'))?;
    Some((ecosystem, package.clone()))
}

/// Split `name@version`, keeping a leading `@` as part of a scoped name.
///
/// `@scope/name@1.2.3` -> `("@scope/name", "1.2.3")`, and `@scope/name` -> None
/// because there is no version to query.
fn split_pinned(specifier: &str) -> Option<(String, String)> {
    let scoped = specifier.starts_with('@');
    let search_from = usize::from(scoped);
    let at = specifier.get(search_from..)?.rfind('@')? + search_from;
    let (name, version) = specifier.split_at(at);
    let version = version.strip_prefix('@')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_owned(), version.to_owned()))
}
