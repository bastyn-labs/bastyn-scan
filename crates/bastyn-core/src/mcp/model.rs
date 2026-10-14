//! The common shape an MCP configuration file is parsed into, regardless of
//! whether it was written as JSON, YAML, or TOML.
//!
//! Every check in [`super::checks`] runs against [`McpConfig`] only, never
//! against the raw text of one format. That is what makes the same logical
//! config produce the same findings no matter how it was serialised.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// One MCP configuration file, normalised across JSON, YAML and TOML.
///
/// Unknown top-level fields are ignored rather than rejected — real configs
/// carry vendor extensions we do not need to understand.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct McpConfig {
    /// The declared servers, keyed by name. `servers` is accepted as an
    /// alias for `mcpServers` — both spellings appear in the wild.
    #[serde(alias = "servers", default)]
    pub(crate) mcp_servers: HashMap<String, ServerEntry>,
    /// A client-wide auto-approve setting, applying to every server this
    /// config declares. Same shape as [`ServerEntry::auto_approve`].
    #[serde(default)]
    pub(crate) auto_approve: Option<serde_json::Value>,
    /// A client-wide always-allow setting. Same shape as
    /// [`ServerEntry::always_allow`].
    #[serde(default)]
    pub(crate) always_allow: Option<serde_json::Value>,
}

/// One MCP server entry.
///
/// Every field is optional: an absent field is not itself a finding, and
/// real-world configs vary in which optional fields they set.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerEntry {
    /// The launcher command, e.g. `npx`, `uvx`, `node`, `python`.
    ///
    /// Needed to tell a package-manager launcher (which resolves a version at
    /// run time) from a local interpreter invocation (which does not).
    #[serde(default)]
    pub(crate) command: Option<String>,
    /// Arguments passed to the launcher command.
    #[serde(default)]
    pub(crate) args: Vec<String>,
    /// Environment variables passed to `command`.
    ///
    /// Values are kept as [`serde_json::Value`] rather than [`String`] so a
    /// config that puts a number or boolean in `env` still parses — only the
    /// checks that care about string content look at the value's shape.
    #[serde(default)]
    pub(crate) env: HashMap<String, serde_json::Value>,
    /// The remote endpoint, for an `http`/`sse` server.
    #[serde(default)]
    pub(crate) url: Option<String>,
    /// Headers sent to `url`.
    #[serde(default)]
    pub(crate) headers: HashMap<String, serde_json::Value>,
    /// The transport this entry declares under the `type` key, if any. Kept
    /// as a raw value, and separate from [`Self::transport_name`], so an
    /// entry that sets both keys, or sets either to something unexpected,
    /// still parses instead of becoming a `BAS-MCP-000` finding.
    #[serde(default, rename = "type")]
    pub(crate) transport_type: Option<serde_json::Value>,
    /// The transport this entry declares under the `transport` key, if any.
    #[serde(default, rename = "transport")]
    pub(crate) transport_name: Option<serde_json::Value>,
    /// A `tools` grant: `"*"`, an array of tool names, or absent.
    #[serde(default)]
    pub(crate) tools: Option<serde_json::Value>,
    /// A `permissions` grant, same shape as `tools`.
    #[serde(default)]
    pub(crate) permissions: Option<serde_json::Value>,
    /// An `allowedTools` grant, same shape as `tools`.
    #[serde(default)]
    pub(crate) allowed_tools: Option<serde_json::Value>,
    /// An `autoApprove` setting — Cline/Kiro/VS Code MCP clients' field for
    /// skipping the human confirmation prompt before a tool call runs. Either
    /// a boolean (`true` approves every tool) or an array of tool names
    /// (`[]` approves none, `["*"]` approves every tool the same as `true`).
    #[serde(default)]
    pub(crate) auto_approve: Option<serde_json::Value>,
    /// An `alwaysAllow` setting — Roo Code/Cline's name for the same idea as
    /// `autoApprove`, same shape.
    #[serde(default)]
    pub(crate) always_allow: Option<serde_json::Value>,
}

/// How a server is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    /// The client launches a local program and talks over its standard streams.
    Stdio,
    /// One HTTP endpoint accepting POST.
    StreamableHttp,
    /// The older HTTP+SSE transport.
    Sse,
    /// A `url` with no declared transport.
    RemoteUnspecified,
}

impl Transport {
    /// Human-readable name used in finding descriptions.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::StreamableHttp => "Streamable HTTP",
            Self::Sse => "SSE",
            Self::RemoteUnspecified => "remote",
        }
    }
}

impl ServerEntry {
    /// The transport this entry uses: an explicit, recognised `type` or
    /// `transport` value wins; otherwise a `url` means a remote server and a
    /// `command` means stdio. A URL path is never used to guess SSE.
    pub(crate) fn transport(&self) -> Option<Transport> {
        let declared = [self.transport_type.as_ref(), self.transport_name.as_ref()]
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .find_map(parse_transport_name);
        if declared.is_some() {
            return declared;
        }
        if self.url.is_some() {
            Some(Transport::RemoteUnspecified)
        } else if self.command.is_some() {
            Some(Transport::Stdio)
        } else {
            None
        }
    }
}

/// Map a declared transport name to a [`Transport`]. The accepted spellings
/// are the ones MCP clients document; anything else is ignored.
fn parse_transport_name(name: &str) -> Option<Transport> {
    match name.trim().to_ascii_lowercase().as_str() {
        "stdio" => Some(Transport::Stdio),
        "sse" => Some(Transport::Sse),
        "http" | "streamable-http" | "streamablehttp" | "streamable_http" => {
            Some(Transport::StreamableHttp)
        }
        _ => None,
    }
}

/// Which serialisation format a config file's text is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// `.json` and dotfile variants such as `.mcp.json`.
    Json,
    /// `.yaml` / `.yml`.
    Yaml,
    /// `.toml`.
    Toml,
}

impl Format {
    /// Guess the format from the file extension. Anything unrecognised is
    /// treated as JSON, the most common shape and the one every recognised
    /// filename without a YAML/TOML extension uses.
    pub(crate) fn detect(path: &Path) -> Self {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("yaml" | "yml") => Self::Yaml,
            Some("toml") => Self::Toml,
            _ => Self::Json,
        }
    }
}

/// Parse `contents` as `format` into the common config shape.
///
/// # Errors
///
/// Returns the underlying parser's error message on syntactically invalid
/// input. This is a normal, expected outcome — the caller turns it into a
/// `BAS-MCP-000` finding rather than propagating it.
pub(crate) fn parse(format: Format, contents: &str) -> Result<McpConfig, String> {
    match format {
        Format::Json => serde_json::from_str(contents).map_err(|error| error.to_string()),
        Format::Yaml => serde_yaml_ng::from_str(contents).map_err(|error| error.to_string()),
        Format::Toml => toml::from_str(contents).map_err(|error| error.to_string()),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    #[test]
    fn detects_format_from_extension() {
        assert_eq!(Format::detect(Path::new("mcp.json")), Format::Json);
        assert_eq!(Format::detect(Path::new(".mcp.json")), Format::Json);
        assert_eq!(Format::detect(Path::new("mcp.yaml")), Format::Yaml);
        assert_eq!(Format::detect(Path::new("mcp.yml")), Format::Yaml);
        assert_eq!(Format::detect(Path::new("mcp.toml")), Format::Toml);
        assert_eq!(
            Format::detect(Path::new("claude_desktop_config.json")),
            Format::Json
        );
    }

    #[test]
    fn servers_alias_is_accepted() {
        let config: McpConfig = serde_json::from_str(r#"{"servers": {"a": {}}}"#).unwrap();
        assert!(config.mcp_servers.contains_key("a"));
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        let config = parse(
            Format::Json,
            r#"{"mcpServers": {}, "$schema": "https://example.com", "vendorExtension": 1}"#,
        );
        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    fn entry(json: &str) -> ServerEntry {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn explicit_type_wins_over_inference() {
        assert_eq!(
            entry(r#"{"url": "https://x/mcp", "type": "sse"}"#).transport(),
            Some(Transport::Sse)
        );
        assert_eq!(
            entry(r#"{"url": "https://x/mcp", "type": "HTTP"}"#).transport(),
            Some(Transport::StreamableHttp)
        );
        assert_eq!(
            entry(r#"{"url": "https://x/mcp", "transport": "streamable-http"}"#).transport(),
            Some(Transport::StreamableHttp)
        );
        assert_eq!(
            entry(r#"{"command": "node", "type": "stdio"}"#).transport(),
            Some(Transport::Stdio)
        );
    }

    #[test]
    fn transport_is_inferred_when_not_declared() {
        assert_eq!(
            entry(r#"{"url": "https://x/mcp"}"#).transport(),
            Some(Transport::RemoteUnspecified)
        );
        assert_eq!(
            entry(r#"{"command": "node"}"#).transport(),
            Some(Transport::Stdio)
        );
        assert_eq!(entry("{}").transport(), None);
    }

    #[test]
    fn a_url_path_ending_in_sse_is_not_read_as_the_sse_transport() {
        assert_eq!(
            entry(r#"{"url": "https://x/sse"}"#).transport(),
            Some(Transport::RemoteUnspecified)
        );
    }

    #[test]
    fn type_and_transport_together_or_odd_shapes_still_parse() {
        let both = parse(
            Format::Json,
            r#"{"mcpServers": {"a": {"url": "https://x", "type": "http", "transport": "sse"}}}"#,
        );
        assert!(both.is_ok(), "{both:?}");
        let object = parse(
            Format::Json,
            r#"{"mcpServers": {"a": {"url": "https://x", "transport": {"kind": "http"}}}}"#,
        );
        assert!(object.is_ok(), "{object:?}");
        let number = parse(
            Format::Json,
            r#"{"mcpServers": {"a": {"command": "x", "type": 3}}}"#,
        );
        assert!(number.is_ok(), "{number:?}");
        // An unrecognised or non-string value falls back to inference.
        assert_eq!(
            entry(r#"{"command": "x", "type": 3}"#).transport(),
            Some(Transport::Stdio)
        );
    }
}
