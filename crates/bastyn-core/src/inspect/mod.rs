//! Capturing the tools an MCP server offers.
//!
//! This module holds the pieces shared by the transports: the snapshot file
//! format, the guard that refuses unsafe addresses, the JSON-RPC message
//! builders, the Server-Sent Events reader, the Streamable HTTP client, and the stdio
//! client. [`inspect`] ties them together for one requested server.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::mcp::model::Transport;

mod error;
pub(crate) mod guard;
mod http;
pub(crate) mod jsonrpc;
pub mod snapshot;
pub(crate) mod sse;
mod stdio;

pub use error::InspectError;
pub use http::{HttpTarget, capture_http};
pub use snapshot::{SNAPSHOT_SCHEMA, ServerInfo, Snapshot};
pub use stdio::{StdioTarget, capture_stdio};

/// Time, size and page caps applied to every capture.
///
/// The defaults are chosen values: a server that is slow, large or endless is
/// refused instead of waited for.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Longest time to wait for a connection. Default 10 seconds.
    pub connect: Duration,
    /// Longest time for one whole request, including reading the reply.
    /// Default 30 seconds.
    pub total: Duration,
    /// Largest reply body accepted, in bytes. Default 4 MiB.
    pub max_body_bytes: u64,
    /// Most `tools/list` pages followed. Default 20.
    pub max_pages: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            total: Duration::from_secs(30),
            max_body_bytes: 4 * 1024 * 1024,
            max_pages: 20,
        }
    }
}

/// Which protocol revision a server answered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// The current revision, where each request names the version.
    Modern,
    /// The earlier revision that begins with an `initialize` handshake.
    Legacy,
}

impl Era {
    /// The name written to the snapshot file.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Modern => "modern",
            Self::Legacy => "legacy",
        }
    }
}

/// The tools a server listed, and how it was asked.
#[derive(Debug, Clone)]
pub struct Capture {
    /// The protocol era the server answered in.
    pub era: Era,
    /// The protocol version used for the requests.
    pub protocol_version: String,
    /// The tool definitions exactly as the server sent them. They are data
    /// from an untrusted server and are never interpreted.
    pub tools: Vec<serde_json::Value>,
}

/// Which server to capture, and how to reach it.
#[derive(Debug, Clone)]
pub enum InspectRequest {
    /// A Streamable HTTP server named by URL.
    Http {
        /// The server's URL.
        url: String,
        /// Extra request headers, as name and value.
        headers: Vec<(String, String)>,
    },
    /// A server entry in an MCP config file.
    Config {
        /// The config file.
        path: PathBuf,
        /// The entry's name in the file.
        server: String,
        /// Whether a `command` entry may be started. Without it such an
        /// entry is refused before anything runs.
        allow_spawn: bool,
    },
}

/// True when `url` is plain `http://` to a host other than `localhost` or a
/// loopback address, so the traffic would cross a network unencrypted.
#[must_use]
pub fn is_plain_http_to_remote_host(url: &str) -> bool {
    let plain = url.parse::<ureq::http::Uri>().is_ok_and(|uri| {
        uri.scheme_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("http"))
    });
    plain && !guard::is_loopback_host(url)
}

/// True for characters that should never reach a terminal or a reader
/// unescaped: control characters (including DEL and the C1 range) and the
/// invisible format and bidirectional characters that can hide or reorder
/// text.
pub(crate) fn is_hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(
            u32::from(c),
            0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x2069
                | 0xFEFF
                | 0xE0000..=0xE007F
        )
}

/// Make text from a server safe to print: every control character, including
/// the escape byte that starts terminal sequences, and every invisible format
/// or bidirectional character becomes a visible escape such as `\u{1b}` or
/// `\u{202e}`.
#[must_use]
pub fn escape_control(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden_char(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// The host part of `url`, or the whole text when it has none.
fn host_of(url: &str) -> String {
    url.parse::<ureq::http::Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned())
}

/// Entries of a config map that hold text, in key order, so the order never
/// depends on hash-map iteration.
fn string_pairs(
    map: &std::collections::HashMap<String, serde_json::Value>,
) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = map
        .iter()
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
        .collect();
    pairs.sort();
    pairs
}

fn snapshot_of(name: String, transport: &str, capture: Capture) -> Snapshot {
    Snapshot::new(
        ServerInfo {
            name,
            transport: transport.to_owned(),
            protocol_era: capture.era.as_str().to_owned(),
            protocol_version: capture.protocol_version,
        },
        capture.tools,
    )
}

/// Capture the tool list of the requested server.
///
/// A config entry that names a command is started only when `allow_spawn` is
/// set; the refusal happens before any process exists.
///
/// # Errors
///
/// Returns an [`InspectError`] when the config cannot be read or names no
/// usable server, the entry uses the deprecated SSE transport, a command is
/// not allowed to run, or the capture itself fails.
pub fn inspect(request: &InspectRequest, limits: &Limits) -> Result<Snapshot, InspectError> {
    match request {
        InspectRequest::Http { url, headers } => {
            let target = HttpTarget {
                url: url.clone(),
                headers: headers.clone(),
            };
            let capture = capture_http(&target, limits)?;
            Ok(snapshot_of(host_of(url), "streamable-http", capture))
        }
        InspectRequest::Config {
            path,
            server,
            allow_spawn,
        } => inspect_config_entry(path, server, *allow_spawn, limits),
    }
}

fn inspect_config_entry(
    path: &Path,
    server: &str,
    allow_spawn: bool,
    limits: &Limits,
) -> Result<Snapshot, InspectError> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        InspectError::Config(format!("could not read {}: {error}", path.display()))
    })?;
    let entry = crate::mcp::load_server(path, &contents, server).map_err(InspectError::Config)?;
    if entry.transport() == Some(Transport::Sse) {
        return Err(InspectError::Refused(
            "SSE transport is not supported".to_owned(),
        ));
    }
    if let Some(url) = &entry.url {
        let target = HttpTarget {
            url: url.clone(),
            headers: string_pairs(&entry.headers),
        };
        let capture = capture_http(&target, limits)?;
        return Ok(snapshot_of(server.to_owned(), "streamable-http", capture));
    }
    if let Some(program) = &entry.command {
        if !allow_spawn {
            let command = std::iter::once(program.as_str())
                .chain(entry.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            return Err(InspectError::Refused(format!(
                "this server runs `{command}`; pass --allow-spawn to run it"
            )));
        }
        let target = StdioTarget {
            program: program.clone(),
            args: entry.args.clone(),
            env: string_pairs(&entry.env),
            cwd: None,
        };
        let capture = capture_stdio(&target, limits)?;
        return Ok(snapshot_of(server.to_owned(), "stdio", capture));
    }
    Err(InspectError::Config(format!(
        "server {server} has neither a `url` nor a `command`"
    )))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    fn config_request(
        dir: &Path,
        json: &serde_json::Value,
        server: &str,
        allow: bool,
    ) -> InspectRequest {
        let path = dir.join("mcp.json");
        std::fs::write(&path, json.to_string()).unwrap();
        InspectRequest::Config {
            path,
            server: server.to_owned(),
            allow_spawn: allow,
        }
    }

    #[test]
    fn a_command_entry_is_refused_without_allow_spawn_and_nothing_runs() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let script = format!("touch '{}'", marker.display());
        let json =
            serde_json::json!({"mcpServers": {"s": {"command": "sh", "args": ["-c", script]}}});
        let request = config_request(dir.path(), &json, "s", false);
        let error = inspect(&request, &Limits::default()).unwrap_err();
        assert!(matches!(error, InspectError::Refused(_)));
        assert!(error.to_string().contains("--allow-spawn"));
        assert!(error.to_string().contains("sh -c"));
        assert!(!marker.exists());
    }

    #[test]
    fn an_sse_entry_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::json!({"mcpServers": {"s": {"url": "http://127.0.0.1:1/sse", "type": "sse"}}});
        let request = config_request(dir.path(), &json, "s", true);
        let error = inspect(&request, &Limits::default()).unwrap_err();
        assert!(
            matches!(&error, InspectError::Refused(text) if text == "SSE transport is not supported")
        );
    }

    #[test]
    fn an_unknown_server_name_lists_the_available_ones() {
        let dir = tempfile::tempdir().unwrap();
        let json =
            serde_json::json!({"mcpServers": {"b": {"command": "x"}, "a": {"command": "y"}}});
        let request = config_request(dir.path(), &json, "zzz", true);
        let error = inspect(&request, &Limits::default()).unwrap_err();
        assert!(matches!(&error, InspectError::Config(text) if text.contains("available: a, b")));
    }

    #[test]
    fn an_entry_with_neither_url_nor_command_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::json!({"mcpServers": {"s": {}}});
        let request = config_request(dir.path(), &json, "s", true);
        assert!(matches!(
            inspect(&request, &Limits::default()),
            Err(InspectError::Config(_))
        ));
    }

    #[test]
    fn an_unreadable_or_unparseable_config_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = InspectRequest::Config {
            path: dir.path().join("none.json"),
            server: "s".into(),
            allow_spawn: true,
        };
        assert!(matches!(
            inspect(&missing, &Limits::default()),
            Err(InspectError::Config(_))
        ));
        let path = dir.path().join("mcp.json");
        std::fs::write(&path, "{ not json").unwrap();
        let broken = InspectRequest::Config {
            path,
            server: "s".into(),
            allow_spawn: true,
        };
        assert!(matches!(
            inspect(&broken, &Limits::default()),
            Err(InspectError::Config(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_allowed_stdio_entry_is_captured_under_the_config_name() {
        let dir = tempfile::tempdir().unwrap();
        let script = r#"read a; printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"]}}'; read b; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"b"},{"name":"a"}]}}'"#;
        let json =
            serde_json::json!({"mcpServers": {"fake": {"command": "sh", "args": ["-c", script]}}});
        let request = config_request(dir.path(), &json, "fake", true);
        let snapshot = inspect(&request, &Limits::default()).unwrap();
        assert_eq!(snapshot.server.name, "fake");
        assert_eq!(snapshot.server.transport, "stdio");
        assert_eq!(snapshot.server.protocol_era, "modern");
        assert_eq!(snapshot.tools[0]["name"], "a");
    }

    #[test]
    fn only_remote_plain_http_is_flagged() {
        assert!(is_plain_http_to_remote_host("http://example.com/mcp"));
        assert!(!is_plain_http_to_remote_host("https://example.com/mcp"));
        assert!(!is_plain_http_to_remote_host("http://localhost:8080/mcp"));
        assert!(!is_plain_http_to_remote_host("http://127.0.0.1/mcp"));
        assert!(!is_plain_http_to_remote_host("http://[::1]/mcp"));
    }

    #[test]
    fn control_characters_are_made_visible() {
        assert_eq!(escape_control("a\u{1b}[31mb\n"), "a\\u{1b}[31mb\\n");
        assert_eq!(escape_control("plain é"), "plain é");
        assert_eq!(escape_control("\u{7f}\u{85}"), "\\u{7f}\\u{85}");
    }

    #[test]
    fn invisible_format_and_bidirectional_characters_are_made_visible() {
        assert_eq!(escape_control("a\u{202e}b"), "a\\u{202e}b");
        for c in [
            '\u{200b}',
            '\u{200f}',
            '\u{2060}',
            '\u{2066}',
            '\u{feff}',
            '\u{e0041}',
        ] {
            let escaped = escape_control(&c.to_string());
            assert!(escaped.starts_with("\\u{"), "{escaped}");
        }
    }

    #[test]
    fn the_name_of_a_direct_capture_is_the_url_host() {
        assert_eq!(host_of("http://127.0.0.1:9/mcp"), "127.0.0.1");
        assert_eq!(host_of("not a url"), "not a url");
    }
}
