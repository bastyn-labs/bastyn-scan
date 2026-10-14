//! The file `bastyn inspect-server` writes and `bastyn scan` reads back.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The `schema` value every snapshot carries.
pub const SNAPSHOT_SCHEMA: &str = "bastyn-tools-snapshot/1";

/// Which server a snapshot describes and how it was reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// The server's name in its config, or its URL host for a direct capture.
    pub name: String,
    /// `"stdio"` or `"streamable-http"`.
    pub transport: String,
    /// `"modern"` (per-request metadata) or `"legacy"` (`initialize` handshake).
    pub protocol_era: String,
    /// The protocol version spoken.
    pub protocol_version: String,
}

/// The tools a server offered, stored exactly as received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Always [`SNAPSHOT_SCHEMA`].
    pub schema: String,
    /// The server described.
    pub server: ServerInfo,
    /// Each tool object as the server returned it, sorted by name.
    pub tools: Vec<Value>,
}

fn tool_name(tool: &Value) -> &str {
    tool.get("name").and_then(Value::as_str).unwrap_or_default()
}

/// Rebuild every object through a sorted map so key order never depends on
/// which `serde_json` features another dependency turned on.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(key, inner)| (key.clone(), sorted(inner)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

impl Snapshot {
    /// Build a snapshot, ordering tools by name then by their serialised text.
    #[must_use]
    pub fn new(server: ServerInfo, tools: Vec<Value>) -> Self {
        let mut tools: Vec<Value> = tools.into_iter().map(|tool| sorted(&tool)).collect();
        tools.sort_by(|left, right| {
            tool_name(left)
                .cmp(tool_name(right))
                .then_with(|| left.to_string().cmp(&right.to_string()))
        });
        Self {
            schema: SNAPSHOT_SCHEMA.to_owned(),
            server,
            tools,
        }
    }

    /// Pretty JSON with a trailing newline.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Parse a snapshot file.
    ///
    /// # Errors
    ///
    /// Returns a message when the text is not JSON, does not have the
    /// snapshot shape, or names a different `schema`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let snapshot: Self = serde_json::from_str(text).map_err(|error| error.to_string())?;
        if snapshot.schema != SNAPSHOT_SCHEMA {
            return Err(format!("unsupported snapshot schema `{}`", snapshot.schema));
        }
        Ok(snapshot)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    fn info() -> ServerInfo {
        ServerInfo {
            name: "s".into(),
            transport: "stdio".into(),
            protocol_era: "modern".into(),
            protocol_version: "2026-07-28".into(),
        }
    }

    #[test]
    fn tools_are_sorted_by_name_and_keys_are_sorted() {
        let tools = vec![
            serde_json::json!({"name": "b", "description": "x", "inputSchema": {"z": 1, "a": 2}}),
            serde_json::json!({"name": "a", "description": "y"}),
        ];
        let text = Snapshot::new(info(), tools).to_json();
        let a = text.find("\"name\": \"a\"").unwrap();
        let b = text.find("\"name\": \"b\"").unwrap();
        assert!(a < b);
        assert!(text.find("\"a\": 2").unwrap() < text.find("\"z\": 1").unwrap());
    }

    #[test]
    fn output_is_identical_across_runs_and_round_trips() {
        let tools = vec![serde_json::json!({"name": "a", "description": null})];
        let first = Snapshot::new(info(), tools.clone()).to_json();
        let second = Snapshot::new(info(), tools).to_json();
        assert_eq!(first, second);
        assert!(first.ends_with('\n'));
        assert_eq!(Snapshot::parse(&first).unwrap().schema, SNAPSHOT_SCHEMA);
    }

    #[test]
    fn tools_without_a_name_or_with_a_null_description_are_kept() {
        let tools = vec![
            serde_json::json!({"description": null}),
            serde_json::json!({"name": "a"}),
        ];
        assert_eq!(Snapshot::new(info(), tools).tools.len(), 2);
    }

    #[test]
    fn parse_rejects_a_foreign_schema() {
        assert!(Snapshot::parse(r#"{"schema": "other/1", "server": {}, "tools": []}"#).is_err());
        assert!(Snapshot::parse("not json").is_err());
    }
}
