//! JSON-RPC messages and replies for the MCP calls the inspector makes.
//!
//! Checked against the 2026-07-28 specification pages (tools, discovery and
//! schema):
//!
//! - `tools/list` takes the pagination cursor as `params.cursor`, and the
//!   result carries the next page's cursor in `nextCursor`.
//! - `server/discover` returns the supported protocol versions in
//!   `supportedVersions`.
//! - Per-request metadata keys are `io.modelcontextprotocol/protocolVersion`,
//!   `.../clientInfo` and `.../clientCapabilities`.
//! - Error codes: `-32022` unsupported protocol version, `-32021` missing
//!   required client capability, `-32020` header mismatch.

use serde_json::{Value, json};

/// The current protocol revision: version and identity travel on every request.
pub(crate) const MODERN_VERSION: &str = "2026-07-28";
/// The last revision that required an `initialize` handshake.
pub(crate) const LEGACY_VERSION: &str = "2025-11-25";

/// The protocol version the server chose in its `initialize` result, or the
/// legacy constant when the field is absent, not a string, or not shaped like
/// a version (letters, digits and hyphens, at most 32 characters).
pub(crate) fn negotiated_version(result: &Value) -> String {
    result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|version| {
            !version.is_empty()
                && version.len() <= 32
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .map_or_else(|| LEGACY_VERSION.to_owned(), str::to_owned)
}

/// The `_meta` block a modern request carries.
pub(crate) fn client_meta(version: &str) -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {"name": "bastyn", "version": env!("CARGO_PKG_VERSION")},
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

/// A modern request with an optional pagination cursor.
pub(crate) fn modern_request(id: u64, method: &str, cursor: Option<&str>) -> Value {
    let mut params = json!({ "_meta": client_meta(MODERN_VERSION) });
    if let Some(cursor) = cursor {
        params["cursor"] = json!(cursor);
    }
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// The legacy `initialize` request.
pub(crate) fn legacy_initialize(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "bastyn", "version": env!("CARGO_PKG_VERSION")}
        }
    })
}

/// A legacy request (no per-request metadata) with an optional cursor.
pub(crate) fn legacy_request(id: u64, method: &str, cursor: Option<&str>) -> Value {
    let params = cursor.map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// A JSON-RPC notification (no id).
pub(crate) fn notification(method: &str) -> Value {
    json!({"jsonrpc": "2.0", "method": method})
}

/// A reply to one request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Reply {
    /// A `result` object.
    Result(Value),
    /// An `error` object.
    Error {
        /// The JSON-RPC error code.
        code: i64,
        /// The error message.
        message: String,
        /// The optional `data` member.
        data: Option<Value>,
    },
}

/// The reply in `message` if it answers request `id`.
pub(crate) fn parse_reply(message: &Value, id: u64) -> Option<Reply> {
    if message.get("id")?.as_u64()? != id {
        return None;
    }
    if let Some(result) = message.get("result") {
        return Some(Reply::Result(result.clone()));
    }
    let error = message.get("error")?;
    Some(Reply::Error {
        code: error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        message: error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        data: error.get("data").cloned(),
    })
}

/// True for the error codes only a modern server returns: unsupported
/// protocol version, missing required client capability and header mismatch.
pub(crate) fn is_recognised_modern_error(code: i64) -> bool {
    (-32022..=-32020).contains(&code)
}

/// The pagination cursor of a `tools/list` result, if there is another page.
pub(crate) fn next_cursor(result: &Value) -> Option<String> {
    result
        .get("nextCursor")
        .and_then(Value::as_str)
        .filter(|cursor| !cursor.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[expect(
    clippy::panic,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    #[test]
    fn a_modern_request_carries_version_identity_and_capabilities_in_meta() {
        let request = modern_request(7, "tools/list", None);
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["id"], 7);
        assert_eq!(request["method"], "tools/list");
        let meta = &request["params"]["_meta"];
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            MODERN_VERSION
        );
        assert_eq!(meta["io.modelcontextprotocol/clientInfo"]["name"], "bastyn");
        assert!(meta["io.modelcontextprotocol/clientCapabilities"].is_object());
        assert!(request["params"].get("cursor").is_none());
        assert_eq!(
            modern_request(8, "tools/list", Some("abc"))["params"]["cursor"],
            "abc"
        );
    }

    #[test]
    fn a_legacy_initialize_names_the_legacy_version_and_has_no_meta() {
        let request = legacy_initialize(2);
        assert_eq!(request["method"], "initialize");
        assert_eq!(request["params"]["protocolVersion"], LEGACY_VERSION);
        assert!(request["params"].get("_meta").is_none());
    }

    #[test]
    fn legacy_requests_and_notifications_have_no_meta() {
        let request = legacy_request(3, "tools/list", Some("c"));
        assert_eq!(request["params"]["cursor"], "c");
        assert!(request["params"].get("_meta").is_none());
        let note = notification("notifications/initialized");
        assert!(note.get("id").is_none());
        assert_eq!(note["method"], "notifications/initialized");
    }

    #[test]
    fn replies_are_matched_by_id_and_classified() {
        let ok = serde_json::json!({"jsonrpc": "2.0", "id": 3, "result": {"tools": []}});
        assert!(matches!(parse_reply(&ok, 3), Some(Reply::Result(_))));
        assert!(parse_reply(&ok, 4).is_none());
        let err = serde_json::json!({"jsonrpc": "2.0", "id": 3, "error": {"code": -32022, "message": "m", "data": {"supported": ["2025-11-25"]}}});
        match parse_reply(&err, 3) {
            Some(Reply::Error { code, data, .. }) => {
                assert_eq!(code, -32022);
                assert!(data.is_some());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_negotiated_version_falls_back_when_absent_or_unusable() {
        let chosen = serde_json::json!({"protocolVersion": "2025-06-18"});
        assert_eq!(negotiated_version(&chosen), "2025-06-18");
        for result in [
            serde_json::json!({}),
            serde_json::json!({"protocolVersion": 7}),
            serde_json::json!({"protocolVersion": ""}),
            serde_json::json!({"protocolVersion": "bad\r\nvalue"}),
        ] {
            assert_eq!(negotiated_version(&result), LEGACY_VERSION);
        }
    }

    #[test]
    fn modern_errors_are_recognised_by_code() {
        assert!(is_recognised_modern_error(-32022));
        assert!(is_recognised_modern_error(-32021));
        assert!(is_recognised_modern_error(-32020));
        assert!(!is_recognised_modern_error(-32601));
        assert!(!is_recognised_modern_error(-32602));
    }

    #[test]
    fn next_cursor_reads_the_pagination_field() {
        assert_eq!(
            next_cursor(&serde_json::json!({"nextCursor": "p2"})).as_deref(),
            Some("p2")
        );
        assert_eq!(next_cursor(&serde_json::json!({"tools": []})), None);
        assert_eq!(next_cursor(&serde_json::json!({"nextCursor": ""})), None);
    }
}
