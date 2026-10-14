//! Reading a Server-Sent Events body for the one JSON-RPC message wanted.

use serde_json::Value;

use super::jsonrpc::parse_reply;

/// The first event whose `data` is a JSON-RPC message answering request `id`.
///
/// Handles `\r\n` and `\n` line endings, comment lines (a leading `:`),
/// events split over several `data:` lines, and events that are not JSON
/// (skipped).
pub(crate) fn message_with_id(body: &str, id: u64) -> Option<Value> {
    let normalised = body.replace("\r\n", "\n");
    for event in normalised.split("\n\n") {
        let data: Vec<&str> = event
            .lines()
            .filter(|line| !line.starts_with(':'))
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|value| value.strip_prefix(' ').unwrap_or(value))
            .collect();
        if data.is_empty() {
            continue;
        }
        if let Ok(message) = serde_json::from_str::<Value>(&data.join("\n"))
            && parse_reply(&message, id).is_some()
        {
            return Some(message);
        }
    }
    None
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_message_with_the_wanted_id_among_several_events() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"ok\":true}}\n\n";
        let message = message_with_id(body, 5).unwrap();
        assert_eq!(message["result"]["ok"], true);
    }

    #[test]
    fn crlf_line_endings_and_keep_alive_comments_are_handled() {
        let body = ":\r\n\r\nid: 1\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":9,\"result\":{}}\r\n\r\n:\r\n";
        assert!(message_with_id(body, 9).is_some());
    }

    #[test]
    fn returns_none_when_no_event_matches_or_data_is_not_json() {
        assert!(message_with_id("data: not json\n\n", 1).is_none());
        assert!(message_with_id("event: ping\n\n", 1).is_none());
        assert!(message_with_id("", 1).is_none());
    }
}
