//! The alert a watcher raises for one finding, and the text-safety rules that
//! apply to everything in it.

use sha2::{Digest, Sha256};

use crate::finding::{Finding, Severity};

/// The longest text field, in characters, that an alert carries.
const MAX_FIELD_CHARS: usize = 200;

/// One reportable finding, reduced to what may leave the process.
///
/// Every text field has been through [`sanitize`]: printable ASCII only and at
/// most 200 characters, so it is safe to print to a terminal and to embed in
/// a message. The file's own text is untrusted, which is why the snippet is
/// kept for the local terminal only and is never part of a delivered message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// Identity of the alert: 64 lowercase hex characters, a SHA-256 over the
    /// rule id, the path and the normalised snippet. The line number is not
    /// part of it, so moving a line does not make a new alert.
    pub key: String,
    /// The rule that matched, such as `BAS-SKILL-013`.
    pub rule_id: String,
    /// How severe the rule rates the finding.
    pub severity: Severity,
    /// The rule's short title, sanitised.
    pub title: String,
    /// The file's path relative to the watched root, sanitised.
    pub path: String,
    /// The 1-based line of the match.
    pub line: usize,
    /// The matched text, sanitised.
    pub snippet: String,
}

impl Alert {
    /// Builds the alert for `finding`.
    #[must_use]
    pub fn from_finding(finding: &Finding) -> Self {
        let raw_path = finding.location.file.to_string_lossy().replace('\\', "/");
        Self {
            key: alert_key(&finding.rule_id, &raw_path, &finding.snippet),
            rule_id: sanitize(&finding.rule_id),
            severity: finding.severity,
            title: sanitize(&finding.title),
            path: sanitize(&raw_path),
            line: finding.location.line,
            snippet: sanitize(&finding.snippet),
        }
    }
}

/// Replaces every character that is not printable ASCII with `?` and keeps at
/// most 200 characters.
///
/// Control characters (including the escape that starts a terminal sequence),
/// bidirectional overrides, zero-width characters and all other non-ASCII text
/// become a single `?` each, so nothing in a scanned file can redraw a
/// terminal or reorder the text of a message.
#[must_use]
pub fn sanitize(text: &str) -> String {
    text.chars()
        .take(MAX_FIELD_CHARS)
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .collect()
}

/// The text with ASCII letters lowercased and every run of whitespace collapsed
/// to one space, trimmed.
fn normalize(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// The hex SHA-256 of `rule_id`, `path` and the normalised `snippet`, separated
/// by NUL bytes.
fn alert_key(rule_id: &str, path: &str, snippet: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(path.as_bytes());
    hasher.update([0]);
    hasher.update(normalize(snippet).as_bytes());
    hex(&hasher.finalize())
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_terminal_escapes() {
        let clean = sanitize("a\u{1b}[31mred\u{1b}[0m\nb\tc");
        assert_eq!(clean, "a?[31mred?[0m?b?c");
        assert!(!clean.contains('\u{1b}'));
    }

    #[test]
    fn sanitize_replaces_bidi_and_zero_width_characters() {
        let clean = sanitize("ok\u{202e}evil\u{200b}\u{2066}x\u{feff}y\u{e9}");
        assert_eq!(clean, "ok?evil??x?y?");
        assert!(clean.is_ascii());
    }

    #[test]
    fn sanitize_caps_the_length() {
        assert_eq!(sanitize(&"a".repeat(500)).len(), 200);
        assert_eq!(sanitize(&"\u{202e}".repeat(500)).chars().count(), 200);
    }

    #[test]
    fn key_ignores_case_and_whitespace_but_not_the_rule_or_path() {
        let base = alert_key("R1", "a.md", "Delete  everything\n now");
        assert_eq!(base, alert_key("R1", "a.md", "delete everything now"));
        assert_ne!(base, alert_key("R2", "a.md", "delete everything now"));
        assert_ne!(base, alert_key("R1", "b.md", "delete everything now"));
        assert_ne!(base, alert_key("R1", "a.md", "delete everything"));
        assert_eq!(base.len(), 64);
    }
}
