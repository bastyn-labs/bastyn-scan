//! Known-provider token literals: the `BAS-ZT1-023` check.
//!
//! A committed value is reported only when it has the exact shape a provider
//! gives its tokens: a fixed prefix, an alphabet, and a length. Nothing here
//! looks at a variable name, so the word "token" alone never produces a
//! finding, and a generic `token = "<anything>"` assignment is not this rule's
//! business (`BAS-ZT1-010`/`-011` own that).
//!
//! Like the `.env` check, this is Rust rather than a pattern in `rules/*.yml`:
//! the value has to be judged in any text file the scan reads (source,
//! Markdown, JSON, `.env`), and the URL, path and digest exclusions need the
//! text around the value, which a metavariable regex cannot see.
//!
//! # Formats
//!
//! | Provider | Shape |
//! | --- | --- |
//! | GitHub | `ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_`, then 36 letters or digits |
//! | AWS access key ID | `AKIA` or `ASIA`, then 16 upper-case letters or digits |
//! | Google API key | `AIza`, then 35 letters, digits, `_` or `-` |
//! | npm | `npm_`, then 36 letters or digits |
//! | Stripe live secret key | `sk_live_`, then 24 or more letters or digits |
//!
//! GitHub tokens end in a checksum; it is not verified, so the check relies on
//! prefix, exact length and alphabet. A 40-character bare AWS secret key has no
//! prefix and is never reported.
//!
//! # What is never reported
//!
//! - A value that is part of a URL (the surrounding word holds `://`), a
//!   Markdown link target (`](`), or a file path (a `/` or `\` touches the
//!   value), or that sits in a digest (`sha256:`, `sha512-`, an `@<sha>` pin).
//! - A value whose body is only hexadecimal digits.
//! - A placeholder: one of the words below, a run of six or more consecutive
//!   letters or digits (`abcdef`, `654321`), or a run of eight or more of one
//!   character.
//! - Test-mode keys (`sk_test_`), which do not have a matching prefix.
//!
//! A value must also stand alone: it may not be glued to letters, digits,
//! `_` or `-` on either side, so a longer string that merely contains it is not
//! a token.

use std::path::Path;

use crate::category::Category;
use crate::finding::{Confidence, Finding, Kind, Location, Severity};
use crate::test_path::is_test_path;

/// Words that mark a value as a placeholder, matched case-insensitively
/// anywhere in the candidate.
const PLACEHOLDER_WORDS: &[&str] = &[
    "example",
    "test",
    "dummy",
    "sample",
    "placeholder",
    "changeme",
    "xxx",
    "your-key-here",
    "your_key_here",
    "redacted",
];

/// Shortest run of consecutive letters or digits that marks a placeholder.
const SEQUENTIAL_RUN: usize = 6;

/// Shortest run of one repeated character that marks a placeholder.
const REPEATED_RUN: usize = 8;

/// Which characters may follow a prefix.
#[derive(Clone, Copy)]
enum Alphabet {
    Base62,
    UpperAlnum,
    UrlSafe,
}

impl Alphabet {
    fn contains(self, byte: u8) -> bool {
        match self {
            Self::Base62 => byte.is_ascii_alphanumeric(),
            Self::UpperAlnum => byte.is_ascii_uppercase() || byte.is_ascii_digit(),
            Self::UrlSafe => byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-',
        }
    }
}

/// How many body characters follow the prefix.
#[derive(Clone, Copy)]
enum Length {
    Exactly(usize),
    AtLeast(usize),
}

struct Format {
    provider: &'static str,
    prefix: &'static str,
    alphabet: Alphabet,
    length: Length,
}

const FORMATS: &[Format] = &[
    Format {
        provider: "GitHub token",
        prefix: "ghp_",
        alphabet: Alphabet::Base62,
        length: Length::Exactly(36),
    },
    Format {
        provider: "GitHub token",
        prefix: "gho_",
        alphabet: Alphabet::Base62,
        length: Length::Exactly(36),
    },
    Format {
        provider: "GitHub token",
        prefix: "ghu_",
        alphabet: Alphabet::Base62,
        length: Length::Exactly(36),
    },
    Format {
        provider: "GitHub token",
        prefix: "ghs_",
        alphabet: Alphabet::Base62,
        length: Length::Exactly(36),
    },
    Format {
        provider: "GitHub token",
        prefix: "ghr_",
        alphabet: Alphabet::Base62,
        length: Length::Exactly(36),
    },
    Format {
        provider: "AWS access key ID",
        prefix: "AKIA",
        alphabet: Alphabet::UpperAlnum,
        length: Length::Exactly(16),
    },
    Format {
        provider: "AWS access key ID",
        prefix: "ASIA",
        alphabet: Alphabet::UpperAlnum,
        length: Length::Exactly(16),
    },
    Format {
        provider: "Google API key",
        prefix: "AIza",
        alphabet: Alphabet::UrlSafe,
        length: Length::Exactly(35),
    },
    Format {
        provider: "npm token",
        prefix: "npm_",
        alphabet: Alphabet::Base62,
        length: Length::Exactly(36),
    },
    Format {
        provider: "Stripe live secret key",
        prefix: "sk_live_",
        alphabet: Alphabet::Base62,
        length: Length::AtLeast(24),
    },
];

/// A byte that may not touch either end of a token: the token would then be
/// a slice of a longer string.
fn is_glue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// Bytes that end a "word" when extracting the text around a candidate.
fn is_word_break(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'`' | b',')
}

/// The token starting at `start` in `line`, if one of [`FORMATS`] matches
/// there exactly. Returns the end offset (exclusive).
fn match_at(line: &[u8], start: usize, format: &Format) -> Option<usize> {
    let body_start = start + format.prefix.len();
    let body_len = line[body_start..]
        .iter()
        .take_while(|byte| format.alphabet.contains(**byte))
        .count();
    let end = body_start + body_len;
    let length_ok = match format.length {
        Length::Exactly(n) => body_len == n,
        Length::AtLeast(n) => body_len >= n,
    };
    if !length_ok {
        return None;
    }
    // Exact formats must not be a prefix of a longer run; an unbounded one
    // has already consumed every body character.
    if line.get(end).is_some_and(|byte| is_glue(*byte)) {
        return None;
    }
    Some(end)
}

/// Whether `token` reads as a placeholder rather than a generated value.
fn is_placeholder(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if PLACEHOLDER_WORDS.iter().any(|word| lower.contains(word)) {
        return true;
    }
    has_repeated_run(lower.as_bytes()) || has_sequential_run(lower.as_bytes())
}

fn has_repeated_run(bytes: &[u8]) -> bool {
    bytes
        .chunk_by(|a, b| a == b)
        .any(|run| run.len() >= REPEATED_RUN)
}

/// A run of `SEQUENTIAL_RUN` letters or digits, each one step above (or
/// below) the last, within the same class.
fn has_sequential_run(bytes: &[u8]) -> bool {
    let same_class = |a: u8, b: u8| {
        (a.is_ascii_lowercase() && b.is_ascii_lowercase())
            || (a.is_ascii_digit() && b.is_ascii_digit())
    };
    for step in [1_i16, -1_i16] {
        let mut run = 1;
        for pair in bytes.windows(2) {
            if same_class(pair[0], pair[1]) && i16::from(pair[1]) - i16::from(pair[0]) == step {
                run += 1;
                if run >= SEQUENTIAL_RUN {
                    return true;
                }
            } else {
                run = 1;
            }
        }
    }
    false
}

/// Whether the text around the token makes it part of a URL, a Markdown link
/// target, a file path or a digest.
fn is_embedded(line: &[u8], start: usize, end: usize) -> bool {
    // A path separator, base64 character or digest/pin marker touching the
    // token means it is a slice of something that is not a credential.
    if start > 0 && matches!(line[start - 1], b'/' | b'\\' | b'+' | b':' | b'@') {
        return true;
    }
    if line
        .get(end)
        .is_some_and(|byte| matches!(byte, b'/' | b'\\' | b'+'))
    {
        return true;
    }

    let word_start = line[..start]
        .iter()
        .rposition(|byte| is_word_break(*byte))
        .map_or(0, |index| index + 1);
    let word_end = line[end..]
        .iter()
        .position(|byte| is_word_break(*byte))
        .map_or(line.len(), |index| end + index);
    let word = &line[word_start..word_end];
    let contains = |needle: &[u8]| word.windows(needle.len()).any(|window| window == needle);

    contains(b"://")
        || contains(b"](")
        || word.starts_with(b"sha256:")
        || word.starts_with(b"sha512-")
        || word.starts_with(b"sha1-")
        || word.starts_with(b"sha384-")
}

/// Whether every body character is a hexadecimal digit, the shape of a
/// truncated digest rather than a generated token.
fn body_is_hex(token: &str, prefix: &str) -> bool {
    let body = &token[prefix.len()..];
    !body.is_empty() && body.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Every provider token on `line`, as `(provider, start offset)`.
fn tokens_in_line(line: &str) -> Vec<(&'static str, usize)> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    for format in FORMATS {
        for (start, _) in line.match_indices(format.prefix) {
            if start > 0 && is_glue(bytes[start - 1]) {
                continue;
            }
            let Some(end) = match_at(bytes, start, format) else {
                continue;
            };
            let token = &line[start..end];
            if is_placeholder(token)
                || body_is_hex(token, format.prefix)
                || is_embedded(bytes, start, end)
            {
                continue;
            }
            found.push((format.provider, start));
        }
    }
    found.sort_by_key(|(_, start)| *start);
    found
}

/// Inspect the text of one file for provider token literals.
///
/// `already_reported_lines` holds the 1-indexed lines on which another
/// credential finding has already been produced; a second finding for the
/// same line is not added. A finding in a test path is an observation.
#[must_use]
pub(crate) fn inspect(
    relative_path: &Path,
    contents: &str,
    already_reported_lines: &[usize],
) -> Vec<Finding> {
    let kind = if is_test_path(relative_path) {
        Kind::Observation
    } else {
        Kind::Defect
    };

    let mut findings = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let number = index + 1;
        if already_reported_lines.contains(&number) {
            continue;
        }
        let Some((provider, start)) = tokens_in_line(line).into_iter().next() else {
            continue;
        };
        let column = line[..start].chars().count() + 1;
        findings.push(Finding {
            rule_id: "BAS-ZT1-023".to_owned(),
            title: format!("{provider} committed to the repository"),
            kind,
            severity: Severity::Critical,
            confidence: Confidence::High,
            categories: vec![Category::Zt1],
            location: Location {
                file: relative_path.to_path_buf(),
                line: number,
                column,
            },
            snippet: line.trim().to_owned(),
            description: format!(
                "A value with the exact format of a {provider} is committed as a literal. \
                 Anything with read access to this repository can read it."
            ),
            remediation: "Remove the literal, read the value from an environment variable or \
                          a secret manager instead, and revoke the token that leaked into \
                          history."
                .to_owned(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a value from pieces so no complete token appears as one literal
    /// in this file.
    fn join(parts: &[&str]) -> String {
        parts.concat()
    }

    const BODY36: [&str; 3] = ["q8Zr4KdN", "w2Vb7LmT5hYc", "J3xPf9GaR6sU1eHo"];

    fn body36() -> String {
        join(&BODY36)
    }

    fn lines(name: &str, contents: &str) -> Vec<usize> {
        inspect(Path::new(name), contents, &[])
            .iter()
            .map(|finding| finding.location.line)
            .collect()
    }

    fn hit(value: &str) -> bool {
        !lines("app.py", &format!("X = \"{value}\"\n")).is_empty()
    }

    #[test]
    fn each_github_prefix_with_a_36_character_body_is_reported() {
        for kind in ["p_", "o_", "u_", "s_", "r_"] {
            let value = join(&["gh", kind, &body36()]);
            assert!(hit(&value), "{value}");
        }
    }

    #[test]
    fn a_github_body_of_the_wrong_length_is_not_reported() {
        let short = join(&["gh", "p_", &body36()[..35]]);
        let long = join(&["gh", "p_", &body36(), "A"]);
        assert!(!hit(&short));
        assert!(!hit(&long));
    }

    #[test]
    fn an_aws_access_key_id_is_reported() {
        for prefix in ["AK", "AS"] {
            let value = join(&[prefix, "IA", "R7QZ", "M2KD", "P9XW", "L4TN"]);
            assert!(hit(&value), "{value}");
        }
    }

    #[test]
    fn a_bare_aws_secret_key_is_not_reported() {
        let secret = join(&["wJalrXUtn", "FEMI/K7MDENG", "/bPxRfiCYzq9d3Lk8Vs"]);
        assert!(!hit(&secret));
    }

    #[test]
    fn the_documented_aws_example_key_is_a_placeholder() {
        assert!(!hit("AKIAIOSFODNN7EXAMPLE"));
        assert!(!hit("ASIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn a_google_api_key_is_reported() {
        let value = join(&["AI", "za", "Sy", "Dk3-mQ7vX_ZpL2nR8tWb5cF0hJ4yGa9uE"]);
        assert_eq!(value.len(), 39);
        assert!(hit(&value));
    }

    #[test]
    fn an_npm_token_is_reported() {
        let value = join(&["np", "m_", &body36()]);
        assert!(hit(&value));
    }

    #[test]
    fn a_stripe_live_secret_key_is_reported_but_a_test_key_is_not() {
        let live = join(&["sk", "_li", "ve_", "Hq3Zr8KdNw2Vb7LmT5hYcJ3x"]);
        let test = join(&["sk", "_te", "st_", "Hq3Zr8KdNw2Vb7LmT5hYcJ3x"]);
        assert!(hit(&live));
        assert!(!hit(&test));
    }

    #[test]
    fn the_word_token_and_generic_assignments_are_not_reported() {
        for text in [
            "max_tokens = 4096",
            "token = \"Zr8KdNw2Vb7LmT5hYcJ3xPf9GaR6sU1e\"",
            "csrf_token: abcDEF123456ghiJKL789",
            "from tokenizer import tokenized",
        ] {
            assert!(lines("app.py", text).is_empty(), "{text}");
        }
    }

    #[test]
    fn a_value_inside_a_url_is_not_reported() {
        let token = join(&["gh", "p_", &body36()]);
        for text in [
            format!("url = \"https://example.org/?t={token}\""),
            format!("git clone https://user:{token}@host.test/repo.git"),
            format!("[docs](https://host.test/{token})"),
        ] {
            assert!(lines("README.md", &text).is_empty(), "{text}");
        }
    }

    #[test]
    fn a_value_in_a_markdown_link_target_is_not_reported() {
        let token = join(&["np", "m_", &body36()]);
        assert!(!hit(&format!("[link]({token})")));
    }

    #[test]
    fn a_value_in_a_file_path_is_not_reported() {
        let token = join(&["gh", "p_", &body36()]);
        for text in [
            format!("path = \"/var/cache/{token}\""),
            format!("path = \"{token}/config.json\""),
            format!("C:\\\\data\\\\{token}"),
        ] {
            assert!(lines("app.py", &text).is_empty(), "{text}");
        }
    }

    #[test]
    fn hex_digests_and_pins_are_not_reported() {
        let hex40 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        let hex64 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        for text in [
            format!("commit {hex40}"),
            format!("image: repo/app@sha256:{hex64}"),
            format!("uses: owner/repo@{hex40}"),
            format!("\"integrity\": \"sha512-{}\"", body36()),
            format!("integrity sha512-AKIA{}", &body36()[..16]),
        ] {
            assert!(lines("lock.json", &text).is_empty(), "{text}");
        }
        // A prefix followed only by hexadecimal digits is a digest slice.
        let hex_body = join(&["np", "m_", &hex40[..36]]);
        assert!(!hit(&hex_body));
    }

    #[test]
    fn placeholders_are_not_reported() {
        let pad = |suffix: &str| {
            let body = body36();
            join(&["np", "m_", &body[..36 - suffix.len()], suffix])
        };
        let fillers = [
            join(&["np", "m_", "abcdefghijklmnopqrstuvwxyz0123456789"]),
            join(&["np", "m_", &"A".repeat(36)]),
            pad("example"),
            pad("test"),
            pad("dummy1"),
            pad("sample"),
            pad("placeholder"),
            pad("changeme"),
            pad("redacted"),
            pad("xxxx"),
            pad("987654"),
            pad("zzzzzzzz"),
        ];
        for value in &fillers {
            assert_eq!(value.len(), 40, "{value}");
            assert!(!hit(value), "{value}");
        }
        // The same shape without the placeholder tail is reported.
        assert!(hit(&join(&["np", "m_", &body36()])));
    }

    #[test]
    fn a_token_glued_to_other_characters_is_not_reported() {
        let token = join(&["gh", "p_", &body36()]);
        assert!(!hit(&format!("a{token}")));
        assert!(!hit(&format!("{token}b")));
        assert!(!hit(&format!("{token}-more")));
    }

    #[test]
    fn a_token_in_markdown_and_env_text_is_reported() {
        let token = join(&["np", "m_", &body36()]);
        assert_eq!(lines("notes.md", &format!("use {token} here")), [1]);
        assert_eq!(lines(".env", &format!("REGISTRY_AUTH={token}")), [1]);
    }

    #[test]
    fn a_test_path_is_an_observation() {
        let token = join(&["np", "m_", &body36()]);
        let found = inspect(
            Path::new("tests/test_auth.py"),
            &format!("X = \"{token}\""),
            &[],
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::Observation);
        let shipped = inspect(Path::new("src/auth.py"), &format!("X = \"{token}\""), &[]);
        assert_eq!(shipped[0].kind, Kind::Defect);
    }

    #[test]
    fn a_line_already_reported_is_skipped() {
        let token = join(&["np", "m_", &body36()]);
        let text = format!("X = \"{token}\"\nY = \"{token}\"\n");
        let found = inspect(Path::new("app.py"), &text, &[1]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].location.line, 2);
    }

    #[test]
    fn the_column_points_at_the_token() {
        let token = join(&["np", "m_", &body36()]);
        let found = inspect(Path::new("app.py"), &format!("X = \"{token}\""), &[]);
        assert_eq!(found[0].location.column, 6);
    }
}
