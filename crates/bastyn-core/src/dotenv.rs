//! `.env` file inspection — the `BAS-ZT1-021` / `BAS-ZT1-022` checks.
//!
//! `crate::walk`'s own allowlist doc comment says `.env` and any `.env.*` file
//! at the scan root is "exactly the material a scanner should not miss" and
//! walks it regardless of `WalkOptions::include_hidden`. Before this module
//! existed, that promise was broken one layer up: `scan::analyse_file` opened
//! nothing that claimed the `.env` format, so a walked `.env` was read by no
//! analyser, produced no findings, and was not even recorded as skipped — a
//! real `sk-`-shaped key committed to a `.env` file produced zero findings
//! and a report that claimed "every file the scan reached was analysed".
//! This module is what a `.env` file is analysed *by*, closing that gap.
//!
//! Like `crate::infra`'s Dockerfile/Compose checks, this is Rust, not an
//! `ast-grep` pattern in `rules/*.yml`: a `KEY=value` line is not source code
//! any tree-sitter grammar parses, so there is no YAML rule file for either
//! id below. `docs/rule-catalogue.md` and this comment are their only rule
//! catalogue entries, the same convention `crate::infra`'s module doc comment
//! uses for `BAS-INFRA-001` through `-010`.
//!
//! # Checks
//!
//! | Rule | What it flags | Kind | Category |
//! | --- | --- | --- | --- |
//! | `BAS-ZT1-021` | A provider API key literal (the `sk-...` shape) in a committed `.env` value | defect | `ZT1` |
//! | `BAS-ZT1-022` | Any other credential-shaped literal in a committed `.env` value | observation | `ZT1` |
//!
//! # Reusing the Dockerfile/Compose credential logic
//!
//! Both checks reuse exactly the judgment already backing `BAS-INFRA-002`/
//! `BAS-INFRA-006`: [`credential::is_provider_key_literal`] for the narrow
//! `sk-` shape, and [`credential::looks_like_credential_key`] /
//! [`credential::is_hardcoded_credential_value`] for everything else
//! credential-named. One `NAME=value` judgment, applied to a third file
//! format, rather than a fourth independently-drifting heuristic.
//!
//! # `.env.example` and friends stay analysed, never flagged
//!
//! `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, and any
//! per-environment variant ending in one of those suffixes
//! (`.env.local.example`, `.env.production.sample`, ...) are conventionally
//! committed on purpose, as documentation of the variables a real `.env`
//! must set — not a leaked secret. [`is_env_file`] still returns `true` for
//! these, so the file is walked, opened, and counted as scanned
//! (honoring `walk.rs`'s "no silent narrowing" principle: a file this module
//! recognises never quietly drops out of coverage), but [`inspect`]
//! recognises the placeholder suffix and returns an empty `Vec` before
//! parsing a single line — the same "looked at, nothing to report" shape
//! [`crate::infra::inspect`] uses for a Dockerfile that parses clean.

use std::path::Path;

use crate::category::Category;
use crate::credential;
use crate::finding::{Confidence, Finding, Kind, Location, Severity};

/// Well-known non-secret suffixes on a `.env.<suffix>` file name. Matched
/// case-insensitively against only the *final* `.`-separated segment of the
/// file name (file-extension style), so `.env.example` is excluded, as is
/// `.env.local.example` / `.env.production.sample` / any other per-environment
/// variant that ends in one of these — but `.env.production` (no placeholder
/// suffix at all) is not.
const PLACEHOLDER_SUFFIXES: &[&str] = &["example", "sample", "template", "dist"];

/// True if this path is a `.env` file — the bare name, or any `.env.<suffix>`
/// variant — matching `crate::walk`'s own allowlist scope exactly, so every
/// `.env` file the walker ever hands to the scan is one this module claims.
///
/// Returns `true` for a placeholder file such as `.env.example` too: whether
/// a file is analysed and whether it is worth flagging are different
/// questions, and only [`inspect`] answers the second one. Answering `true`
/// here is what keeps `.env.example` counted as scanned rather than quietly
/// uncovered.
///
/// `pub(crate)`, not `pub`: `dotenv`, like `credential`, is a private,
/// crate-internal module (see `lib.rs`) rather than one of the crate's public
/// analyser modules (`infra`, `mcp`, ...), so nothing outside `scan.rs` ever
/// needs to ask this question.
#[must_use]
pub(crate) fn is_env_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == ".env" || name.starts_with(".env.")
}

/// True if this `.env.<...>` file name ends in a well-known placeholder
/// suffix.
///
/// The check is on the file name's *final* `.`-separated segment only, the
/// same way a file extension is checked — not on the whole remainder after
/// `.env.` — so a per-environment example file such as `.env.local.example`
/// or `.env.production.sample` (an extremely common convention: a real
/// project keeps per-environment example files alongside its per-environment
/// real ones) is still recognised as a placeholder. Before this, only a
/// remainder that was *exactly* one of [`PLACEHOLDER_SUFFIXES`] matched, so
/// `.env.local.example` (remainder `"local.example"`) fell through and was
/// scanned as a genuine `.env` file — the false-positive this function
/// exists to prevent.
pub(crate) fn placeholder_suffix(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(final_segment) = name.rsplit('.').next() else {
        return false;
    };
    PLACEHOLDER_SUFFIXES
        .iter()
        .any(|suffix| final_segment.eq_ignore_ascii_case(suffix))
}

/// One `KEY=value` line parsed out of a `.env` file.
struct Assignment {
    key: String,
    value: String,
    line: usize,
}

/// Parse every `KEY=value` line in a `.env` file, 1-indexed by line number.
///
/// A blank line or a line whose first non-blank character is `#` is not an
/// assignment. An optional leading `export ` (the shell-sourceable form many
/// `.env` files use) is stripped before splitting on the first `=`. An
/// UNQUOTED value has a trailing inline comment stripped first (see
/// [`strip_inline_comment`]); a QUOTED value is left untouched by that step,
/// since a `#` inside quotes is part of the value, not a comment. Matching
/// surrounding `"`/`'` quotes are then stripped from whatever remains. A line
/// with no `=` at all is not an assignment either, and is silently skipped —
/// this module has no notion of a malformed `.env` file the way
/// `infra::inspect` has an unparseable Compose file, because there is no
/// schema here to fail: every line is either a `KEY=value` pair or it is not.
fn assignments(contents: &str) -> Vec<Assignment> {
    contents
        .lines()
        .enumerate()
        .filter_map(|(index, raw)| {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let rest = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            let (key, value) = rest.split_once('=')?;
            let is_quoted = matches!(value.trim_start().chars().next(), Some('"' | '\''));
            let value = if is_quoted {
                value
            } else {
                strip_inline_comment(value)
            };
            Some(Assignment {
                key: key.trim().to_owned(),
                value: unquote(value.trim()).to_owned(),
                line: index + 1,
            })
        })
        .collect()
}

/// Strip a trailing inline comment from an UNQUOTED `.env` value: the first
/// whitespace-immediately-followed-by-`#` marks where the real value ends,
/// and everything from that whitespace onward (comment included) is dropped.
/// Matches how real `.env` loaders such as `python-dotenv` behave — a `#`
/// only starts a comment outside quotes, so callers must never pass a
/// quoted value's content through here (see the `is_quoted` check in
/// [`assignments`]).
///
/// A `#` with no preceding whitespace (`abc#123`) is left alone: it reads as
/// part of the token, not a comment, the same way a real `.env` loader
/// treats it.
fn strip_inline_comment(value: &str) -> &str {
    let mut prev_whitespace_index = None;
    for (index, ch) in value.char_indices() {
        if ch == '#'
            && let Some(ws_index) = prev_whitespace_index
        {
            return &value[..ws_index];
        }
        prev_whitespace_index = ch.is_whitespace().then_some(index);
    }
    value
}

fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

/// Inspect one `.env` file. `relative_path` is used in findings; its file
/// name decides only whether it is a placeholder (see the module doc
/// comment) — [`is_env_file`] has already decided this module claims it.
///
/// A path this module does not claim, or a recognised placeholder-suffix
/// file, both yield `Vec::new()`: the first because there is nothing here for
/// this module to say, the second because a `.env.example` is documentation,
/// not a leaked secret.
#[must_use]
pub(crate) fn inspect(relative_path: &Path, contents: &str) -> Vec<Finding> {
    if placeholder_suffix(relative_path) {
        return Vec::new();
    }

    assignments(contents)
        .into_iter()
        .filter_map(|assignment| finding_for(relative_path, &assignment))
        .collect()
}

fn finding_for(relative_path: &Path, assignment: &Assignment) -> Option<Finding> {
    let Assignment { key, value, line } = assignment;

    if credential::is_provider_key_literal(value) {
        return Some(Finding {
            rule_id: "BAS-ZT1-021".to_owned(),
            title: "Provider API key committed to a .env file".to_owned(),
            kind: Kind::Defect,
            severity: Severity::Critical,
            confidence: Confidence::High,
            categories: vec![Category::Zt1],
            location: location(relative_path, *line),
            snippet: format!("{key}={value}"),
            description: format!(
                "`{key}` holds a provider API key as a literal in a committed `.env` file. \
                 Anything with read access to this repository — every clone, every backup, \
                 every CI checkout — can read the key."
            ),
            remediation: format!(
                "Remove the literal, add `.env` to `.gitignore` if it is not there already, \
                 and inject `{key}` at run time instead — a secrets manager, an orchestrator \
                 secret, or a `.env` file that is never committed — then rotate the key that \
                 leaked into history."
            ),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        });
    }

    if credential::looks_like_credential_key(key)
        && credential::is_hardcoded_credential_value(value)
    {
        return Some(Finding {
            rule_id: "BAS-ZT1-022".to_owned(),
            title: "Hardcoded credential committed to a .env file".to_owned(),
            // Reported as an observation: the match alone does not show a real problem.
            kind: Kind::Observation,
            severity: credential::credential_severity(key, value),
            confidence: Confidence::High,
            categories: vec![Category::Zt1],
            location: location(relative_path, *line),
            snippet: format!("{key}={value}"),
            description: format!(
                "`{key}` holds a literal credential in a committed `.env` file. Anything with \
                 read access to this repository — every clone, every backup, every CI \
                 checkout — can read it."
            ),
            remediation: format!(
                "Remove the literal, add `.env` to `.gitignore` if it is not there already, \
                 and inject `{key}` at run time instead — a secrets manager, an orchestrator \
                 secret, or a `.env` file that is never committed — then rotate the credential \
                 that leaked into history."
            ),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        });
    }

    None
}

fn location(relative_path: &Path, line: usize) -> Location {
    Location {
        file: relative_path.to_path_buf(),
        line,
        column: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(name: &str, contents: &str) -> Vec<String> {
        inspect(Path::new(name), contents)
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect()
    }

    #[test]
    fn recognises_dot_env_and_variants() {
        for name in [".env", ".env.local", ".env.production", ".env.example"] {
            assert!(is_env_file(Path::new(name)), "{name} should be claimed");
        }
    }

    #[test]
    fn does_not_claim_unrelated_names() {
        for name in ["env", "environment.py", ".environment", "dotenv.py"] {
            assert!(!is_env_file(Path::new(name)), "{name} was wrongly claimed");
        }
    }

    #[test]
    fn a_provider_key_literal_is_a_defect() {
        let contents = "OPENAI_API_KEY=sk-proj-7f3a9c1eAbCdEfGh1234\n";

        assert_eq!(rules(".env", contents), ["BAS-ZT1-021"]);
    }

    #[test]
    fn a_hardcoded_generic_credential_is_a_defect() {
        let contents = "DB_PASSWORD=hunter2million\n";

        assert_eq!(rules(".env", contents), ["BAS-ZT1-022"]);
    }

    #[test]
    fn a_provider_key_is_not_double_reported_as_a_generic_credential() {
        let contents = "OPENAI_API_KEY=sk-proj-7f3a9c1eAbCdEfGh1234\n";

        assert_eq!(rules(".env", contents), ["BAS-ZT1-021"]);
    }

    #[test]
    fn both_lines_of_the_original_bug_report_fire() {
        let contents =
            "OPENAI_API_KEY=sk-proj-7f3a9c1eAbCdEfGh1234\nDB_PASSWORD=hunter2million\nDEBUG=true\n";

        let findings = inspect(Path::new(".env"), contents);

        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-ZT1-021");
        assert_eq!(findings[0].location.line, 1);
        assert_eq!(findings[0].kind, Kind::Defect);
        assert_eq!(findings[1].rule_id, "BAS-ZT1-022");
        assert_eq!(findings[1].location.line, 2);
        assert_eq!(findings[1].kind, Kind::Observation);
    }

    #[test]
    fn ordinary_config_and_boolean_flags_are_silent() {
        let contents = "DEBUG=true\nNODE_ENV=production\nPORT=8080\n";

        assert_eq!(rules(".env", contents), Vec::<String>::new());
    }

    #[test]
    fn an_interpolated_or_placeholder_value_is_not_flagged() {
        for line in [
            "DB_PASSWORD=$DB_PASSWORD",
            "DB_PASSWORD=${DB_PASSWORD}",
            "DB_PASSWORD=changeme",
        ] {
            assert!(rules(".env", line).is_empty(), "{line} was wrongly flagged");
        }
    }

    #[test]
    fn blank_lines_and_comments_are_skipped() {
        let contents = "\n# a comment\n  # indented comment\nDEBUG=true\n";

        assert_eq!(rules(".env", contents), Vec::<String>::new());
    }

    #[test]
    fn an_export_prefixed_line_is_still_parsed() {
        let contents = "export DB_PASSWORD=hunter2million\n";

        assert_eq!(rules(".env", contents), ["BAS-ZT1-022"]);
    }

    #[test]
    fn quoted_values_are_unquoted_before_judging() {
        let double = "OPENAI_API_KEY=\"sk-proj-7f3a9c1eAbCdEfGh1234\"\n";
        let single = "OPENAI_API_KEY='sk-proj-7f3a9c1eAbCdEfGh1234'\n";

        assert_eq!(rules(".env", double), ["BAS-ZT1-021"]);
        assert_eq!(rules(".env", single), ["BAS-ZT1-021"]);
    }

    #[test]
    fn a_line_with_no_equals_sign_is_skipped() {
        let contents = "this is not an assignment\nDEBUG=true\n";

        assert_eq!(rules(".env", contents), Vec::<String>::new());
    }

    #[test]
    fn a_placeholder_suffix_file_is_never_flagged() {
        for name in [
            ".env.example",
            ".env.EXAMPLE",
            ".env.sample",
            ".env.template",
            ".env.dist",
        ] {
            let contents =
                "OPENAI_API_KEY=sk-proj-7f3a9c1eAbCdEfGh1234\nDB_PASSWORD=hunter2million\n";
            assert!(
                rules(name, contents).is_empty(),
                "{name} should stay silent"
            );
        }
    }

    #[test]
    fn a_placeholder_suffix_file_is_still_claimed_as_analysed() {
        // Whether a file is analysed and whether it is worth flagging are
        // different questions -- is_env_file answers only the first, so an
        // .env.example is still counted as scanned even though inspect
        // reports nothing for it.
        assert!(is_env_file(Path::new(".env.example")));
    }

    #[test]
    fn a_non_placeholder_env_variant_is_still_checked() {
        let contents = "DB_PASSWORD=hunter2million\n";

        assert_eq!(rules(".env.production", contents), ["BAS-ZT1-022"]);
    }

    #[test]
    fn a_multi_segment_placeholder_suffix_file_is_never_flagged() {
        // Regression for the false-positive report: `placeholder_suffix` used
        // to require the ENTIRE remainder after ".env." to equal exactly
        // "example"/"sample"/"template"/"dist", so a per-environment example
        // file such as ".env.local.example" (remainder "local.example")
        // fell through the old check and was scanned as a genuine .env file.
        // The fix checks only the final `.`-separated segment, so any number
        // of environment segments before the placeholder suffix must still
        // be recognised.
        for name in [
            ".env.local.example",
            ".env.development.sample",
            ".env.production.template",
            ".env.staging.dist",
            ".env.LOCAL.EXAMPLE",
        ] {
            let contents = "OPENAI_API_KEY=sk-your-key-here-1234567890abcdef\nSTRIPE_SECRET_KEY=sk-REPLACE_WITH_YOUR_ACTUAL_STRIPE_KEY\nDB_PASSWORD=hunter2million\n";
            assert!(
                rules(name, contents).is_empty(),
                "{name} should stay silent"
            );
        }
    }

    #[test]
    fn a_multi_segment_non_placeholder_env_variant_is_still_checked() {
        // The counterpart to the fix above: a genuine per-environment .env
        // file with no placeholder suffix at all -- e.g. ".env.local" or
        // ".env.production" -- must still be fully checked for real
        // credentials. The final-segment check must not become so loose
        // that it starts treating every multi-segment name as a
        // placeholder.
        for name in [".env.local", ".env.production", ".env.staging"] {
            let contents = "DB_PASSWORD=hunter2million\n";
            assert_eq!(
                rules(name, contents),
                ["BAS-ZT1-022"],
                "{name} should still be checked"
            );
        }
    }

    #[test]
    fn an_empty_file_produces_nothing() {
        assert_eq!(rules(".env", ""), Vec::<String>::new());
    }

    #[test]
    fn an_unquoted_value_that_is_only_a_placeholder_comment_is_not_flagged() {
        // The value after `=` is entirely an inline comment ("fill me in"),
        // so once the comment is stripped there is no credential value left
        // at all -- this must be silent the same way a genuinely empty
        // value already is, not report the literal comment text as a
        // high-severity secret.
        let contents = "DB_PASSWORD= # fill me in\n";

        assert_eq!(rules(".env", contents), Vec::<String>::new());
    }

    #[test]
    fn an_unquoted_value_with_a_trailing_inline_comment_is_stripped_before_judging() {
        // The trailing " # prod" must not break the `sk-`-shape match --
        // before this fix it did, and the line was misclassified as the
        // generic BAS-ZT1-022 instead of the provider-key BAS-ZT1-021.
        let contents = "OPENAI_API_KEY=sk-proj-abc123def456ghi789 # prod\n";

        assert_eq!(rules(".env", contents), ["BAS-ZT1-021"]);
    }

    #[test]
    fn a_quoted_value_containing_a_literal_hash_is_preserved_in_full() {
        // Comment-stripping must never apply inside quotes: a `#` (even one
        // preceded by whitespace) inside a quoted value is part of the
        // secret, not a comment marker, matching how real `.env` loaders
        // (e.g. python-dotenv) treat quoted values.
        let contents = "SECRET=\"abc #123\"\n";

        let findings = inspect(Path::new(".env"), contents);

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-ZT1-022");
        assert_eq!(findings[0].snippet, "SECRET=abc #123");
    }

    #[test]
    fn a_placeholder_shaped_value_in_a_genuine_env_file_is_not_flagged() {
        // Regression for the second bug in the same report: unlike
        // `placeholder_suffix`, `is_provider_key_literal` used to have no
        // placeholder-content check at all -- only the `sk-` shape and
        // length. A real, non-suffixed `.env` file that a developer only
        // partially filled in after cloning a template (a very common real
        // scenario, not just an `.env.example` problem) must stay silent for
        // an obviously-placeholder value.
        let contents = "OPENAI_API_KEY=sk-your-key-here-1234567890abcdef\nSTRIPE_SECRET_KEY=sk-REPLACE_WITH_YOUR_ACTUAL_STRIPE_KEY\n";

        assert!(
            rules(".env", contents).is_empty(),
            "{:#?}",
            inspect(Path::new(".env"), contents)
        );
    }

    #[test]
    fn a_real_looking_provider_key_in_a_genuine_env_file_still_fires() {
        // The fix above must not become so broad that it silences a genuine
        // leak: a real-shaped key with no placeholder text must still
        // produce a finding, in a plain (non-suffixed) `.env` file.
        let contents = "OPENAI_API_KEY=sk-proj-Ab3xR9kLm2Qw7ZvN4tYh8sJ1234567890\n";

        assert_eq!(rules(".env", contents), ["BAS-ZT1-021"]);
    }
}
