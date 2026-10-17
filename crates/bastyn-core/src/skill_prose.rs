//! Scoring short passages of skill text for "fetch code from a URL and run it".
//!
//! A passage is a window of seven lines centred on a line that mentions a
//! download tool or word (`curl`, `wget`, `npx`, `download`, `git clone`, and
//! so on). [`score_file`] turns each passage into a probability with a small
//! bundled linear model:
//!
//! 1. The passage is rewritten: every URL becomes a token naming its host, and
//!    a few marker tokens are appended (inside a code fence or in prose, which
//!    kind of file, whether a negation such as "never" or "avoid" appears in
//!    the passage, whether `BAS-SKILL-010` already reported a command nearby,
//!    and the words of the nearest heading).
//! 2. The rewritten text is turned into hashed word and character features.
//!    Each feature set is weighted by a fixed inverse-document-frequency table,
//!    length-normalised, and multiplied by the model's coefficients.
//! 3. The sum plus a bias goes through the logistic function.
//!
//! The arithmetic is plain `f64` over a fixed weight file, in a fixed order, on
//! one thread, so the same text always gives the same score. Every text rule
//! here is ASCII-only on purpose, so the behaviour does not depend on locale or
//! on Unicode tables.
//!
//! The weight file `skill_prose/model.bin` is little-endian: the magic bytes
//! `BPM1`, a `u32` bucket count `B`, an `f32` bias, then four `f32` arrays of
//! length `B` (word IDF, character IDF, word coefficients, character
//! coefficients). A file with the wrong magic or length yields no scores
//! instead of an error.

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The bundled weights.
static MODEL_BYTES: &[u8] = include_bytes!("skill_prose/model.bin");

/// Bytes at the start of a valid weight file.
const MAGIC: &[u8; 4] = b"BPM1";

/// How many characters of a file are read.
const MAX_CHARS: usize = 14_000;

/// Lines of context on each side of an anchor line.
const CONTEXT: usize = 3;

/// A `BAS-SKILL-010` command within this many lines of an anchor line sets the
/// `__BAS010__` marker.
const INSTALL_LINE_REACH: usize = 2;

/// How many words of the heading become marker tokens.
const HEADING_WORDS: usize = 6;

/// Words that make a line an anchor line. Matched case-insensitively between
/// ASCII word boundaries.
const ANCHOR_WORDS: &[&str] = &[
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
    "npx",
    "uvx",
    "pipx",
    "bunx",
    "dlx",
    "download",
    "downloads",
    "downloaded",
];

/// Phrases that set the `__NEG__` marker. Matched in the ASCII-lowercased
/// passage between ASCII word boundaries.
const NEGATION_PHRASES: &[&str] = &[
    "don't",
    "do not",
    "never",
    "avoid",
    "warning",
    "unsafe",
    "insecure",
    "instead of",
    "rather than",
    "not recommended",
    "dangerous",
    "malicious",
];

/// The score of one passage.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WindowScore {
    /// 1-based line of the anchor line the passage is centred on.
    pub(crate) line: usize,
    /// The model's probability, between 0 and 1.
    pub(crate) score: f64,
    /// Whether the passage contains an `http://` or `https://` address.
    pub(crate) has_url: bool,
}

/// One passage before scoring.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Window {
    line: usize,
    prepped: String,
    has_url: bool,
}

/// The parsed weight file.
struct Model {
    buckets: usize,
    bias: f64,
    idf_word: Vec<f32>,
    idf_char: Vec<f32>,
    coef_word: Vec<f32>,
    coef_char: Vec<f32>,
}

/// Scores every passage of one file.
///
/// `file_name` is the path of the file (only its ending is used),
/// `contents` its text, and `install_lines` the 1-based lines of the commands
/// `BAS-SKILL-010` reports in the same file. The result has one entry per
/// anchor line, in line order, and is empty when the bundled weights cannot be
/// read.
pub(crate) fn score_file(
    file_name: &str,
    contents: &str,
    install_lines: &[usize],
) -> Vec<WindowScore> {
    let Some(model) = model() else {
        return Vec::new();
    };
    windows(file_name, contents, install_lines)
        .into_iter()
        .map(|window| WindowScore {
            line: window.line,
            score: model.score(&window.prepped),
            has_url: window.has_url,
        })
        .collect()
}

/// The bundled model, parsed on first use. `None` when the bytes are not a
/// valid weight file.
fn model() -> Option<&'static Model> {
    static MODEL: OnceLock<Option<Model>> = OnceLock::new();
    MODEL.get_or_init(|| Model::parse(MODEL_BYTES)).as_ref()
}

/// Reads little-endian `f32` values from `bytes`, which must hold a whole
/// number of them.
fn read_f32s(bytes: &[u8]) -> Vec<f32> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| f32::from_le_bytes(*chunk))
        .collect()
}

impl Model {
    /// Parses a weight file, or returns `None` if the magic or the length is
    /// wrong.
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.get(..4)? != MAGIC {
            return None;
        }
        let count = bytes.get(4..8)?;
        let buckets =
            usize::try_from(u32::from_le_bytes([count[0], count[1], count[2], count[3]])).ok()?;
        let array_bytes = buckets.checked_mul(4)?;
        let expected = array_bytes.checked_mul(4)?.checked_add(12)?;
        if buckets == 0 || bytes.len() != expected {
            return None;
        }
        let bias = *read_f32s(bytes.get(8..12)?).first()?;
        let array = |index: usize| -> Option<Vec<f32>> {
            let start = 12 + index * array_bytes;
            Some(read_f32s(bytes.get(start..start + array_bytes)?))
        };
        Some(Self {
            buckets,
            bias: f64::from(bias),
            idf_word: array(0)?,
            idf_char: array(1)?,
            coef_word: array(2)?,
            coef_char: array(3)?,
        })
    }

    /// The probability the model gives a rewritten passage.
    fn score(&self, prepped: &str) -> f64 {
        let (words, chars) = self.features(prepped);
        let z = block_sum(&words, &self.idf_word, &self.coef_word)
            + block_sum(&chars, &self.idf_char, &self.coef_char)
            + self.bias;
        1.0 / (1.0 + (-z).exp())
    }

    /// Hashed word and character feature counts, keyed by bucket.
    fn features(&self, text: &str) -> (BTreeMap<usize, u32>, BTreeMap<usize, u32>) {
        let mut words: BTreeMap<usize, u32> = BTreeMap::new();
        let tokens = word_tokens(text);
        for (at, token) in tokens.iter().enumerate() {
            *words
                .entry(self.bucket(&format!("w1\0{token}")))
                .or_insert(0) += 1;
            if let Some(next) = tokens.get(at + 1) {
                *words
                    .entry(self.bucket(&format!("w2\0{token} {next}")))
                    .or_insert(0) += 1;
            }
        }
        let mut chars: BTreeMap<usize, u32> = BTreeMap::new();
        for token in text.split(is_ascii_space).filter(|part| !part.is_empty()) {
            let padded: Vec<char> = std::iter::once(' ')
                .chain(token.chars())
                .chain(std::iter::once(' '))
                .collect();
            for size in 3..=5 {
                for gram in padded.windows(size) {
                    let key: String = gram.iter().collect();
                    *chars.entry(self.bucket(&format!("c\0{key}"))).or_insert(0) += 1;
                }
            }
        }
        (words, chars)
    }

    /// The bucket a feature key hashes to.
    fn bucket(&self, key: &str) -> usize {
        // The remainder is below the bucket count, so it fits in `usize`.
        usize::try_from(fnv1a(key.as_bytes()) % self.buckets as u64).unwrap_or(0)
    }
}

/// One block's contribution to the score: the length-normalised, IDF-weighted
/// counts multiplied by the coefficients.
fn block_sum(counts: &BTreeMap<usize, u32>, idf: &[f32], coef: &[f32]) -> f64 {
    let weighted: Vec<(usize, f64)> = counts
        .iter()
        .map(|(&index, &count)| {
            let weight = idf.get(index).copied().map_or(0.0, f64::from);
            (index, (1.0 + f64::from(count).ln()) * weight)
        })
        .collect();
    let sum_squares: f64 = weighted.iter().map(|(_, value)| value * value).sum();
    let root = sum_squares.sqrt();
    let norm = if root > 0.0 { root } else { 1.0 };
    weighted
        .iter()
        .map(|&(index, value)| (value / norm) * coef.get(index).copied().map_or(0.0, f64::from))
        .sum()
}

/// 64-bit FNV-1a hash.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Maximal runs of `[a-z0-9_.-]` in `text`.
fn word_tokens(text: &str) -> Vec<&str> {
    let is_word =
        |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte);
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut start = None;
    for (at, &byte) in bytes.iter().enumerate() {
        match (is_word(byte), start) {
            (true, None) => start = Some(at),
            (false, Some(from)) => {
                tokens.push(&text[from..at]);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        tokens.push(&text[from..]);
    }
    tokens
}

/// ASCII whitespace as the model defines it: space, tab, line feed, carriage
/// return, vertical tab and form feed.
fn is_ascii_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

/// True for a byte that is part of an ASCII word: a letter, a digit or `_`.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// True if `needle` occurs in `haystack` with no ASCII word byte directly
/// before or after it. Both are compared as given, so lowercase `haystack`
/// first for a case-insensitive search.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    haystack.match_indices(needle).any(|(start, _)| {
        let before = start.checked_sub(1).and_then(|at| bytes.get(at));
        let after = bytes.get(start + needle.len());
        !before.is_some_and(|&b| is_word_byte(b)) && !after.is_some_and(|&b| is_word_byte(b))
    })
}

/// True if `lower` (already ASCII-lowercased) holds `git`, one or more ASCII
/// whitespace characters and `clone`, between word boundaries.
fn contains_git_clone(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    lower.match_indices("git").any(|(start, _)| {
        if start > 0 && bytes.get(start - 1).is_some_and(|&b| is_word_byte(b)) {
            return false;
        }
        let rest = &lower[start + 3..];
        let trimmed = rest.trim_start_matches(is_ascii_space);
        trimmed.len() < rest.len()
            && trimmed.starts_with("clone")
            && !trimmed.as_bytes().get(5).is_some_and(|&b| is_word_byte(b))
    })
}

/// True if the line mentions a download tool or word.
fn is_anchor_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ANCHOR_WORDS.iter().any(|word| contains_word(&lower, word)) || contains_git_clone(&lower)
}

/// True if the passage contains a negation phrase.
fn has_negation(passage: &str) -> bool {
    let lower = passage.to_ascii_lowercase();
    NEGATION_PHRASES
        .iter()
        .any(|phrase| contains_word(&lower, phrase))
}

/// True for a line that opens or closes a code fence: optional whitespace and
/// then three backticks or three tildes.
fn is_fence_line(line: &str) -> bool {
    let rest = line.trim_start_matches(is_ascii_space);
    rest.starts_with("```") || rest.starts_with("~~~")
}

/// The heading text if `line` is a Markdown heading: at most three leading
/// whitespace characters, one to six `#`, then a whitespace character. The
/// text is what follows the whitespace run.
fn heading_text(line: &str) -> Option<&str> {
    let after_indent = line.trim_start_matches(is_ascii_space);
    let indent = line.chars().count() - after_indent.chars().count();
    if indent > 3 {
        return None;
    }
    let marks = after_indent.chars().take_while(|&c| c == '#').count();
    if !(1..=6).contains(&marks) {
        return None;
    }
    let after_marks = &after_indent[marks..];
    let text = after_marks.trim_start_matches(is_ascii_space);
    (text.len() < after_marks.len()).then_some(text)
}

/// Replaces each maximal run of characters outside `[a-z0-9]` with one `_`.
/// The input must already be ASCII-lowercased.
fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_run = false;
    for c in text.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

/// Replaces each `http://` or `https://` address with ` URL_<host> `, where
/// the host is lowercased and sanitised. An address runs to the next ASCII
/// whitespace, `)`, `'`, `"`, `` ` `` or `>`, and needs at least one character
/// after the scheme.
fn replace_urls(text: &str) -> String {
    let ends_url = |c: char| is_ascii_space(c) || matches!(c, ')' | '\'' | '"' | '`' | '>');
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let scheme = ["https://", "http://"]
            .into_iter()
            .find(|scheme| rest.starts_with(scheme));
        let matched = scheme.and_then(|scheme| {
            let body = &rest[scheme.len()..];
            let length = body.find(ends_url).unwrap_or(body.len());
            (length > 0).then_some(scheme.len() + length)
        });
        if let Some(length) = matched {
            let host = rest[..length].split('/').nth(2).unwrap_or("");
            out.push_str(" URL_");
            out.push_str(&sanitize(&host.to_ascii_lowercase()));
            out.push(' ');
            at += length;
        } else if let Some(c) = rest.chars().next() {
            out.push(c);
            at += c.len_utf8();
        } else {
            break;
        }
    }
    out
}

/// The marker tokens of one passage, joined by single spaces.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the model was fitted with a case-sensitive `.md` test"
)]
fn extra_tokens(
    file_name: &str,
    in_fence: bool,
    passage: &str,
    near_install: bool,
    heading: &str,
) -> String {
    let mut tokens: Vec<String> = vec![
        if in_fence { "__INFENCE__" } else { "__PROSE__" }.to_owned(),
        if file_name.ends_with("SKILL.md") {
            "__FILE_SKILLMD__"
        } else if file_name.ends_with(".md") {
            "__FILE_MD__"
        } else {
            "__FILE_SCRIPT__"
        }
        .to_owned(),
    ];
    if has_negation(passage) {
        tokens.push("__NEG__".to_owned());
    }
    if near_install {
        tokens.push("__BAS010__".to_owned());
    }
    tokens.extend(
        heading
            .split(is_ascii_space)
            .filter(|word| !word.is_empty())
            .take(HEADING_WORDS)
            .map(|word| format!("H_{}", sanitize(&word.to_ascii_lowercase()))),
    );
    tokens.join(" ")
}

/// Cuts the passages out of one file and rewrites them for the model.
fn windows(file_name: &str, contents: &str, install_lines: &[usize]) -> Vec<Window> {
    let end = contents
        .char_indices()
        .nth(MAX_CHARS)
        .map_or(contents.len(), |(at, _)| at);
    let lines: Vec<&str> = contents[..end].split('\n').collect();

    let mut in_fence = false;
    let mut heading = "";
    let mut states: Vec<(bool, &str)> = Vec::with_capacity(lines.len());
    for line in &lines {
        if is_fence_line(line) {
            in_fence = !in_fence;
        }
        if let Some(text) = heading_text(line) {
            heading = text;
        }
        states.push((in_fence, heading));
    }

    let mut out = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        if !is_anchor_line(line) {
            continue;
        }
        let first = at.saturating_sub(CONTEXT);
        let last = (at + CONTEXT).min(lines.len() - 1);
        let passage = lines[first..=last].join("\n");
        let (fenced, heading) = states[at];
        let near_install = install_lines
            .iter()
            .any(|&install| install.abs_diff(at + 1) <= INSTALL_LINE_REACH);
        let extra = extra_tokens(file_name, fenced, &passage, near_install, heading);
        let prepped = format!("{} {extra}", replace_urls(&passage)).to_ascii_lowercase();
        out.push(Window {
            line: at + 1,
            prepped,
            has_url: passage.contains("http://") || passage.contains("https://"),
        });
    }
    out
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ScoreCase {
        prepped: String,
        score: f64,
    }

    #[derive(Deserialize)]
    struct FileCase {
        name: String,
        content: String,
    }

    #[derive(Deserialize)]
    struct ExpectedWindow {
        file: String,
        line: usize,
        prepped: String,
        score: f64,
    }

    #[derive(Deserialize)]
    struct WindowCase {
        files: Vec<FileCase>,
        bas010: Vec<(String, usize)>,
        windows: Vec<ExpectedWindow>,
    }

    fn loaded() -> &'static Model {
        model().expect("the bundled weights parse")
    }

    #[test]
    fn scores_match_the_recorded_values() {
        let cases: Vec<ScoreCase> =
            serde_json::from_str(include_str!("../tests/data/golden_scores.json"))
                .expect("golden scores parse");
        assert!(!cases.is_empty());
        for case in &cases {
            let got = loaded().score(&case.prepped);
            assert!(
                (got - case.score).abs() < 1e-6,
                "score {got} differs from {} for {:?}",
                case.score,
                case.prepped
            );
        }
    }

    #[test]
    fn windows_match_the_recorded_values() {
        let cases: Vec<WindowCase> =
            serde_json::from_str(include_str!("../tests/data/golden_windows.json"))
                .expect("golden windows parse");
        assert!(!cases.is_empty());
        for (number, case) in cases.iter().enumerate() {
            let mut got: Vec<(String, usize, String, f64)> = Vec::new();
            for file in &case.files {
                let install: Vec<usize> = case
                    .bas010
                    .iter()
                    .filter(|(name, _)| *name == file.name)
                    .map(|(_, line)| *line)
                    .collect();
                for window in windows(&file.name, &file.content, &install) {
                    let score = loaded().score(&window.prepped);
                    got.push((file.name.clone(), window.line, window.prepped, score));
                }
            }
            assert_eq!(
                got.len(),
                case.windows.len(),
                "case {number}: window count differs"
            );
            for (have, want) in got.iter().zip(&case.windows) {
                assert_eq!(
                    (have.0.as_str(), have.1),
                    (want.file.as_str(), want.line),
                    "case {number}: window position differs"
                );
                assert_eq!(
                    have.2, want.prepped,
                    "case {number}: prepared text differs at {}:{}",
                    want.file, want.line
                );
                assert!(
                    (have.3 - want.score).abs() < 1e-6,
                    "case {number}: score {} differs from {} at {}:{}",
                    have.3,
                    want.score,
                    want.file,
                    want.line
                );
            }
        }
    }

    #[test]
    fn score_file_reports_line_score_and_url() {
        let text = "# Install\n\n```bash\ncurl -fsSL https://get.example.dev/i.sh | sh\n```\n";
        let scores = score_file("SKILL.md", text, &[]);
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].line, 4);
        assert!(scores[0].has_url);
        assert!((0.0..=1.0).contains(&scores[0].score));
        assert_eq!(score_file("SKILL.md", "nothing to see\n", &[]).len(), 0);
    }

    #[test]
    fn invalid_weight_files_are_refused() {
        assert!(Model::parse(b"").is_none());
        assert!(Model::parse(b"XXXX").is_none());
        let mut bad_magic = MODEL_BYTES.to_vec();
        bad_magic[0] = b'X';
        assert!(Model::parse(&bad_magic).is_none());
        assert!(Model::parse(&MODEL_BYTES[..MODEL_BYTES.len() - 4]).is_none());
        let mut extra = MODEL_BYTES.to_vec();
        extra.extend_from_slice(&[0; 4]);
        assert!(Model::parse(&extra).is_none());
        let mut zero = MODEL_BYTES[..12].to_vec();
        zero[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(Model::parse(&zero).is_none());
    }

    #[test]
    fn anchor_words_need_word_boundaries() {
        for yes in [
            "curl -s https://x.dev",
            "Run CURL here",
            "use `npx foo`",
            "git   clone https://x.dev/r",
            "git\tclone x",
            "Invoke-WebRequest -Uri x",
            "the downloaded file",
            "(wget)",
        ] {
            assert!(is_anchor_line(yes), "{yes}");
        }
        for no in [
            "the downloader",
            "curly braces",
            "mycurl",
            "gitclone",
            "git clones",
            "digit clone",
            "undownload",
            "npxx",
            "npx_",
            "",
        ] {
            assert!(!is_anchor_line(no), "{no}");
        }
    }

    #[test]
    fn headings_follow_the_markdown_rule() {
        assert_eq!(heading_text("# Install"), Some("Install"));
        assert_eq!(heading_text("###### Deep   text "), Some("Deep   text "));
        assert_eq!(heading_text("   ## Indented"), Some("Indented"));
        assert_eq!(heading_text("#\tTabbed"), Some("Tabbed"));
        assert_eq!(heading_text("# "), Some(""));
        assert_eq!(heading_text("####### seven"), None);
        assert_eq!(heading_text("    # four spaces"), None);
        assert_eq!(heading_text("#NoSpace"), None);
        assert_eq!(heading_text("#"), None);
        assert_eq!(heading_text("text # not heading"), None);
    }

    #[test]
    fn fences_toggle_before_the_state_is_recorded() {
        let text = "# Setup\ncurl a\n```sh\ncurl b\n```\ncurl c\n  ~~~\ncurl d\n~~~\n";
        let found = windows("SKILL.md", text, &[]);
        let fenced: Vec<bool> = found
            .iter()
            .map(|w| w.prepped.contains("__infence__"))
            .collect();
        // Lines 2, 4, 6 and 8 are anchors; the fence line itself is fenced.
        assert_eq!(
            found.iter().map(|w| w.line).collect::<Vec<_>>(),
            [2, 4, 6, 8]
        );
        assert_eq!(fenced, [false, true, false, true]);
    }

    #[test]
    fn headings_apply_inside_fences_and_cap_at_six_words() {
        let text = "## One Two-Three four five six seven eight\ncurl a\n";
        let found = windows("SKILL.md", text, &[]);
        assert!(
            found[0]
                .prepped
                .ends_with("h_one h_two_three h_four h_five h_six h_seven")
        );
        let inside = "```\n# Comment Heading\ncurl a\n```\n";
        let found = windows("a.md", inside, &[]);
        assert!(found[0].prepped.contains("h_comment h_heading"));
    }

    #[test]
    fn urls_become_host_tokens() {
        assert_eq!(
            replace_urls("run https://Get.Example-Tool.dev/a/b.sh now"),
            "run  URL_get_example_tool_dev  now"
        );
        assert_eq!(replace_urls("(http://a.b)"), "( URL_a_b )");
        assert_eq!(
            replace_urls("see \"https://x.io/p?q=1\"."),
            "see \" URL_x_io \"."
        );
        assert_eq!(replace_urls("https://"), "https://");
        assert_eq!(replace_urls("HTTPS://x.io"), "HTTPS://x.io");
        assert_eq!(replace_urls("http:///x"), " URL_ ");
        assert_eq!(
            replace_urls("h\u{e9}llo http://x.io"),
            "h\u{e9}llo  URL_x_io "
        );
    }

    #[test]
    fn negation_phrases_need_word_boundaries() {
        for yes in [
            "Don't pipe it",
            "do not run",
            "NEVER do this",
            "avoid it",
            "a warning follows",
            "this is unsafe.",
            "use X instead of Y",
            "rather than that",
            "not recommended",
            "dangerous!",
            "malicious code",
        ] {
            assert!(has_negation(yes), "{yes}");
        }
        for no in [
            "nevermind",
            "unsafely",
            "avoided",
            "warnings",
            "fine",
            "do nothing",
        ] {
            assert!(!has_negation(no), "{no}");
        }
    }

    #[test]
    fn window_edges_and_markers() {
        let text = "a\ncurl https://x.io/s\nb\nc\nd\ne\nf\ng\n";
        let found = windows("scripts/run.sh", text, &[3]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 2);
        assert!(found[0].has_url);
        assert!(found[0].prepped.starts_with("a\ncurl  url_x_io \nb\nc\nd "));
        assert!(!found[0].prepped.contains("\ne"));
        assert!(
            found[0]
                .prepped
                .ends_with("__prose__ __file_script__ __bas010__")
        );
        // Out of reach of the reported line: no marker.
        let far = windows("scripts/run.sh", text, &[5]);
        assert!(!far[0].prepped.contains("__bas010__"));
    }

    #[test]
    fn only_the_first_characters_are_read() {
        let mut text = "x".repeat(MAX_CHARS - 1);
        text.push('\n');
        text.push_str("curl https://x.io\n");
        assert_eq!(windows("a.md", &text, &[]).len(), 0);
        // Multi-byte characters count once each.
        let wide = format!("{}\ncurl a\n", "\u{e9}".repeat(MAX_CHARS - 20));
        assert_eq!(windows("a.md", &wide, &[]).len(), 1);
    }
}
