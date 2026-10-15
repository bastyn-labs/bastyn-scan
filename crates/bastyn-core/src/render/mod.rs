//! Render a [`Report`] into JSON, SARIF, or a terminal-friendly summary.
//!
//! All three functions read the exact same [`Report`] value produced by the
//! engine, so they can never disagree with each other: there is no separate
//! code path anywhere in here that re-decides what counts as a defect, or
//! what the CVE status was.

mod error;
mod json;
mod sarif;
mod stdout;

#[cfg(test)]
pub(crate) mod test_support;

use crate::report::Report;

pub use error::{Error, Result};

/// Render `report` as our own JSON.
///
/// Field names are exactly [`Report`]'s own `Serialize` output — this is a
/// public contract other tools parse, so it is never reshaped into a bespoke
/// wrapper.
pub fn json(report: &Report) -> Result<String> {
    json::render(report)
}

/// Render `report` as a SARIF 2.1.0 log, for GitHub Advanced Security and
/// GitLab.
///
/// Rules are deduplicated by rule id and every result's `ruleIndex` points at
/// its rule's entry. Observations always report SARIF level `"note"`,
/// regardless of severity, so a context-dependent finding can never make a
/// code-scanning gate block a pull request the way a defect does.
pub fn sarif(report: &Report) -> Result<String> {
    sarif::render(report)
}

/// How much of a [`crate::compliance::Crosswalk`] the terminal renderer prints.
///
/// An explicit choice rather than one inferred from how many crosswalks a
/// report happens to carry. Detail level is a presentation decision, and
/// deriving it from `crosswalks.len() == 1` would tie it to a data-shape
/// accident: the first caller who computes a single crosswalk for some other
/// reason would silently get a page of per-finding lines it never asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrosswalkDetail {
    /// One compact block per framework: its areas, their counts, and its
    /// standing — and no per-finding lines.
    ///
    /// What a default can afford. The detailed form lists every finding under
    /// every area it touches, so on a repository with thirty defects under one
    /// article three frameworks would append several hundred lines to every
    /// scan. This form's size depends on how many areas a framework has, not
    /// on how many findings there are.
    Summary,
    /// Every finding listed under every area it is relevant to.
    ///
    /// What `--group-by <framework>` asks for: the reader named one framework,
    /// so they want to see which findings sit under which of its areas.
    Detailed,
}

/// Which characters the terminal renderer draws its furniture with.
///
/// A tick, a hollow circle, a box-drawing rule and a dagger all render
/// correctly in a modern terminal and all mangle somewhere: an older Windows
/// console, a CI log viewer that stores bytes rather than text, a pasted
/// snippet that lost its encoding. The report has to stay readable in those,
/// so the renderer draws with ASCII whenever it cannot see a terminal it can
/// trust.
///
/// [`Glyphs::Ascii`] also folds typographic punctuation — em dashes, curly
/// quotes, the middle dot — down to ASCII wherever it appears, including
/// inside a rule's own prose. That is a rendering of the same text, not a
/// rewording of it, and it is the only way the guarantee can be absolute:
/// "mostly ASCII" is not something a CI log can rely on. Characters outside
/// that table — an accented word, a path in another script — are left exactly
/// as they are, because mangling a path is worse than a wide character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyphs {
    /// Draw with Unicode.
    Unicode,
    /// Draw with ASCII only.
    Ascii,
}

impl Glyphs {
    /// The marker for a step that ran.
    #[must_use]
    pub const fn tick(self) -> &'static str {
        match self {
            Self::Unicode => "\u{2713}",
            Self::Ascii => "[ok]",
        }
    }

    /// The marker for a step that was skipped.
    #[must_use]
    pub const fn circle(self) -> &'static str {
        match self {
            Self::Unicode => "\u{25cb}",
            Self::Ascii => "[--]",
        }
    }

    /// The character a heading is underlined with.
    #[must_use]
    pub const fn rule(self) -> &'static str {
        match self {
            Self::Unicode => "\u{2500}",
            Self::Ascii => "-",
        }
    }

    /// The dash that separates a heading from its gloss.
    #[must_use]
    pub const fn dash(self) -> &'static str {
        match self {
            Self::Unicode => "\u{2014}",
            Self::Ascii => "-",
        }
    }

    /// The separator between two short facts on one line.
    #[must_use]
    pub const fn middot(self) -> &'static str {
        match self {
            Self::Unicode => "\u{b7}",
            Self::Ascii => "|",
        }
    }

    /// The mark that says a string was cut.
    #[must_use]
    pub const fn ellipsis(self) -> &'static str {
        match self {
            Self::Unicode => "\u{2026}",
            Self::Ascii => "...",
        }
    }

    /// The opening quote around text transcribed from a source document.
    #[must_use]
    pub const fn quote_open(self) -> &'static str {
        match self {
            Self::Unicode => "\u{201c}",
            Self::Ascii => "\"",
        }
    }

    /// The closing quote around text transcribed from a source document.
    #[must_use]
    pub const fn quote_close(self) -> &'static str {
        match self {
            Self::Unicode => "\u{201d}",
            Self::Ascii => "\"",
        }
    }

    /// The `index`-th footnote marker.
    ///
    /// Runs out of distinct symbols after three and starts doubling rather
    /// than repeating one: two footnotes sharing a marker would send a reader
    /// to the wrong paragraph, which is the one thing a footnote must not do.
    #[must_use]
    pub fn marker(self, index: usize) -> String {
        match self {
            Self::Unicode => {
                const SYMBOLS: [&str; 3] = ["\u{2020}", "\u{2021}", "\u{a7}"];
                SYMBOLS[index % SYMBOLS.len()].repeat(index / SYMBOLS.len() + 1)
            }
            Self::Ascii => "*".repeat(index + 1),
        }
    }

    /// `text` with typographic punctuation folded to ASCII, under
    /// [`Glyphs::Ascii`], and untouched otherwise.
    #[must_use]
    pub fn text(self, text: &str) -> String {
        if self == Self::Unicode {
            return text.to_owned();
        }
        let mut out = String::with_capacity(text.len());
        for character in text.chars() {
            match character {
                '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}'
                | '\u{2500}' => out.push('-'),
                '\u{2018}' | '\u{2019}' => out.push('\''),
                '\u{201c}' | '\u{201d}' => out.push('"'),
                '\u{2026}' => out.push_str("..."),
                '\u{00b7}' => out.push('|'),
                '\u{2022}' | '\u{2020}' => out.push('*'),
                '\u{2021}' => out.push_str("**"),
                '\u{00a7}' => out.push_str("***"),
                '\u{2713}' => out.push_str("[ok]"),
                '\u{25cb}' => out.push_str("[--]"),
                '\u{00a0}' | '\u{2009}' | '\u{202f}' => out.push(' '),
                other => out.push(other),
            }
        }
        out
    }
}

/// Whether the scan passed the threshold it was given.
///
/// Never derived inside the renderer. It is the same value the process exit
/// code is built from, threaded in, because a printed `RESULT` that can
/// disagree with `$?` is worse than no printed result at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanResult {
    /// Nothing at or above the threshold.
    Passed,
    /// Something at or above the threshold.
    Failed,
}

/// What the terminal renderer needs beyond the report itself.
///
/// A struct rather than a widening list of positional booleans and enums: at
/// the call site `stdout(&report, true, Summary)` says nothing about which
/// argument is which, and the next option added would make it worse.
///
/// Everything counted here is a fact about the scan that ran. None of it is a
/// default the renderer could invent: a rule count nobody measured, or a
/// verdict recomputed from the findings, is a number that can be wrong while
/// looking exactly as authoritative as one that is right.
#[derive(Debug, Clone, Copy)]
pub struct StdoutOptions {
    /// Whether to emit ANSI colour. False emits no escape byte at all, which
    /// CI logs and piped output depend on.
    pub color: bool,
    /// Which characters to draw the report's furniture with.
    pub glyphs: Glyphs,
    /// How much of each crosswalk to print.
    pub crosswalks: CrosswalkDetail,
    /// Whether the CVE lookup was skipped on purpose.
    pub offline: bool,
    /// How many rules the analysis pass ran.
    pub rules: usize,
    /// How many dependencies were resolved to an exact version and looked up.
    pub dependencies: usize,
    /// Whether the scan passed the threshold it was given.
    pub result: ScanResult,
    /// The exit code this run will finish with.
    pub exit_code: u8,
    /// Whether to list the path of every file the scan read, grouped by kind.
    /// False prints only the one-line count of each kind.
    pub show_coverage: bool,
}

/// A rendered terminal report, and the one line `--quiet` prints.
///
/// The summary is returned rather than left for the caller to find, because
/// the caller used to find it with `rendered.lines().last()` — correct only
/// for as long as nothing was ever printed below the summary, and silently
/// wrong the moment something was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalReport {
    /// The whole report.
    pub text: String,
    /// The single line that summarises it.
    pub summary: String,
}

/// Render `report` for a terminal.
///
/// Defects are listed first, grouped by [`crate::category::Layer`] in the
/// order an attack runs — entry vectors, amplifiers, impacts, cross-layer
/// threats, then the defenses found absent — and within each of those worst
/// severity first. The grouping is what makes the list argue an order of work:
/// the first section is the one whose fixes make the later sections
/// unreachable. A clearly separated, visually quieter section for observations
/// follows, then what the scan did not cover, then the compliance crosswalks
/// the report carries.
///
/// This is presentation only. Nothing here changes what [`json`] or [`sarif`]
/// emit — both always carry the full crosswalk structure whatever
/// [`StdoutOptions::crosswalks`] says — and a finding's layer never appears in
/// either.
///
/// CVE status is always shown, even when nothing was checked.
#[must_use]
pub fn stdout(report: &Report, options: StdoutOptions) -> TerminalReport {
    stdout::render(report, options)
}
