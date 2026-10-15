//! Terminal rendering.
//!
//! The report reads top to bottom as the answer to four questions, in the
//! order a reader asks them: what ran, what the verdict is, what to fix, and
//! what the scan did not see.
//!
//! Defects are grouped by [`Layer`] and printed in the order an attack runs —
//! entry vectors, amplifiers, impacts, then the threats that span rings — and
//! the missing defenses close the list. A flat list by file answers "what is
//! wrong"; this ordering answers "what first", because the top section is the
//! one whose fixes make the sections below it unreachable. Within a section
//! the worst severity comes first: the file a finding lives in is on the
//! finding's own header line, so grouping by file would only add a level of
//! nesting that pushes a critical below a high.
//!
//! Observations follow in their own, visibly quieter section and are never
//! ranked among the layers, however their categories map — an observation is a
//! control the repository cannot show is actually missing, and giving it a
//! place in a priority order would be claiming otherwise. When they were not
//! collected the report says how many are being withheld and which flag shows
//! them; it never says "no observations" while the summary counts three.
//!
//! A "Files read" section precedes the coverage gaps and says how many skill
//! files, skill reference files, MCP configs and instruction files the scan
//! read, so a clean result is never mistaken for a scan that ignored them;
//! `--show-coverage` adds the path of every one.
//!
//! Coverage gaps are always printed, even when nothing was skipped and even
//! when no CVE lookup ran: a reader must never read "no CVEs listed" as "no
//! CVEs exist". The compliance crosswalk and the summary close it out.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::category::Layer;
use crate::compliance::{CROSSWALK_INTRO, Crosswalk, TERMINAL_CAVEAT};
use crate::finding::{Confidence, Finding, Kind, Severity};
use crate::report::{CveStatus, Report, Skip, SkipReason};

use super::{CrosswalkDetail, Glyphs, ScanResult, StdoutOptions, TerminalReport};

/// ANSI SGR codes used only when `color` is true.
mod ansi {
    pub(super) const RESET: &str = "\x1b[0m";
    pub(super) const CRITICAL: &str = "\x1b[1;31m";
    pub(super) const HIGH: &str = "\x1b[31m";
    pub(super) const MEDIUM: &str = "\x1b[33m";
    pub(super) const LOW: &str = "\x1b[36m";
    pub(super) const DIM: &str = "\x1b[2m";
    pub(super) const BOLD: &str = "\x1b[1m";
    pub(super) const GREEN: &str = "\x1b[32m";
}

/// The column every line of this report stays inside.
///
/// Eighty is the width a terminal, a CI log viewer and a pasted snippet all
/// still agree on. Two columns of slack keep a wrapped line from touching the
/// edge, where it is easy to misread as having been cut.
const WRAP: usize = 78;

/// Indent for the prose under a finding: enough to read as belonging to the
/// header above it, not so much that a paragraph loses a quarter of its width.
const PROSE: &str = "  ";

/// Render `report` for a terminal.
///
/// `color` false emits no ANSI escape byte, and [`Glyphs::Ascii`] emits no
/// non-ASCII character of the renderer's own — quoted text still reaches the
/// reader exactly as its source wrote it.
pub(crate) fn render(report: &Report, options: StdoutOptions) -> TerminalReport {
    let mut out = String::new();

    let defects: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.kind == Kind::Defect)
        .collect();
    let observations: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.kind == Kind::Observation)
        .collect();

    render_header(&mut out, report, options);
    render_steps(&mut out, report, options);
    render_verdict(&mut out, report, &defects, &observations, options);
    render_defects(&mut out, &defects, options);
    render_observations(&mut out, &observations, options);
    render_files_read(&mut out, report, options);
    render_coverage(&mut out, report, options);
    render_crosswalks(&mut out, report, options);

    let summary = summary_line(report);
    let _ = writeln!(out, "{summary}");
    let _ = writeln!(out, "Exit status: {}", options.exit_code);

    TerminalReport { text: out, summary }
}

// ---------------------------------------------------------------------------
// Header and the record of what actually ran
// ---------------------------------------------------------------------------

fn render_header(out: &mut String, report: &Report, options: StdoutOptions) {
    const LABEL: &str = "Bastyn scan: ";
    // Wrapped, not cut. A checked-out path can be arbitrarily deep, and it is
    // the one thing on the page that says which tree these findings are about.
    wrap_into(
        out,
        &paint(LABEL, ansi::BOLD, options.color),
        LABEL.len(),
        "  ",
        &report.root,
        None,
        options,
    );
    let _ = writeln!(
        out,
        "Mode: {}",
        if options.offline { "offline" } else { "online" }
    );
    out.push('\n');
}

/// What the scan did, one line per step, with the skipped ones marked.
///
/// Never a tick for work that did not happen. A reader who sees "checked
/// dependencies" and no CVE findings will conclude there are none, which is
/// the single most expensive thing this report could imply.
fn render_steps(out: &mut String, report: &Report, options: StdoutOptions) {
    step(out, true, "Discovered source tree", options);

    let files = report.summary.files_scanned;
    if files == 0 {
        step(
            out,
            false,
            "No files to analyse — nothing under this root matched an analyser",
            options,
        );
    } else {
        step(
            out,
            true,
            &format!(
                "Analysed {} with {}",
                plural(files, "file", "files"),
                plural(options.rules, "rule", "rules")
            ),
            options,
        );
    }

    // Everything a manifest yielded, pinned or not: an unpinned entry was
    // parsed just as successfully as a pinned one, it simply cannot be looked
    // up. Counting only the resolvable ones would understate what was read.
    let unpinned = report
        .skipped
        .iter()
        .filter(|skip| skip.reason == SkipReason::Unpinned)
        .count();
    let parsed = options.dependencies + unpinned;
    if parsed == 0 {
        step(out, false, "No dependencies found to check", options);
    } else {
        step(
            out,
            true,
            &format!("Parsed {}", plural(parsed, "dependency", "dependencies")),
            options,
        );
    }

    match &report.cve {
        CveStatus::Checked { dependencies } => step(
            out,
            true,
            &format!(
                "OSV vulnerability lookup — {} checked",
                plural(*dependencies, "dependency", "dependencies")
            ),
            options,
        ),
        CveStatus::Partial {
            dependencies,
            incomplete,
        } => step(
            out,
            false,
            &format!(
                "OSV vulnerability lookup incomplete — {} checked, results may be missing for {}",
                plural(*dependencies, "dependency", "dependencies"),
                plural(*incomplete, "dependency", "dependencies")
            ),
            options,
        ),
        CveStatus::NoManifest => step(
            out,
            false,
            "OSV vulnerability lookup skipped — no dependency manifest found",
            options,
        ),
        CveStatus::SkippedOffline => step(
            out,
            false,
            "OSV vulnerability lookup skipped — offline mode",
            options,
        ),
        CveStatus::Unreachable { reason } => step(
            out,
            false,
            &format!("OSV vulnerability lookup skipped — {reason}"),
            options,
        ),
    }

    out.push('\n');
}

/// One step line, with its marker and its em dashes translated for the
/// terminal that is going to render them.
///
/// Wrapped like anything else: an unreachable lookup explains itself in the
/// reason the network gave, and that is a sentence of unknown length.
fn step(out: &mut String, ran: bool, label: &str, options: StdoutOptions) {
    let (glyph, code) = if ran {
        (options.glyphs.tick(), ansi::GREEN)
    } else {
        (options.glyphs.circle(), ansi::DIM)
    };
    let marker = paint(glyph, code, options.color);
    let width = glyph.chars().count() + 1;
    wrap_into(
        out,
        &format!("{marker} "),
        width,
        &" ".repeat(width),
        label,
        None,
        options,
    );
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// The one line a CI log gets read for, and the two counts behind it.
///
/// `RESULT` is not derived here. It comes from the same value that becomes the
/// process exit code, because a printed status that can disagree with `$?` is
/// worse than no printed status at all.
fn render_verdict(
    out: &mut String,
    report: &Report,
    defects: &[&Finding],
    observations: &[&Finding],
    options: StdoutOptions,
) {
    let (word, code) = match options.result {
        ScanResult::Passed => ("PASSED", ansi::GREEN),
        ScanResult::Failed => ("FAILED", ansi::CRITICAL),
    };
    let _ = writeln!(out, "RESULT: {}", paint(word, code, options.color));

    if defects.is_empty() {
        out.push_str("No defects found.\n");
    } else {
        let _ = writeln!(
            out,
            "{} found: {}",
            plural(defects.len(), "defect", "defects"),
            severity_breakdown(defects)
        );
    }

    let _ = writeln!(
        out,
        "{}",
        observation_line(report, observations, options.glyphs)
    );
    out.push('\n');
}

/// `"1 critical, 2 high"`, worst first, silent about severities with nothing
/// in them.
fn severity_breakdown(defects: &[&Finding]) -> String {
    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .into_iter()
    .filter_map(|severity| {
        let count = defects
            .iter()
            .filter(|finding| finding.severity == severity)
            .count();
        (count > 0).then(|| format!("{count} {}", severity_label(severity)))
    })
    .collect::<Vec<_>>()
    .join(", ")
}

/// The true sentence about observations, out of the three that can be true.
///
/// The count comes from [`crate::report::Summary`], which is filled in before
/// the findings are filtered, so the number here and the number in the closing
/// summary are the same number. The report used to print "No observations."
/// above a summary line saying there were three, which is the contradiction
/// this function exists to make impossible.
fn observation_line(report: &Report, observations: &[&Finding], glyphs: Glyphs) -> String {
    let total = report.summary.observations;
    if total == 0 {
        return "No observations.".to_owned();
    }
    if observations.is_empty() {
        return glyphs.text(&format!(
            "{} hidden — use --show-observations",
            plural(total, "observation", "observations")
        ));
    }
    glyphs.text(&format!(
        "{} found — listed below",
        plural(total, "observation", "observations")
    ))
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// One heading in the defect list.
///
/// Declaration order is print order, and is the whole argument the report
/// makes: an entry vector is worth more than the impact it enables, because
/// closing it closes the impact too. Deriving `Ord` and bucketing into a
/// [`BTreeMap`] means the order lives in exactly one place — this enum — and
/// an empty section simply has no key to iterate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    Entry,
    Amplifiers,
    Impacts,
    CrossLayer,
    MissingDefenses,
}

impl Section {
    /// Which heading a layer prints under.
    fn of(layer: Layer) -> Self {
        match layer {
            Layer::Entry => Self::Entry,
            Layer::Amplifier => Self::Amplifiers,
            Layer::Impact => Self::Impacts,
            Layer::CrossLayer => Self::CrossLayer,
            // The defensive rings are a real distinction, and not one a reader
            // acts on differently: perimeter, machinery and impact mitigation
            // all reduce to the same instruction, "this control is absent".
            // Splitting them would cost three headings to say one thing.
            Layer::Defense(_) => Self::MissingDefenses,
        }
    }

    /// The heading, and the half-line that says why the section is where it is.
    fn heading(self) -> (&'static str, &'static str) {
        match self {
            Self::Entry => ("ENTRY VECTORS", "how an attack gets in; close these first"),
            Self::Amplifiers => ("AMPLIFIERS", "what turns a foothold into leverage"),
            Self::Impacts => ("IMPACTS", "what the attack finally costs"),
            Self::CrossLayer => ("CROSS-LAYER", "present at more than one ring"),
            Self::MissingDefenses => (
                "MISSING DEFENSES",
                "controls that would have broken the chain",
            ),
        }
    }
}

/// The section a finding is printed under.
///
/// A finding can name more than one category — `[LLM01, ZT4]` is both the way
/// in and the perimeter control that would have stopped it — and it must be
/// printed exactly once, so one of them has to win. The rule is the smallest
/// [`Layer`], which by that enum's declaration order means the earliest point
/// in the attack chain, and any threat ahead of any defense.
///
/// Both halves of that are deliberate. Filing `[LLM01, ZT4]` under entry
/// vectors rather than missing defenses is the same fix either way; the entry
/// framing is the one that tells a reader why it is urgent, and it keeps the
/// missing-defenses section to controls that are genuinely absent rather than
/// ones already accounted for above.
///
/// `categories` is usually non-empty — YAML rule loading rejects a rule
/// without one — but a hand-written Rust check can leave it empty (for
/// example `BAS-SKILL-001`, a spec-validity observation that carries no
/// security category). Such an unfiled finding must still be printed rather
/// than silently dropped, so it falls through to cross-layer.
fn section_of(finding: &Finding) -> Section {
    finding
        .categories
        .iter()
        .map(|category| Section::of(category.layer()))
        .min()
        .unwrap_or(Section::CrossLayer)
}

/// Worst first: severity, then confidence, then where it is.
///
/// Severity leads because that is the order the work gets done in. It did not
/// used to: findings were grouped by file inside each layer, which put a
/// `critical` in `tools.py` below a `high` in `graph.py` for no better reason
/// than the alphabet.
fn worst_first(a: &Finding, b: &Finding) -> std::cmp::Ordering {
    b.severity
        .cmp(&a.severity)
        .then_with(|| b.confidence.cmp(&a.confidence))
        .then_with(|| a.location.file.cmp(&b.location.file))
        .then_with(|| a.location.line.cmp(&b.location.line))
        .then_with(|| a.rule_id.cmp(&b.rule_id))
}

fn render_defects(out: &mut String, defects: &[&Finding], options: StdoutOptions) {
    if defects.is_empty() {
        return;
    }

    heading(out, "Findings", options);
    out.push('\n');

    let mut by_section: BTreeMap<Section, Vec<&Finding>> = BTreeMap::new();
    for finding in defects.iter().copied() {
        by_section
            .entry(section_of(finding))
            .or_default()
            .push(finding);
    }

    for (section, mut findings) in by_section {
        let (name, why) = section.heading();
        heading(
            out,
            &options.glyphs.text(&format!("{name} \u{2014} {why}")),
            options,
        );

        findings.sort_by(|a, b| worst_first(a, b));
        for finding in findings {
            write_finding(out, finding, options);
        }
    }
}

/// One defect: what and where, then what it is, then what to do.
fn write_finding(out: &mut String, finding: &Finding, options: StdoutOptions) {
    write_finding_head(out, finding, severity_code(finding.severity), options);

    write_wrapped(out, &finding.title, "", None, options);
    write_attribution(out, finding, options);
    write_references(out, &finding.references, options);

    // An empty description prints nothing rather than a blank indented block:
    // a gap in the layout says "there is more here" and there is not.
    if !finding.description.trim().is_empty() {
        out.push('\n');
        write_wrapped(out, &finding.description, PROSE, None, options);
    }

    if !finding.remediation.trim().is_empty() {
        out.push('\n');
        let _ = writeln!(out, "{PROSE}{}", paint("Fix:", ansi::BOLD, options.color));
        write_wrapped(out, &finding.remediation, PROSE, None, options);
    }

    out.push_str("\n\n");
}

/// Width the severity word is padded to, so rule ids line up under each other.
/// `CRITICAL` is the longest, at eight.
const SEVERITY_COLUMN: usize = 10;

/// `"CRITICAL  BAS-LLM10-003  tools.py:214"`, or two lines when a deep path
/// would push it past the edge.
///
/// `code` is the colour the severity is painted in — its own for a defect, the
/// dim one for an observation, which is what makes the quieter section look
/// quieter.
fn write_finding_head(out: &mut String, finding: &Finding, code: &str, options: StdoutOptions) {
    let severity = format!(
        "{:<SEVERITY_COLUMN$}",
        severity_label(finding.severity).to_uppercase()
    );
    let severity = paint(&severity, code, options.color);
    let location = format!(
        "{}:{}",
        finding.location.file.to_string_lossy(),
        finding.location.line
    );

    let plain = SEVERITY_COLUMN + finding.rule_id.chars().count() + 2 + location.chars().count();
    if plain <= WRAP {
        let _ = writeln!(out, "{severity}{}  {location}", finding.rule_id);
        return;
    }

    // A deep path would push the header past the edge. The location moves to
    // its own line rather than being cut: a truncated path is a path nobody
    // can open.
    let _ = writeln!(out, "{severity}{}", finding.rule_id);
    let indent = " ".repeat(SEVERITY_COLUMN);
    write_wrapped(out, &location, &indent, None, options);
}

/// `"Confidence: high · Categories: LLM01, ZT4"`, or just `"Confidence: high"`
/// for a hand-written Rust check that carries no category at all (for
/// example `BAS-SKILL-001`, a spec-validity observation) -- an empty list
/// still deserves a line, just not a dangling `· Categories:` with nothing
/// after it.
fn write_attribution(out: &mut String, finding: &Finding, options: StdoutOptions) {
    let categories: Vec<&str> = finding
        .categories
        .iter()
        .map(|category| category.id())
        .collect();
    let confidence = format!("Confidence: {}", confidence_label(finding.confidence));
    let line = if categories.is_empty() {
        options.glyphs.text(&confidence)
    } else {
        let label = if categories.len() == 1 {
            "Category"
        } else {
            "Categories"
        };
        options.glyphs.text(&format!(
            "{confidence} \u{b7} {label}: {}",
            categories.join(", ")
        ))
    };
    write_wrapped(out, &line, "", Some(ansi::DIM), options);
}

/// The external identifiers a grouped finding covers.
///
/// Capped, because the point of grouping was to stop a wall of advisory ids
/// burying everything else. The complete list is always in the JSON and SARIF
/// output.
fn write_references(out: &mut String, references: &[String], options: StdoutOptions) {
    /// How many identifiers to name before summarising the rest.
    const SHOWN: usize = 4;

    if references.len() < 2 {
        return;
    }

    let named = references
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let line = if references.len() > SHOWN {
        format!("{named}, and {} more", references.len() - SHOWN)
    } else {
        named
    };

    write_wrapped(out, &line, "", Some(ansi::DIM), options);
}

/// Observations, in their own quieter section.
///
/// Terser than a defect on purpose: no description and no fix, because an
/// observation is a control the repository cannot show is actually missing,
/// and printing an instruction under one would be telling a reader to act on
/// something the scan has not established.
fn render_observations(out: &mut String, observations: &[&Finding], options: StdoutOptions) {
    if observations.is_empty() {
        return;
    }

    heading(
        out,
        &options
            .glyphs
            .text("OBSERVATIONS \u{2014} context-dependent, not defects"),
        options,
    );

    let mut sorted = observations.to_vec();
    sorted.sort_by(|a, b| worst_first(a, b));

    for finding in sorted {
        write_finding_head(out, finding, ansi::DIM, options);
        write_wrapped(out, &finding.title, "", Some(ansi::DIM), options);
        write_attribution(out, finding, options);
        out.push('\n');
    }
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Files read
// ---------------------------------------------------------------------------

/// How many files of each kind the scan read, and with `show_coverage` which.
///
/// Always printed, so a clean result on a skills repository is distinguishable
/// from a scan that never looked at skills. The listing is uncapped and each
/// path is printed whole, however long: a path cut short names no file.
fn render_files_read(out: &mut String, report: &Report, options: StdoutOptions) {
    let coverage = &report.coverage;
    heading(out, "Files read", options);

    let sentence = format!(
        "{}, {}, {}, {} read.",
        plural(coverage.skill_files.len(), "skill file", "skill files"),
        plural(
            coverage.skill_reference_files.len(),
            "skill reference",
            "skill references"
        ),
        plural(coverage.mcp_manifests.len(), "MCP config", "MCP configs"),
        plural(
            coverage.instruction_files.len(),
            "instruction file",
            "instruction files"
        ),
    );
    write_wrapped(out, &sentence, "", None, options);

    if options.show_coverage {
        let kinds: [(&str, &[String]); 5] = [
            ("Skill files", &coverage.skill_files),
            ("Skill reference files", &coverage.skill_reference_files),
            ("MCP configs", &coverage.mcp_manifests),
            ("Instruction files", &coverage.instruction_files),
            ("Skill files no analyser reads", &coverage.skill_unanalysed),
        ];
        for (label, paths) in kinds {
            if paths.is_empty() {
                continue;
            }
            let _ = writeln!(out, "\n{label}:");
            for path in paths {
                let _ = writeln!(out, "{PROSE}{path}");
            }
        }
    }
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Coverage gaps
// ---------------------------------------------------------------------------

/// Everything the scan did not cover, grouped by why.
///
/// Every entry used to carry its own copy of the reason, so six unpinned
/// dependencies printed the same sentence six times and the six names — the
/// only part that differed — were the hardest thing on the line to find. The
/// reason is stated once, with a count, and the entries are listed bare
/// underneath.
///
/// Always printed, even when there is nothing to say, because the CVE status
/// lives here: a reader must never read "no CVEs listed" as "no CVEs exist".
fn render_coverage(out: &mut String, report: &Report, options: StdoutOptions) {
    heading(out, "Coverage gaps", options);

    let mut by_reason: BTreeMap<SkipReason, Vec<&Skip>> = BTreeMap::new();
    for skip in &report.skipped {
        by_reason.entry(skip.reason).or_default().push(skip);
    }

    if by_reason.is_empty() {
        out.push_str("Every file the scan reached was analysed.\n");
    }

    for (reason, entries) in by_reason {
        write_wrapped(out, &reason.sentence(entries.len()), "", None, options);
        write_skip_entries(out, &entries, options);
        out.push('\n');
    }

    write_wrapped(out, &cve_sentence(&report.cve), "", None, options);
    out.push_str("\n\n");
}

/// Two columns: what was skipped, and the one thing that differs between
/// entries sharing a reason.
fn write_skip_entries(out: &mut String, entries: &[&Skip], options: StdoutOptions) {
    let widest = entries
        .iter()
        .filter(|skip| worth_saying(skip))
        .map(|skip| skip.path.chars().count())
        .max()
        .unwrap_or(0);
    // Two to indent, two between the columns, and a detail worth reading.
    let aligned = PROSE.len() + widest + 2 + SHORTEST_USEFUL_DETAIL <= WRAP;

    for skip in entries {
        if !worth_saying(skip) {
            let _ = writeln!(out, "{PROSE}{}", skip.path);
            continue;
        }
        let head = format!("{PROSE}{:<widest$}  ", skip.path);
        if aligned && head.chars().count() + skip.detail.chars().count() <= WRAP {
            let _ = writeln!(out, "{head}{}", skip.detail);
        } else {
            let _ = writeln!(out, "{PROSE}{}", skip.path);
            write_wrapped(out, &skip.detail, "    ", Some(ansi::DIM), options);
        }
    }
}

/// Below this a second column is a stub, and the entry reads better alone.
const SHORTEST_USEFUL_DETAIL: usize = 8;

/// Whether an entry's detail tells the reader anything its path did not.
///
/// `--exclude vendor/` removing `vendor/` is the common case, and printing
/// `vendor/  vendor/` teaches nobody anything. `--exclude "*.min.js"` removing
/// `web/app.min.js` is the case the column exists for.
fn worth_saying(skip: &Skip) -> bool {
    !skip.detail.is_empty() && skip.detail.trim_matches('/') != skip.path.trim_matches('/')
}

/// What happened to the CVE lookup, as a sentence.
fn cve_sentence(status: &CveStatus) -> String {
    match status {
        CveStatus::Checked { dependencies } => format!(
            "{} checked against the OSV vulnerability database.",
            plural(*dependencies, "dependency was", "dependencies were")
        ),
        CveStatus::Partial {
            dependencies,
            incomplete,
        } => format!(
            "{} checked against the OSV vulnerability database, but results for {} may be incomplete because not every OSV response could be read.",
            plural(*dependencies, "dependency was", "dependencies were"),
            plural(*incomplete, "dependency", "dependencies")
        ),
        CveStatus::NoManifest => {
            "CVEs were not checked because no dependency manifest was found.".to_owned()
        }
        CveStatus::SkippedOffline => {
            "CVEs were not checked because the scan ran in offline mode.".to_owned()
        }
        CveStatus::Unreachable { reason } => format!("CVEs were not checked: {reason}."),
    }
}

// ---------------------------------------------------------------------------
// Compliance crosswalk
// ---------------------------------------------------------------------------

/// The same findings, regrouped by the areas of the frameworks they touch.
///
/// Additive on purpose: the layered listing above is untouched, and this reads
/// as a second view of it rather than a replacement. A compliance reader and
/// an engineer want different arrangements of one set of facts.
///
/// How much is printed is [`StdoutOptions::crosswalks`], never a guess from
/// how many crosswalks the report carries. A default scan carries all three
/// and prints them compactly; `--group-by` carries one and prints it in full.
fn render_crosswalks(out: &mut String, report: &Report, options: StdoutOptions) {
    if report.crosswalks.is_empty() {
        return;
    }

    heading(out, "Compliance crosswalk", options);
    write_wrapped(out, CROSSWALK_INTRO, "", None, options);
    out.push('\n');

    let notes = Footnotes::of(&report.crosswalks);

    for (index, walk) in report.crosswalks.iter().enumerate() {
        write_crosswalk_title(out, walk, &notes.marker(index, options.glyphs), options);
        match options.crosswalks {
            CrosswalkDetail::Summary => write_crosswalk_areas(out, walk, options),
            CrosswalkDetail::Detailed => write_crosswalk_findings(out, report, walk, options),
        }
        out.push('\n');
    }

    notes.write(out, options);

    write_wrapped(out, TERMINAL_CAVEAT, "", None, options);
    out.push('\n');
}

/// The footnote markers, and the standings they point at.
///
/// Two frameworks that say the same thing about their own standing share a
/// marker rather than printing the paragraph twice. Both NIST documents are
/// voluntary guidance in identical words, and a caveat a reader has already
/// read once is one they skip the second time.
struct Footnotes {
    /// Distinct standings, in the order the frameworks first named them.
    texts: Vec<String>,
    /// For each crosswalk, which of `texts` it points at.
    of_walk: Vec<usize>,
}

impl Footnotes {
    fn of(walks: &[Crosswalk]) -> Self {
        let mut texts: Vec<String> = Vec::new();
        let mut of_walk = Vec::with_capacity(walks.len());
        for walk in walks {
            let at = texts.iter().position(|text| *text == walk.standing);
            of_walk.push(at.unwrap_or_else(|| {
                texts.push(walk.standing.clone());
                texts.len() - 1
            }));
        }
        Self { texts, of_walk }
    }

    fn marker(&self, walk: usize, glyphs: Glyphs) -> String {
        self.of_walk
            .get(walk)
            .map_or_else(String::new, |note| glyphs.marker(*note))
    }

    fn write(&self, out: &mut String, options: StdoutOptions) {
        for (index, text) in self.texts.iter().enumerate() {
            let marker = options.glyphs.marker(index);
            let indent = " ".repeat(marker.chars().count() + 1);
            write_hanging(out, &format!("{marker} "), &indent, text, None, options);
            out.push('\n');
        }
    }
}

/// `"EU AI Act \u{2020}  \u{b7}  Regulation (EU) 2024/1689"`, on one line.
///
/// The document identifier, not the full citation. An identifier a reader
/// cannot trace to a document is not a citation \u{2014} but the identifier
/// *is* the traceable half, and it is the half that fits. The full title added
/// length without adding anything checkable, and it wrapped five of the six
/// heading lines in a three-framework table, so the citations ended up
/// shouting over the counts they were introducing.
/// [`crate::compliance::Crosswalk::citation`] is untouched, and is what JSON
/// and SARIF carry.
///
/// `as amended by Regulation (EU) 2026/1744` is not lost with it: the standing
/// footnote this heading's marker points at names the amendment, and saying it
/// twice was half of what made the line wrap.
fn write_crosswalk_title(out: &mut String, walk: &Crosswalk, marker: &str, options: StdoutOptions) {
    let name = paint(&walk.name, ansi::BOLD, options.color);
    let head = format!("{name} {marker}  {}  ", options.glyphs.middot());
    let visible = walk.name.chars().count()
        + 1
        + marker.chars().count()
        + 2
        + options.glyphs.middot().chars().count()
        + 2;
    // Still wrapped rather than cut, because nothing here may run off the
    // edge. With the identifier alone, no framework in the table reaches the
    // wrap; `a_framework_heading_never_wraps` is what keeps that true.
    let hanging = " ".repeat(visible.min(WRAP.saturating_sub(SHORTEST_CITATION)));
    wrap_into(
        out,
        &head,
        visible,
        &hanging,
        walk.framework.document_id(),
        None,
        options,
    );
}

/// Below this a hanging citation has too little room left to read, and the
/// continuation falls back to a shallower indent.
const SHORTEST_CITATION: usize = 24;

/// One line per area: its identifier, as much of its quoted title as fits, and
/// the counts, right-aligned.
///
/// The counts are the point of this form and are never truncated. The title is
/// an aid to recognising the identifier here, not the citation itself — a NIST
/// Generative AI Profile risk definition is a full paragraph, and four of
/// those would bury what the reader came for. `--group-by` prints them whole.
fn write_crosswalk_areas(out: &mut String, walk: &Crosswalk, options: StdoutOptions) {
    if walk.groups.is_empty() && walk.unmapped.findings.is_empty() {
        let _ = writeln!(out, "{PROSE}no findings to group.");
        return;
    }

    for group in &walk.groups {
        write_area_line(
            out,
            &group.id,
            Some(group.title.as_str()),
            &counts(group.defects, group.observations),
            options,
        );
    }
    if !walk.unmapped.findings.is_empty() {
        write_area_line(
            out,
            "not covered by this framework",
            None,
            &counts(walk.unmapped.defects, walk.unmapped.observations),
            options,
        );
    }
}

/// Below this there is no room for a title fragment worth reading, so the
/// identifier and its counts stand alone.
const SHORTEST_USEFUL_TITLE: usize = 12;

fn write_area_line(
    out: &mut String,
    id: &str,
    title: Option<&str>,
    counts: &str,
    options: StdoutOptions,
) {
    // Two between the text and the counts, so they never touch.
    let right = WRAP.saturating_sub(counts.chars().count());
    let mut text = format!("{PROSE}{id}");

    if let Some(title) = title {
        let room = right.saturating_sub(text.chars().count() + 5);
        if room >= SHORTEST_USEFUL_TITLE
            && let Some(short) = area_title(title, room, options.glyphs)
        {
            let _ = write!(text, " {} {short}", options.glyphs.dash());
        }
    }

    let pad = right.saturating_sub(text.chars().count()).max(2);
    let _ = writeln!(
        out,
        "{text}{}{}",
        " ".repeat(pad),
        paint(counts, ansi::DIM, options.color)
    );
}

/// As much of a transcribed area heading as fits in `width`, or `None` when
/// nothing that fits is worth reading.
///
/// Three rules, in order.
///
/// **Cut at the separator.** Several NIST subcategories are written as a
/// heading, an en dash, and an elaboration: `"AI system security and
/// resilience \u{2013} as identified in the MAP function \u{2013} are
/// evaluated and documented."` The text before the first dash is the
/// subcategory's own name, and it is a complete phrase.
///
/// **Otherwise cut at a clause boundary, or not at all.** A title with no
/// separator is kept whole if it fits. If it does not, it may still be cut,
/// but only where the source text itself broke — at a comma, semicolon or
/// colon. Anywhere else produces a fragment, and `"Lowered barriers for
/// offensive cyber\u{2026}"` in a compliance table reads as though somebody
/// stopped mid-sentence, which is exactly what happened.
///
/// **Otherwise nothing.** The identifier and the counts are the load-bearing
/// parts of this line, and `--group-by` prints every title in full, quoted.
fn area_title(title: &str, width: usize, glyphs: Glyphs) -> Option<String> {
    let heading = before_separator(title);
    if heading.chars().count() <= width {
        return Some(glyphs.text(heading));
    }
    clause_prefix(heading, width, glyphs)
}

/// The text before the first spaced dash, or all of it when there is none.
fn before_separator(title: &str) -> &str {
    ["\u{2013}", "\u{2014}"]
        .iter()
        .filter_map(|dash| title.find(&format!(" {dash} ")))
        .min()
        .map_or(title, |at| title[..at].trim_end())
}

/// `text` cut to `width`, but only where the source text had already ended a
/// clause.
///
/// Every such place is a candidate and the longest one that fits wins, which
/// is not the same as filling greedily by word and then hoping the last word
/// happens to carry a comma — that answer is `None` far more often than it
/// needs to be, because the comma it is looking for sits one word past the
/// edge and is about to be deleted anyway.
fn clause_prefix(text: &str, width: usize, glyphs: Glyphs) -> Option<String> {
    /// Punctuation the source used to end a clause.
    const BOUNDARY: [char; 3] = [',', ';', ':'];

    let mark = glyphs.ellipsis();
    let budget = width.checked_sub(mark.chars().count())?;

    let mut best: Option<&str> = None;
    for (at, character) in text.char_indices() {
        if !BOUNDARY.contains(&character) {
            continue;
        }
        let kept = text[..at].trim_end();
        if !kept.is_empty() && kept.chars().count() <= budget {
            best = Some(kept);
        }
    }

    best.map(|kept| format!("{}{mark}", glyphs.text(kept)))
}

/// One framework in full: every finding under every area it is relevant to.
///
/// What `--group-by <framework>` asks for. Deliberately terser per finding
/// than the listing above — the full text of every one is already on screen,
/// and repeating it would bury the grouping this section exists to show. A
/// finding relevant to three areas is listed under all three, which is what a
/// crosswalk means.
fn write_crosswalk_findings(
    out: &mut String,
    report: &Report,
    walk: &Crosswalk,
    options: StdoutOptions,
) {
    if walk.groups.is_empty() && walk.unmapped.findings.is_empty() {
        let _ = writeln!(out, "{PROSE}no findings to group.");
        return;
    }

    for group in &walk.groups {
        let _ = writeln!(
            out,
            "{PROSE}{} ({}) {} relevant to:",
            group.id,
            counts(group.defects, group.observations),
            options.glyphs.dash(),
        );
        // Quoted in full on its own wrapped lines: an identifier a reader
        // cannot check against its source text is not a citation.
        write_wrapped(
            out,
            &format!(
                "{}{}{}",
                options.glyphs.quote_open(),
                group.title,
                options.glyphs.quote_close()
            ),
            "    ",
            Some(ansi::DIM),
            options,
        );
        write_area_findings(out, report, &group.findings, options);
        out.push('\n');
    }

    if !walk.unmapped.findings.is_empty() {
        let heading = format!(
            "not covered by this framework ({}) \u{2014} listed so nothing disappears from a \
compliance view",
            counts(walk.unmapped.defects, walk.unmapped.observations)
        );
        write_wrapped(out, &heading, PROSE, Some(ansi::DIM), options);
        write_area_findings(out, report, &walk.unmapped.findings, options);
    }
}

fn write_area_findings(
    out: &mut String,
    report: &Report,
    indices: &[usize],
    options: StdoutOptions,
) {
    for index in indices {
        let Some(finding) = report.findings.get(*index) else {
            continue;
        };
        let severity = format!(
            "{:<SEVERITY_COLUMN$}",
            severity_label(finding.severity).to_uppercase()
        );
        let severity = if finding.kind == Kind::Observation {
            paint(&severity, ansi::DIM, options.color)
        } else {
            paint(&severity, severity_code(finding.severity), options.color)
        };
        let location = format!(
            "{}:{}",
            finding.location.file.to_string_lossy(),
            finding.location.line
        );
        let used = 4
            + SEVERITY_COLUMN
            + finding.rule_id.chars().count()
            + 2
            + location.chars().count()
            + 2;
        if used + SHORTEST_USEFUL_TITLE <= WRAP {
            let _ = writeln!(
                out,
                "    {severity}{}  {location}  {}",
                finding.rule_id,
                ellipsise(&finding.title, WRAP - used, options.glyphs)
            );
            continue;
        }

        // A deep path has eaten the line. The path wraps rather than being
        // cut — a truncated path is one nobody can open — and the title,
        // which is printed in full in the listing above, drops below it.
        let _ = writeln!(out, "    {severity}{}", finding.rule_id);
        write_wrapped(out, &location, "      ", None, options);
        write_wrapped(
            out,
            &ellipsise(&finding.title, WRAP - 6, options.glyphs),
            "      ",
            Some(ansi::DIM),
            options,
        );
    }
}

/// `"2 defects, 1 observation"`, or just the half that is non-zero.
fn counts(defects: usize, observations: usize) -> String {
    match (defects, observations) {
        (0, 0) => "none".to_string(),
        (0, observations) => plural(observations, "observation", "observations"),
        (defects, 0) => plural(defects, "defect", "defects"),
        (defects, observations) => format!(
            "{}, {}",
            plural(defects, "defect", "defects"),
            plural(observations, "observation", "observations")
        ),
    }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// The one line `--quiet` prints.
///
/// Returned from [`render`] rather than recovered by the caller from the last
/// line of the report: the caller used to take `rendered.lines().last()`,
/// which stopped being the summary the moment anything was printed below it.
fn summary_line(report: &Report) -> String {
    format!(
        "Scan complete: {}, {}, {}",
        plural(report.summary.defects, "defect", "defects"),
        plural(report.summary.observations, "observation", "observations"),
        plural(
            report.summary.files_skipped,
            "coverage gap",
            "coverage gaps"
        ),
    )
}

// ---------------------------------------------------------------------------
// Shared layout helpers
// ---------------------------------------------------------------------------

/// A section heading, underlined to its own width.
fn heading(out: &mut String, text: &str, options: StdoutOptions) {
    let text = options.glyphs.text(text);
    let width = text.chars().count().min(WRAP);
    let _ = writeln!(out, "{}", paint(&text, ansi::BOLD, options.color));
    let _ = writeln!(
        out,
        "{}",
        paint(
            &options.glyphs.rule().repeat(width),
            ansi::DIM,
            options.color
        )
    );
}

fn paint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("{code}{text}{}", ansi::RESET)
    } else {
        text.to_string()
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

fn severity_code(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => ansi::CRITICAL,
        Severity::High => ansi::HIGH,
        Severity::Medium => ansi::MEDIUM,
        Severity::Low => ansi::LOW,
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

/// Write `text` wrapped to [`WRAP`] columns under `indent`.
fn write_wrapped(
    out: &mut String,
    text: &str,
    indent: &str,
    code: Option<&str>,
    options: StdoutOptions,
) {
    wrap_into(
        out,
        indent,
        indent.chars().count(),
        indent,
        text,
        code,
        options,
    );
}

/// Wrap `text` with a different prefix on the first line.
fn write_hanging(
    out: &mut String,
    first: &str,
    indent: &str,
    text: &str,
    code: Option<&str>,
    options: StdoutOptions,
) {
    wrap_into(
        out,
        first,
        first.chars().count(),
        indent,
        text,
        code,
        options,
    );
}

/// Wrap `text` to [`WRAP`] columns, with `first` before the first line and
/// `indent` before the rest.
///
/// `first_width` is stated separately because a first-line prefix may already
/// carry ANSI escapes, whose bytes take no space on screen.
///
/// Breaks on spaces so a quoted article heading survives the wrap intact. A
/// single word wider than the line is broken rather than allowed to run off
/// the edge: the eighty-column promise has to hold for a URL or a deep path
/// too, and a line that runs off the side is one nobody reads.
fn wrap_into(
    out: &mut String,
    first: &str,
    first_width: usize,
    indent: &str,
    text: &str,
    code: Option<&str>,
    options: StdoutOptions,
) {
    let text = options.glyphs.text(text);
    let rest_width = WRAP.saturating_sub(indent.chars().count()).max(1);
    // A word is broken to whichever of the two lines is narrower, because a
    // piece is cut before it is known which one it will land on. The first
    // line is the narrow one whenever a label or a marker precedes it.
    let piece_width = rest_width.min(WRAP.saturating_sub(first_width)).max(1);

    let mut prefix = first.to_owned();
    let mut width = WRAP.saturating_sub(first_width).max(1);
    let mut line = String::new();
    let mut pending = true;

    for word in text.split_whitespace() {
        for piece in break_word(word, piece_width) {
            let extra = piece.chars().count() + usize::from(!line.is_empty());
            if !line.is_empty() && line.chars().count() + extra > width {
                emit(out, &prefix, &line, code, options.color);
                line.clear();
                pending = false;
                indent.clone_into(&mut prefix);
                width = rest_width;
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&piece);
        }
    }
    if !line.is_empty() || pending {
        emit(out, &prefix, &line, code, options.color);
    }
}

/// One wrapped line: the prefix as-is, the text painted if a colour was asked
/// for.
fn emit(out: &mut String, prefix: &str, line: &str, code: Option<&str>, color: bool) {
    match code {
        Some(code) => {
            let _ = writeln!(out, "{prefix}{}", paint(line, code, color));
        }
        None => {
            let _ = writeln!(out, "{prefix}{line}");
        }
    }
}

/// `word` in pieces no wider than `width`.
fn break_word(word: &str, width: usize) -> Vec<String> {
    if word.chars().count() <= width {
        return vec![word.to_owned()];
    }
    word.chars()
        .collect::<Vec<char>>()
        .chunks(width)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

/// `text` cut to `width` characters at a word boundary, with an ellipsis.
///
/// Breaks between words so the fragment that survives is readable; a first
/// word longer than `width` is cut mid-word rather than dropped, because an
/// empty line says less than a truncated one.
fn ellipsise(text: &str, width: usize, glyphs: Glyphs) -> String {
    let text = glyphs.text(text);
    let mark = glyphs.ellipsis();
    if text.chars().count() <= width {
        return text;
    }
    let budget = width.saturating_sub(mark.chars().count());
    let mut kept = String::new();
    for word in text.split_whitespace() {
        let extra = word.chars().count() + usize::from(!kept.is_empty());
        if kept.chars().count() + extra > budget {
            break;
        }
        if !kept.is_empty() {
            kept.push(' ');
        }
        kept.push_str(word);
    }
    if kept.is_empty() {
        kept = text.chars().take(budget).collect();
    }
    kept.push_str(mark);
    kept
}

/// `"1 file"`, `"3 files"`.
///
/// Worth the eight lines: a security tool that prints "1 files" invites the
/// reader to wonder what else it did not check.
///
/// `pub(super)` rather than private: `render::sarif`'s own CVE-incomplete
/// notification counts dependencies the same way and reuses this rather than
/// growing a second copy.
pub(super) fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("{count} {one}")
    } else {
        format!("{count} {many}")
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::{
        CrosswalkDetail, Glyphs, ScanResult, StdoutOptions, area_title, ellipsise, plural, render,
    };
    use crate::compliance::{
        CROSSWALK_INTRO, FORBIDDEN_CHARACTERISATIONS, FORBIDDEN_CLAIMS, Framework, TERMINAL_CAVEAT,
        crosswalk,
    };
    use crate::finding::{Kind, Severity};
    use crate::render::test_support::{
        EVERY_REASON, defect, empty_report, every_skip_reason, layered_report,
        observations_withheld, report_with, verbose_report, worse_finding_in_the_later_file,
    };
    use crate::report::{CveStatus, Report};

    /// The options a scan with no flags produces, into a pipe.
    ///
    /// Named for the detail level rather than wrapping [`render`] anonymously,
    /// because which of the two forms a test is asserting about is the whole
    /// point of most of the assertions below.
    fn options(color: bool) -> StdoutOptions {
        StdoutOptions {
            color,
            glyphs: Glyphs::Unicode,
            crosswalks: CrosswalkDetail::Summary,
            offline: true,
            rules: 43,
            dependencies: 14,
            result: ScanResult::Failed,
            exit_code: 1,
            show_coverage: false,
        }
    }

    /// The terminal output a scan with no flags produces.
    fn summarised(report: &Report, color: bool) -> String {
        render(report, options(color)).text
    }

    /// The terminal output `--group-by <framework>` produces.
    fn detailed(report: &Report, color: bool) -> String {
        render(
            report,
            StdoutOptions {
                crosswalks: CrosswalkDetail::Detailed,
                ..options(color)
            },
        )
        .text
    }

    /// `layered_report` plus an excessive-agency defect.
    ///
    /// `layered_report` was built for the layer sections and happens to name
    /// no `LLM03` or `ZT2`, so on its own it exercises only the articles and
    /// subcategories those two do not reach — Art. 14 and `MAP 3.5` would
    /// never appear, and an ordering test could not see them. One extra
    /// defect makes the fixture cover every group each framework can produce.
    fn base() -> Report {
        let mut report = layered_report();
        let mut agency = defect();
        agency.rule_id = "BAS-ZT2-001".to_string();
        agency.title = "Agent granted every tool in the registry".to_string();
        agency.categories = vec![
            crate::category::Category::Llm03,
            crate::category::Category::Zt2,
        ];
        report.findings.push(agency);
        report.summary.defects += 1;
        report
    }

    /// [`base`] crosswalked to one framework, as `--group-by` produces.
    fn grouped(framework: Framework) -> Report {
        let mut report = base();
        report.crosswalks = vec![crosswalk(&report, framework)];
        report
    }

    /// [`base`] crosswalked to every framework, as a scan with no flags
    /// produces.
    fn grouped_by_all() -> Report {
        let mut report = base();
        report.crosswalks = Framework::ALL
            .iter()
            .map(|framework| crosswalk(&report, *framework))
            .collect();
        report
    }

    /// A report with nothing found, crosswalked to every framework.
    ///
    /// The shape a clean repository produces under the new default, and the
    /// one most at risk of reading as a clean bill of regulatory health.
    fn empty_grouped_by_all() -> Report {
        let mut report = empty_report();
        report.crosswalks = Framework::ALL
            .iter()
            .map(|framework| crosswalk(&report, *framework))
            .collect();
        report
    }

    /// The text with every run of whitespace collapsed, so an assertion about
    /// wording is not also an assertion about where the lines were wrapped.
    fn unwrapped(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Where `needle` starts, with the whole report in the failure message.
    ///
    /// Ordering assertions are the only way to test a layout without pinning
    /// its wording, and a bare `Option` comparison tells you nothing about why
    /// it failed.
    fn position(text: &str, needle: &str) -> usize {
        assert!(text.contains(needle), "expected {needle:?} in:\n{text}");
        text.find(needle).unwrap()
    }

    /// Just the compliance crosswalk, which is the only part of the report the
    /// anti-overclaim word filter applies to.
    ///
    /// "Coverage gaps" is a legitimate heading elsewhere, and `gap` is on the
    /// list, so a filter run over the whole document would fail on a heading
    /// that claims nothing at all.
    fn crosswalk_section(text: &str) -> String {
        let start = position(text, "Compliance crosswalk");
        let end = position(text, "Scan complete:");
        text[start..end].to_owned()
    }

    // -----------------------------------------------------------------
    // What ran
    // -----------------------------------------------------------------

    /// The header says which tree, and which mode.
    #[test]
    fn the_report_opens_with_what_was_scanned() {
        let report = report_with(CveStatus::SkippedOffline);
        assert!(summarised(&report, false).starts_with("Bastyn scan: /repo\nMode: offline\n"));

        let online = render(
            &report,
            StdoutOptions {
                offline: false,
                ..options(false)
            },
        )
        .text;
        assert!(online.contains("Mode: online"), "{online}");
    }

    /// A step that did not run never gets a tick.
    ///
    /// A reader who sees "checked dependencies" and no CVE findings will
    /// conclude there are none, which is the most expensive thing this report
    /// could imply.
    #[test]
    fn a_skipped_step_is_never_marked_as_having_run() {
        let text = summarised(&report_with(CveStatus::SkippedOffline), false);
        let osv = text
            .lines()
            .find(|line| line.contains("OSV"))
            .unwrap_or_else(|| unreachable!("no OSV step in:\n{text}"));
        assert!(
            osv.starts_with(Glyphs::Unicode.circle()),
            "an offline scan must not tick the lookup it skipped: {osv:?}"
        );
        assert!(osv.contains("offline mode"), "{osv:?}");

        let checked = summarised(&report_with(CveStatus::Checked { dependencies: 5 }), false);
        let osv = checked
            .lines()
            .find(|line| line.contains("OSV"))
            .unwrap_or_else(|| unreachable!("no OSV step in:\n{checked}"));
        assert!(osv.starts_with(Glyphs::Unicode.tick()), "{osv:?}");
        assert!(osv.contains("5 dependencies"), "{osv:?}");
    }

    /// The counts on the checklist are the scan's own, not the renderer's
    /// guesses.
    #[test]
    fn the_checklist_counts_come_from_the_scan() {
        let mut report = report_with(CveStatus::SkippedOffline);
        report.skipped = every_skip_reason();
        let text = render(
            &report,
            StdoutOptions {
                rules: 43,
                dependencies: 14,
                ..options(false)
            },
        )
        .text;

        assert!(
            text.contains("Analysed 17 files with 43 rules"),
            "the file count is the report's and the rule count the caller's:\n{text}"
        );
        // Fourteen resolved plus the one unpinned entry in the fixture: an
        // unpinned dependency was parsed just as successfully as a pinned one,
        // it simply cannot be looked up.
        assert!(text.contains("Parsed 15 dependencies"), "{text}");
    }

    // -----------------------------------------------------------------
    // The verdict
    // -----------------------------------------------------------------

    /// `RESULT` is whatever it was told, and the exit status agrees with it.
    #[test]
    fn the_result_line_states_what_it_was_given() {
        let report = report_with(CveStatus::SkippedOffline);

        let failed = render(
            &report,
            StdoutOptions {
                result: ScanResult::Failed,
                exit_code: 1,
                ..options(false)
            },
        )
        .text;
        assert!(failed.contains("RESULT: FAILED"), "{failed}");
        assert!(failed.contains("Exit status: 1"), "{failed}");
        assert!(!failed.contains("RESULT: PASSED"), "{failed}");

        let passed = render(
            &report,
            StdoutOptions {
                result: ScanResult::Passed,
                exit_code: 0,
                ..options(false)
            },
        )
        .text;
        assert!(passed.contains("RESULT: PASSED"), "{passed}");
        assert!(passed.contains("Exit status: 0"), "{passed}");
        assert!(!passed.contains("RESULT: FAILED"), "{passed}");
    }

    /// The defect line breaks the count down by severity, worst first.
    #[test]
    fn the_defect_line_says_how_bad() {
        let text = summarised(&worse_finding_in_the_later_file(), false);
        assert!(
            text.contains("2 defects found: 1 critical, 1 high"),
            "{text}"
        );
        assert!(
            summarised(&empty_report(), false).contains("No defects found."),
            "a clean report says so plainly"
        );
    }

    // -----------------------------------------------------------------
    // Observations: the contradiction this layout was built to remove
    // -----------------------------------------------------------------

    /// Each of the three true things the report can say about observations,
    /// and it says the true one.
    #[test]
    fn the_observation_line_never_argues_with_the_summary() {
        // Counted but not collected: the old report printed "No
        // observations." directly above a summary saying there were three.
        let hidden = summarised(&observations_withheld(), false);
        assert!(
            hidden.contains("3 observations hidden \u{2014} use --show-observations"),
            "{hidden}"
        );
        assert!(
            !hidden.contains("No observations."),
            "the report must not deny what its own summary counts:\n{hidden}"
        );
        assert!(hidden.contains("3 observations,"), "{hidden}");

        // Collected: listed below, and said to be.
        let shown = summarised(&report_with(CveStatus::NoManifest), false);
        assert!(
            shown.contains("1 observation found \u{2014} listed below"),
            "{shown}"
        );
        assert!(shown.contains("OBSERVATIONS \u{2014}"), "{shown}");
        assert!(!shown.contains("hidden"), "{shown}");

        // None at all.
        let none = summarised(&empty_report(), false);
        assert!(none.contains("No observations."), "{none}");
        assert!(!none.contains("hidden"), "{none}");
    }

    /// The hidden count and the summary count are one number.
    #[test]
    fn the_hidden_count_is_the_summary_count() {
        for total in [1_usize, 2, 17] {
            let mut report = observations_withheld();
            report.summary.observations = total;
            let text = summarised(&report, false);
            let word = plural(total, "observation", "observations");
            assert!(
                text.contains(&format!("{word} hidden")),
                "expected {word:?} hidden in:\n{text}"
            );
            assert!(
                text.contains(&format!(", {word}, ")),
                "the summary must carry the same number:\n{text}"
            );
        }
    }

    #[test]
    fn observations_are_not_ranked_among_the_defect_layers() {
        // The observation maps to LLM06, an Impact category. It still belongs
        // in the quiet section at the bottom: it is a control the repository
        // cannot show is actually missing, not something to prioritise.
        let text = summarised(&layered_report(), false);

        let heading = position(&text, "OBSERVATIONS");
        assert!(
            heading > position(&text, "MISSING DEFENSES"),
            "got:\n{text}"
        );
        assert!(
            position(&text, "No token ceiling on LLM call") > heading,
            "got:\n{text}"
        );
    }

    #[test]
    fn defects_come_before_observations() {
        let text = summarised(&report_with(CveStatus::NoManifest), false);
        assert!(
            position(&text, "BAS-LLM10-001") < position(&text, "OBSERVATIONS"),
            "defects must render before the observations section:\n{text}"
        );
    }

    // -----------------------------------------------------------------
    // Findings
    // -----------------------------------------------------------------

    #[test]
    fn defect_sections_follow_the_attack_chain() {
        let text = summarised(&layered_report(), false);

        let entry = position(&text, "ENTRY VECTORS");
        let amplifiers = position(&text, "AMPLIFIERS");
        let impacts = position(&text, "IMPACTS");
        let cross = position(&text, "CROSS-LAYER");
        let defenses = position(&text, "MISSING DEFENSES");

        assert!(
            entry < amplifiers && amplifiers < impacts && impacts < cross && cross < defenses,
            "sections must read in causal order, entry vector first:\n{text}"
        );
    }

    /// Inside a layer, the worse finding comes first however the files sort.
    ///
    /// The old layout grouped by file inside each section, which put a
    /// `critical` in `zzz_tools.py` below a `high` in `aaa_graph.py`.
    #[test]
    fn a_critical_outranks_a_high_whatever_the_filename() {
        let text = summarised(&worse_finding_in_the_later_file(), false);

        let critical = position(&text, "BAS-LLM10-003");
        let high = position(&text, "BAS-LLM10-004");
        assert!(
            critical < high,
            "severity orders the section, not the alphabet:\n{text}"
        );
        assert!(critical < position(&text, "aaa_graph.py"), "{text}");
    }

    /// Every rule string a finding carries reaches the reader.
    ///
    /// The description used to be computed on every finding and then printed
    /// nowhere, so a rule author's explanation of *why* only ever existed in
    /// the JSON.
    #[test]
    fn a_finding_shows_its_description_and_its_fix() {
        let report = report_with(CveStatus::NoManifest);
        let text = unwrapped(&summarised(&report, false));

        let finding = &report.findings[0];
        assert!(
            text.contains(&unwrapped(&finding.description)),
            "the description must be printed, not merely computed:\n{text}"
        );
        assert!(text.contains(&unwrapped(&finding.remediation)), "{text}");
        assert!(text.contains("Fix:"), "{text}");
        assert!(
            text.contains("Confidence: high \u{b7} Categories: LLM10, ZT4"),
            "{text}"
        );
    }

    /// One category is not "Categories".
    #[test]
    fn a_single_category_is_named_in_the_singular() {
        let mut report = report_with(CveStatus::NoManifest);
        report.findings[0].categories = vec![crate::category::Category::Llm10];
        let text = summarised(&report, false);
        assert!(
            text.contains("Confidence: high \u{b7} Category: LLM10"),
            "{text}"
        );
    }

    /// An empty description leaves no hole where one would be.
    #[test]
    fn an_empty_description_prints_nothing_rather_than_a_blank_block() {
        let mut report = report_with(CveStatus::NoManifest);
        report.findings[0].description = String::new();
        let text = summarised(&report, false);

        let head = position(&text, "BAS-LLM10-001");
        let fix = position(&text, "Fix:");
        let between = &text[head..fix];
        assert!(
            !between.contains("\n\n\n"),
            "a missing description must not leave a gap that says there is more:\n{between:?}"
        );
    }

    #[test]
    fn a_finding_naming_both_a_threat_and_a_defense_is_filed_as_the_threat() {
        let text = summarised(&layered_report(), false);

        // BAS-ZT4-001 is [LLM01, ZT4]: an entry vector and the perimeter
        // defense that would have stopped it. Printing it twice would inflate
        // the counts and make the report argue with itself about what to do.
        assert_eq!(
            text.matches("BAS-ZT4-001").count(),
            1,
            "a multi-category finding must be printed exactly once:\n{text}"
        );
        let filed = position(&text, "BAS-ZT4-001");
        assert!(
            filed > position(&text, "ENTRY VECTORS") && filed < position(&text, "AMPLIFIERS"),
            "BAS-ZT4-001 belongs under entry vectors:\n{text}"
        );

        // BAS-LLM10-001 is [LLM10, ZT4]: cross-layer, and the same defense.
        assert_eq!(text.matches("BAS-LLM10-001").count(), 1);
        let cross_filed = position(&text, "BAS-LLM10-001");
        assert!(
            cross_filed > position(&text, "CROSS-LAYER")
                && cross_filed < position(&text, "MISSING DEFENSES"),
            "BAS-LLM10-001 belongs under cross-layer:\n{text}"
        );
    }

    /// A hand-written Rust check (e.g. `BAS-SKILL-001`) can leave `categories`
    /// empty rather than claiming a security category it does not have. The
    /// attribution line must not print a dangling `· Categories:` with
    /// nothing after it, and the finding must still be printed -- filed under
    /// cross-layer, the same fallback an unfiled finding of any kind gets.
    #[test]
    fn empty_categories_omits_the_label_and_falls_through_to_cross_layer() {
        let mut report = empty_report();
        let mut uncategorised = defect();
        uncategorised.rule_id = "BAS-SKILL-001".to_string();
        uncategorised.title = "SKILL.md frontmatter is not spec-valid".to_string();
        uncategorised.categories = Vec::new();
        report.findings.push(uncategorised);
        report.summary.defects = 1;

        let text = summarised(&report, false);

        assert!(
            !text.contains("Categories:") && !text.contains("Category:"),
            "an empty category list must not print a dangling label:\n{text}"
        );
        assert!(
            text.contains("Confidence: high"),
            "confidence must still be printed on its own:\n{text}"
        );
        assert!(
            text.contains("CROSS-LAYER"),
            "an uncategorised finding belongs under cross-layer:\n{text}"
        );
        assert!(text.contains("BAS-SKILL-001"), "got:\n{text}");
    }

    #[test]
    fn every_defect_is_printed_exactly_once() {
        let report = layered_report();
        let text = unwrapped(&summarised(&report, false));

        for finding in report.findings.iter().filter(|f| f.kind == Kind::Defect) {
            assert_eq!(
                text.matches(finding.title.as_str()).count(),
                1,
                "{} was not printed exactly once:\n{text}",
                finding.rule_id
            );
        }
    }

    #[test]
    fn a_section_with_nothing_in_it_is_not_printed() {
        let mut report = empty_report();
        let mut credential = defect();
        credential.rule_id = "BAS-ZT1-001".to_string();
        credential.categories = vec![crate::category::Category::Zt1];
        report.findings.push(credential);
        report.summary.defects = 1;

        let text = summarised(&report, false);

        assert!(text.contains("MISSING DEFENSES"), "got:\n{text}");
        for absent in ["ENTRY VECTORS", "AMPLIFIERS", "IMPACTS", "CROSS-LAYER"] {
            assert!(
                !text.contains(absent),
                "an empty {absent} heading must not be printed:\n{text}"
            );
        }
    }

    // -----------------------------------------------------------------
    // Coverage gaps
    // -----------------------------------------------------------------

    /// Every reason a path can leave the scan reaches the reader, and the
    /// reason is stated once per group rather than once per entry.
    #[test]
    fn every_reason_a_path_was_not_covered_reaches_the_reader() {
        let mut report = report_with(CveStatus::NoManifest);
        report.skipped = every_skip_reason();
        report.summary.files_skipped = report.skipped.len();

        let text = summarised(&report, false);
        let start = position(&text, "Coverage gaps");
        let section = &text[start..position(&text, "Scan complete:")];

        for reason in EVERY_REASON {
            let sentence = reason.sentence(if reason == crate::report::SkipReason::Excluded {
                2
            } else {
                1
            });
            assert!(
                unwrapped(section).contains(&unwrapped(&sentence)),
                "{reason:?} did not reach the listing:\n{section}"
            );
        }

        for skip in &report.skipped {
            assert!(
                section.contains(&skip.path),
                "{} is missing from:\n{section}",
                skip.path
            );
        }

        // Stated once for the group, not once per entry.
        assert_eq!(
            section.matches("could not be matched to CVEs").count(),
            1,
            "the reason belongs to the group, not to each line:\n{section}"
        );
    }

    /// A pattern that repeats the path it removed adds nothing, and is not
    /// printed twice.
    #[test]
    fn a_pattern_that_merely_names_its_own_path_is_not_echoed() {
        let mut report = report_with(CveStatus::NoManifest);
        report.skipped = vec![crate::report::Skip::excluded(
            "vendor/".to_owned(),
            "vendor/",
        )];
        let text = summarised(&report, false);
        assert_eq!(text.matches("vendor/").count(), 1, "{text}");

        // A pattern that says something the path does not is still shown.
        report.skipped = vec![crate::report::Skip::excluded(
            "web/app.min.js".to_owned(),
            "*.min.js",
        )];
        let text = summarised(&report, false);
        assert!(text.contains("web/app.min.js"), "{text}");
        assert!(text.contains("*.min.js"), "{text}");
    }

    /// The CVE line is printed for every outcome, including the ones with
    /// nothing to report: "no CVEs listed" must never read as "no CVEs".
    #[test]
    fn cve_status_is_visible_for_every_variant() {
        let checked = summarised(&report_with(CveStatus::Checked { dependencies: 5 }), false);
        assert!(
            checked.contains("5 dependencies were checked against the OSV vulnerability database."),
            "{checked}"
        );

        let one = summarised(&report_with(CveStatus::Checked { dependencies: 1 }), false);
        assert!(one.contains("1 dependency was checked"), "{one}");

        let no_manifest = summarised(&report_with(CveStatus::NoManifest), false);
        assert!(
            no_manifest.contains("CVEs were not checked because no dependency manifest was found."),
            "{no_manifest}"
        );

        let offline = summarised(&report_with(CveStatus::SkippedOffline), false);
        assert!(
            offline.contains("CVEs were not checked because the scan ran in offline mode."),
            "SkippedOffline must be visible, got: {offline}"
        );

        let unreachable = summarised(
            &report_with(CveStatus::Unreachable {
                reason: "no network connection".to_string(),
            }),
            false,
        );
        assert!(
            unreachable.contains("CVEs were not checked: no network connection."),
            "Unreachable must be visible, got: {unreachable}"
        );

        let partial = summarised(
            &report_with(CveStatus::Partial {
                dependencies: 9,
                incomplete: 2,
            }),
            false,
        );
        assert!(
            partial.contains("may be incomplete"),
            "Partial must be visible, got: {partial}"
        );
    }

    /// A scan that skipped nothing still gets the section, because the CVE
    /// status lives in it.
    #[test]
    fn the_coverage_section_is_printed_even_when_nothing_was_skipped() {
        let text = summarised(&empty_report(), false);
        assert!(text.contains("Coverage gaps"), "{text}");
        assert!(
            text.contains("Every file the scan reached was analysed."),
            "{text}"
        );
        assert!(text.contains("CVEs were not checked"), "{text}");
    }

    // -----------------------------------------------------------------
    // Files read
    // -----------------------------------------------------------------

    /// A report that read two skill files and one MCP config.
    fn report_that_read_files() -> Report {
        let mut report = empty_report();
        report.coverage.skill_files = vec![
            "skills/a/SKILL.md".to_string(),
            "skills/b/SKILL.md".to_string(),
        ];
        report.coverage.mcp_manifests = vec![".mcp.json".to_string()];
        report
    }

    fn listing(report: &Report, color: bool, glyphs: Glyphs) -> String {
        render(
            report,
            StdoutOptions {
                show_coverage: true,
                glyphs,
                ..options(color)
            },
        )
        .text
    }

    #[test]
    fn the_default_report_counts_files_read_and_lists_none() {
        let text = summarised(&report_that_read_files(), false);
        assert!(text.contains("Files read\n"), "{text}");
        assert!(
            unwrapped(&text).contains(
                "2 skill files, 0 skill references, 1 MCP config, 0 instruction files read."
            ),
            "{text}"
        );
        assert!(!text.contains("skills/a/SKILL.md"), "{text}");
        assert!(!text.contains(".mcp.json"), "{text}");
    }

    #[test]
    fn show_coverage_lists_every_path_in_order_under_its_label() {
        let mut report = report_that_read_files();
        report.coverage.skill_unanalysed = vec!["skills/a/run.sh".to_string()];
        let text = listing(&report, false, Glyphs::Unicode);

        let skills = position(
            &text,
            "Skill files:\n  skills/a/SKILL.md\n  skills/b/SKILL.md\n",
        );
        let mcp = position(&text, "MCP configs:\n  .mcp.json\n");
        let unread = position(&text, "Skill files no analyser reads:\n  skills/a/run.sh\n");
        assert!(skills < mcp && mcp < unread, "{text}");
        assert!(!text.contains("Skill reference files:"), "{text}");
        assert!(!text.contains("Instruction files:"), "{text}");
    }

    #[test]
    fn a_single_file_of_a_kind_is_counted_in_the_singular() {
        let mut report = empty_report();
        report.coverage.skill_files = vec!["SKILL.md".to_string()];
        report.coverage.skill_reference_files = vec!["references/a.md".to_string()];
        report.coverage.mcp_manifests = vec![".mcp.json".to_string()];
        report.coverage.instruction_files = vec!["AGENTS.md".to_string()];
        let text = unwrapped(&summarised(&report, false));
        assert!(
            text.contains(
                "1 skill file, 1 skill reference, 1 MCP config, 1 instruction file read."
            ),
            "{text}"
        );
    }

    #[test]
    fn files_read_comes_before_the_coverage_gaps() {
        let text = summarised(&report_that_read_files(), false);
        assert!(position(&text, "Files read") < position(&text, "Coverage gaps"));
    }

    #[test]
    fn the_files_read_section_leaves_no_escape_or_unicode_behind() {
        let report = report_that_read_files();
        let plain = listing(&report, false, Glyphs::Unicode);
        assert!(!plain.contains('\u{1b}'), "{plain}");
        let ascii = listing(&report, false, Glyphs::Ascii);
        assert!(ascii.is_ascii(), "{ascii}");
    }

    #[test]
    fn the_files_read_count_line_stays_inside_the_wrap_width() {
        let mut report = empty_report();
        let many = |n: usize| vec!["f".to_string(); n];
        report.coverage.skill_files = many(123_456);
        report.coverage.skill_reference_files = many(234_567);
        report.coverage.mcp_manifests = many(345_678);
        report.coverage.instruction_files = many(456_789);
        let text = summarised(&report, false);
        let start = position(&text, "Files read");
        let end = position(&text, "Coverage gaps");
        for line in text[start..end].lines() {
            assert!(line.chars().count() <= 78, "{line:?}");
        }
        assert!(
            unwrapped(&text).contains("123456 skill files, 234567 skill references"),
            "{text}"
        );
    }

    // -----------------------------------------------------------------
    // Compliance crosswalk
    // -----------------------------------------------------------------

    /// A report that carries no crosswalk prints none.
    ///
    /// The CLI always computes them now, so this is the renderer's own
    /// contract rather than the command line's: nothing invents a framework
    /// heading for a report that has no framework data behind it.
    #[test]
    fn a_report_without_a_crosswalk_prints_no_crosswalk() {
        for text in [
            summarised(&layered_report(), false),
            detailed(&layered_report(), false),
        ] {
            assert!(!text.contains("Compliance crosswalk"));
            assert!(!text.contains("EU AI Act"));
        }
    }

    /// The caveat comes before any framework name, in both forms, and once.
    ///
    /// A reader who stops at the first heading must already have been told
    /// what the whole section does not mean. A caveat repeated before every
    /// block is one a reader learns to skip.
    #[test]
    fn the_crosswalk_states_what_it_is_not_before_it_states_anything_else() {
        for text in [
            detailed(&grouped(Framework::EuAiAct), false),
            summarised(&grouped_by_all(), false),
        ] {
            let flat = unwrapped(&text);
            assert!(
                flat.contains(&unwrapped(CROSSWALK_INTRO)),
                "the opening caveat must be printed in full:\n{text}"
            );
            assert!(
                flat.contains(&unwrapped(TERMINAL_CAVEAT)),
                "the closing caveat must be printed in full:\n{text}"
            );
            assert!(
                flat.contains("Finding nothing does not mean an obligation is met."),
                "an empty table must not read as a clean bill of health:\n{text}"
            );
            assert_eq!(
                flat.matches("Not a compliance assessment.").count(),
                1,
                "one caveat for the section, not one per framework:\n{text}"
            );

            let caveat = position(&text, "Not a compliance assessment");
            assert!(caveat < position(&text, "EU AI Act"), "{text}");
        }

        let summary = summarised(&grouped_by_all(), false);
        for framework in Framework::ALL {
            assert!(
                position(&summary, "Not a compliance assessment")
                    < position(&summary, framework.name()),
                "{} is named before the caveat:\n{summary}",
                framework.name()
            );
        }
    }

    /// The wording constraint, enforced on the bytes a user actually sees.
    ///
    /// The mapping's own strings are checked in `compliance`; this checks the
    /// renderer's prose too, because a heading is just as capable of promising
    /// a verdict as the data under it.
    ///
    /// Scoped to the crosswalk section: "Coverage gaps" is a legitimate
    /// heading elsewhere in the report, and `gap` is on the list.
    #[test]
    fn the_rendered_crosswalk_never_claims_compliance() {
        let mut rendered: Vec<String> = Framework::ALL
            .iter()
            .map(|framework| detailed(&grouped(*framework), false))
            .collect();
        // Every string the summary form adds — its section heading, its
        // framework headings, its truncated titles and its footnotes — goes
        // through the same filter. The summary is the form most readers will
        // ever see.
        rendered.push(summarised(&grouped_by_all(), false));
        rendered.push(summarised(&empty_grouped_by_all(), false));

        for text in &rendered {
            let section = unwrapped(&crosswalk_section(text));
            let lowered = section.to_lowercase();
            for word in FORBIDDEN_CLAIMS {
                assert!(
                    !lowered.contains(word),
                    "{word:?} reached the crosswalk:\n{section}"
                );
            }

            // The weaker words are held against Bastyn's own prose only. NIST
            // AI 100-1's MAP 3.5 reads "defined, assessed, and documented";
            // rewriting a citation to satisfy a word list would be the worse
            // failure by a distance.
            let authored = without_transcriptions(&section).to_lowercase();
            assert!(
                authored.contains("compliance crosswalk"),
                "the filter stripped the section it was meant to check:\n{authored}"
            );
            for word in FORBIDDEN_CHARACTERISATIONS {
                assert!(
                    !authored.contains(word),
                    "{word:?} reached the crosswalk's own prose:\n{authored}"
                );
            }
        }
    }

    /// `text` with every transcribed control heading removed, including the
    /// word-boundary prefixes and clause cuts the compact form reduces them
    /// to.
    ///
    /// What is left is exactly the prose Bastyn wrote, which is what
    /// [`FORBIDDEN_CHARACTERISATIONS`] is about.
    fn without_transcriptions(text: &str) -> String {
        let mut text = text.to_owned();
        for framework in Framework::ALL {
            for control in framework.controls() {
                let words: Vec<&str> = control.title.split_whitespace().collect();
                // Longest first, so a prefix never eats the cut that a longer
                // one would have matched. Each prefix twice: as written, and
                // with the clause punctuation the cut strips before adding its
                // ellipsis.
                for take in (1..=words.len()).rev() {
                    let cut = words[..take].join(" ");
                    let trimmed = cut.trim_end_matches([',', ';', ':']).to_owned();
                    text = text.replace(&cut, " ");
                    text = text.replace(&trimmed, " ");
                }
            }
        }
        text
    }

    /// Groups print in the framework's own order, not in whatever order the
    /// findings happened to arrive.
    #[test]
    fn groups_print_in_the_frameworks_canonical_order() {
        for text in [
            detailed(&grouped(Framework::NistAiRmf), false),
            summarised(&grouped_by_all(), false),
        ] {
            let map = position(&text, "MAP 3.5");
            let map4 = position(&text, "MAP 4.1");
            let measure = position(&text, "MEASURE 2.7");
            assert!(
                map < map4 && map4 < measure,
                "MAP before MEASURE, as AI RMF orders them:\n{text}"
            );
        }
    }

    /// Each framework names the document its identifiers come from, and each
    /// group names its identifier: an identifier a reader cannot check is not
    /// a citation.
    ///
    /// The terminal names the document by its identifier — the half a reader
    /// can look up. The full reference travels in JSON and SARIF, which
    /// `render::json` pins.
    #[test]
    fn every_framework_names_the_document_it_read() {
        for text in [
            summarised(&grouped_by_all(), false),
            detailed(&grouped(Framework::EuAiAct), false),
        ] {
            for framework in Framework::ALL {
                if !text.contains(framework.name()) {
                    continue;
                }
                assert!(
                    text.contains(framework.document_id()),
                    "{} lost the document it read:\n{text}",
                    framework.name()
                );
            }
        }

        let text = detailed(&grouped(Framework::EuAiAct), false);
        assert!(text.contains("Art. 15"));
        assert!(text.contains("Accuracy, robustness and cybersecurity"));
        assert!(text.contains("Art. 14"));
        assert!(text.contains("Human oversight"));
    }

    /// No framework heading wraps.
    ///
    /// It used to: five of the six heading lines in a three-framework table
    /// carried a hanging continuation, and a reader met two lines of document
    /// title before the first count. The identifier alone fits, and this is
    /// what keeps it fitting if a framework is added or renamed.
    #[test]
    fn a_framework_heading_never_wraps() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            for crosswalks in [CrosswalkDetail::Summary, CrosswalkDetail::Detailed] {
                let text = render(
                    &grouped_by_all(),
                    StdoutOptions {
                        glyphs,
                        crosswalks,
                        ..options(false)
                    },
                )
                .text;
                let lines: Vec<&str> = text.lines().collect();

                for framework in Framework::ALL {
                    let at = lines
                        .iter()
                        .position(|line| line.starts_with(framework.name()))
                        .unwrap_or_else(|| {
                            unreachable!("no heading for {}:\n{text}", framework.name())
                        });
                    assert!(
                        lines[at].contains(framework.document_id()),
                        "{glyphs:?}/{crosswalks:?}: the whole heading must fit on its own \
line: {:?}",
                        lines[at]
                    );
                    // A continuation would be indented past the area lines,
                    // which sit at two.
                    let next = lines.get(at + 1).copied().unwrap_or_default();
                    let indent = next.len() - next.trim_start().len();
                    assert!(
                        indent <= 2,
                        "{glyphs:?}/{crosswalks:?}: {:?} wrapped into {next:?}",
                        lines[at]
                    );
                }
            }
        }
    }

    /// The counts in the table are defects and observations, never "findings".
    ///
    /// This table is the most likely thing in the report to be quoted out of
    /// context, and the split is the whole reason an observation cannot fail
    /// a build.
    #[test]
    fn the_table_counts_defects_not_findings() {
        let text = summarised(&grouped_by_all(), false);
        let section = crosswalk_section(&text);

        assert!(section.contains("8 defects, 1 observation"), "{section}");
        for count in 0..20_usize {
            assert!(
                !section.contains(&format!("{count} finding")),
                "the table must never total the two kinds together:\n{section}"
            );
        }
    }

    /// The EU AI Act's application dates are on screen, because a reader
    /// planning against the wrong deadline is the expensive mistake here.
    #[test]
    fn the_eu_grouping_says_when_the_articles_actually_apply() {
        for text in [
            detailed(&grouped(Framework::EuAiAct), false),
            summarised(&grouped_by_all(), false),
        ] {
            let flat = unwrapped(&text);
            assert!(flat.contains("2 December 2027"), "{text}");
            assert!(flat.contains("2 August 2028"), "{text}");
            assert!(flat.contains("high-risk"), "{text}");
            assert!(flat.contains("2026/1744"), "{text}");

            // Reached by a footnote marker on the EU heading, not left for a
            // reader to find: the dates are the most consequential fact here.
            let heading = text
                .lines()
                .find(|line| line.starts_with("EU AI Act"))
                .unwrap_or_else(|| unreachable!("no EU heading in:\n{text}"));
            let marker = Glyphs::Unicode.marker(0);
            assert!(heading.contains(&marker), "{heading:?}");
            assert!(
                position(&text, &format!("\n{marker} ")) > position(&text, "EU AI Act"),
                "the footnote must follow the heading that points at it:\n{text}"
            );
        }
    }

    /// NIST is voluntary guidance and the report says so, so a group heading
    /// is never read as a legal duty.
    ///
    /// Both NIST documents say it in identical words, so they share one
    /// footnote rather than printing the paragraph twice — but both headings
    /// have to carry the marker that reaches it.
    #[test]
    fn the_nist_groupings_say_they_are_voluntary() {
        for framework in [Framework::NistAiRmf, Framework::NistGenAi] {
            let text = unwrapped(&detailed(&grouped(framework), false));
            assert!(
                text.contains("Voluntary guidance, not a regulation"),
                "{} must not read as a legal duty",
                framework.name()
            );
        }

        let text = summarised(&grouped_by_all(), false);
        let voluntary = position(&text, "Voluntary guidance, not a regulation");
        let marker = text[..voluntary]
            .lines()
            .next_back()
            .map(|line| {
                line.split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .unwrap_or_default();
        assert!(
            !marker.is_empty(),
            "the footnote must have a marker:\n{text}"
        );

        for framework in [Framework::NistAiRmf, Framework::NistGenAi] {
            let heading = text
                .lines()
                .find(|line| line.starts_with(framework.name()))
                .unwrap_or_else(|| unreachable!("no heading for {}", framework.name()));
            assert!(
                heading.contains(&marker),
                "{} must point at the voluntary-guidance footnote: {heading:?}",
                framework.name()
            );
        }
    }

    /// A finding no article covers is shown, not quietly dropped.
    ///
    /// `layered_report`'s observation is `LLM06`, which has no EU AI Act
    /// mapping. Silently omitting it would make the compliance view claim a
    /// completeness it does not have.
    #[test]
    fn findings_the_framework_does_not_reach_are_still_listed() {
        let text = detailed(&grouped(Framework::EuAiAct), false);
        let unmapped = position(&text, "not covered by this framework");
        assert!(
            unmapped > position(&text, "Compliance crosswalk"),
            "the unmapped section is part of the crosswalk:\n{text}"
        );
        assert!(
            text[unmapped..].contains("BAS-LLM06-001"),
            "the unmapped observation must be named:\n{text}"
        );

        // Under NIST it does map, so nothing is unmapped there.
        let nist = detailed(&grouped(Framework::NistAiRmf), false);
        assert!(!nist.contains("not covered by this framework"));

        // The summary carries the same line, with counts and no findings.
        let summary = summarised(&grouped_by_all(), false);
        assert_eq!(
            summary.matches("not covered by this framework").count(),
            1,
            "only the EU block has an unmapped finding:\n{summary}"
        );
    }

    /// The compact form names no individual finding; the expanded one does.
    #[test]
    fn only_the_expanded_form_lists_findings_under_an_area() {
        let summary = crosswalk_section(&summarised(&grouped_by_all(), false));
        assert!(
            !summary.contains("BAS-"),
            "the default form is a table, not a second listing:\n{summary}"
        );

        let expanded = crosswalk_section(&detailed(&grouped(Framework::EuAiAct), false));
        assert!(expanded.contains("BAS-"), "{expanded}");
    }

    /// The crosswalk regroups; it never changes the report it groups.
    ///
    /// Everything above it — the checklist, the verdict, the layered listing,
    /// the coverage gaps — must read exactly as it did before, so a reader who
    /// was using the default view loses nothing by asking for a framework as
    /// well.
    #[test]
    fn the_crosswalk_is_added_below_an_otherwise_unchanged_report() {
        let plain = summarised(&base(), false);
        let head = plain.split("Scan complete:").next().unwrap();

        for text in [
            detailed(&grouped(Framework::EuAiAct), false),
            summarised(&grouped_by_all(), false),
        ] {
            assert!(
                text.starts_with(head),
                "everything above the crosswalk must be untouched:\n{text}"
            );
            assert!(position(&text, "Compliance crosswalk") < position(&text, "Scan complete:"));
            assert!(text.ends_with(&format!(
                "Scan complete:{}",
                plain.split("Scan complete:").nth(1).unwrap()
            )));
        }
    }

    /// A report with a crosswalk and nothing to say still says it, so an empty
    /// section is never mistaken for a section that was not asked for.
    #[test]
    fn a_crosswalk_over_an_empty_report_still_prints_its_caveat() {
        let mut report = empty_report();
        report.crosswalks = vec![crosswalk(&report, Framework::EuAiAct)];
        let text = detailed(&report, false);

        assert!(text.contains("Compliance crosswalk"));
        assert!(unwrapped(&text).contains(&unwrapped(TERMINAL_CAVEAT)));
        assert!(
            text.contains("no findings"),
            "an empty crosswalk must say it is empty, not look like a clean bill:\n{text}"
        );
    }

    // -----------------------------------------------------------------
    // Layout contracts
    // -----------------------------------------------------------------

    /// No line of the report runs off an eighty-column terminal.
    ///
    /// Checked on a fixture built to break it: a deep path, a title longer
    /// than the wrap, two paragraphs of prose, an unbreakable identifier
    /// wider than the line, and every skip reason.
    #[test]
    fn nothing_runs_off_an_eighty_column_terminal() {
        let mut report = verbose_report();
        report.crosswalks = Framework::ALL
            .iter()
            .map(|framework| crosswalk(&report, *framework))
            .collect();

        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            for crosswalks in [CrosswalkDetail::Summary, CrosswalkDetail::Detailed] {
                let text = render(
                    &report,
                    StdoutOptions {
                        glyphs,
                        crosswalks,
                        ..options(false)
                    },
                )
                .text;
                for line in text.lines() {
                    assert!(
                        line.chars().count() <= 80,
                        "{} characters with {glyphs:?}/{crosswalks:?}: {line:?}",
                        line.chars().count()
                    );
                }
            }
        }
    }

    /// No area title ends mid-clause, and the counts it makes room for are
    /// never the thing that gets cut.
    ///
    /// `AI system security and resilience – as identified…` and `Lowered
    /// barriers for offensive cyber…` both stopped inside a clause. A
    /// subcategory written as "heading – elaboration" is cut at the dash; a
    /// title with no separator is cut only where the source itself ended a
    /// clause, and dropped when there is no such place, because the
    /// identifier and the count are what the line is for.
    #[test]
    fn no_area_title_ends_mid_clause() {
        let text = summarised(&grouped_by_all(), false);
        let section = crosswalk_section(&text);

        // The longest definition in the mapping, so the rule is exercised
        // rather than merely available.
        let long = "Lowered barriers for offensive cyber capabilities, including via automated \
discovery and exploitation of vulnerabilities";
        assert!(
            !section.contains(long),
            "a paragraph-length definition reached the summary whole:\n{section}"
        );
        assert!(section.contains("8 defects, 1 observation"), "{section}");

        // Every cut in the section landed where the source itself ended a
        // clause.
        let ellipsis = Glyphs::Unicode.ellipsis();
        let titles: Vec<&str> = Framework::ALL
            .iter()
            .flat_map(|framework| framework.controls())
            .map(|control| control.title)
            .collect();
        let mut cuts = 0;

        for line in section.lines() {
            if !line.contains(ellipsis) {
                continue;
            }
            let kept = line
                .split_once(" \u{2014} ")
                .and_then(|(_, rest)| rest.split(ellipsis).next())
                .unwrap_or_else(|| unreachable!("{line:?} has no title before its cut"));
            cuts += 1;

            let source = titles
                .iter()
                .find(|title| title.starts_with(kept))
                .unwrap_or_else(|| unreachable!("{kept:?} is no title's prefix:\n{section}"));
            let after = &source[kept.len()..];
            assert!(
                after.starts_with([',', ';', ':']),
                "{kept:?} stops inside a clause \u{2014} the source continues {after:?}"
            );
        }
        assert!(
            cuts > 0,
            "no title was cut, so nothing was checked:\n{section}"
        );

        // A subcategory written as "heading \u{2013} elaboration" keeps its
        // whole heading and drops the elaboration, with no ellipsis at all.
        assert!(
            section.contains("MEASURE 2.7 \u{2014} AI system security and resilience  "),
            "a dash-separated heading must survive whole:\n{section}"
        );
        assert!(
            !section.contains("resilience \u{2013}"),
            "and must not drag its elaboration in with it:\n{section}"
        );
    }

    /// The three rules, driven directly.
    #[test]
    fn an_area_title_is_cut_at_the_separator_the_source_wrote() {
        let dashed = "AI system security and resilience \u{2013} as identified in the MAP \
function \u{2013} are evaluated and documented.";

        // Cut at the dash, whole, and with no ellipsis: this is the
        // subcategory's own name.
        assert_eq!(
            area_title(dashed, 40, Glyphs::Unicode).as_deref(),
            Some("AI system security and resilience")
        );
        // Too narrow even for the heading, and the heading has no comma in it.
        assert_eq!(area_title(dashed, 20, Glyphs::Unicode), None);

        // No separator: kept whole when it fits.
        assert_eq!(
            area_title("Human oversight", 40, Glyphs::Unicode).as_deref(),
            Some("Human oversight")
        );
        assert_eq!(
            area_title(
                "Accuracy, robustness and cybersecurity",
                40,
                Glyphs::Unicode
            )
            .as_deref(),
            Some("Accuracy, robustness and cybersecurity")
        );

        // No separator and too long: cut only where the author put a comma.
        let genai = "Lowered barriers for offensive cyber capabilities, including via automated \
discovery and exploitation of vulnerabilities.";
        assert_eq!(
            area_title(genai, 50, Glyphs::Unicode).as_deref(),
            Some("Lowered barriers for offensive cyber capabilities\u{2026}")
        );
        // The ASCII marker costs two columns more, so it drops the title two
        // columns sooner rather than overflowing the line it was cut to fit.
        assert_eq!(area_title(genai, 51, Glyphs::Ascii), None);
        assert_eq!(
            area_title(genai, 52, Glyphs::Ascii).as_deref(),
            Some("Lowered barriers for offensive cyber capabilities...")
        );
        // Narrower than the first clause: nothing rather than a fragment.
        assert_eq!(area_title(genai, 40, Glyphs::Unicode), None);
        assert_eq!(
            area_title(
                "One long unbroken clause with no punctuation at all",
                20,
                Glyphs::Unicode
            ),
            None
        );
    }

    /// Cutting happens between words, and says that it happened.
    #[test]
    fn a_cut_title_breaks_between_words_and_is_marked() {
        assert_eq!(
            ellipsise("Human oversight", 40, Glyphs::Unicode),
            "Human oversight"
        );
        assert_eq!(
            ellipsise("Human oversight", 15, Glyphs::Unicode),
            "Human oversight"
        );
        assert_eq!(
            ellipsise("Record-keeping and more", 15, Glyphs::Unicode),
            "Record-keeping\u{2026}"
        );

        // A first word wider than the budget is cut mid-word rather than
        // dropped: an empty line says less than a truncated one.
        assert_eq!(
            ellipsise("Extraordinarily", 6, Glyphs::Unicode),
            "Extra\u{2026}"
        );
        assert_eq!(ellipsise("Extraordinarily", 6, Glyphs::Ascii), "Ext...");
    }

    #[test]
    fn no_color_emits_no_escape_byte() {
        let mut report = verbose_report();
        report.crosswalks = Framework::ALL
            .iter()
            .map(|framework| crosswalk(&report, *framework))
            .collect();

        for crosswalks in [CrosswalkDetail::Summary, CrosswalkDetail::Detailed] {
            let text = render(
                &report,
                StdoutOptions {
                    crosswalks,
                    ..options(false)
                },
            )
            .text;
            assert!(
                !text.contains('\u{1b}'),
                "expected no ANSI escape bytes, got: {text}"
            );
        }
        assert!(!summarised(&empty_grouped_by_all(), false).contains('\u{1b}'));
    }

    #[test]
    fn color_true_does_emit_escapes() {
        assert!(
            summarised(&report_with(CveStatus::Checked { dependencies: 3 }), true)
                .contains('\u{1b}'),
            "expected ANSI escape bytes when color is on"
        );
    }

    /// A terminal that cannot be trusted with Unicode gets none of the
    /// renderer's own.
    #[test]
    fn ascii_glyphs_leave_no_unicode_behind() {
        let mut report = verbose_report();
        report.crosswalks = Framework::ALL
            .iter()
            .map(|framework| crosswalk(&report, *framework))
            .collect();

        for crosswalks in [CrosswalkDetail::Summary, CrosswalkDetail::Detailed] {
            let text = render(
                &report,
                StdoutOptions {
                    glyphs: Glyphs::Ascii,
                    crosswalks,
                    ..options(false)
                },
            )
            .text;
            assert!(
                text.is_ascii(),
                "a non-ASCII byte survived the fallback:\n{:?}",
                text.chars().filter(|c| !c.is_ascii()).collect::<String>()
            );
        }
    }

    /// The Unicode form does use the glyphs the fallback replaces, so the
    /// test above is measuring something.
    #[test]
    fn the_unicode_form_actually_uses_the_glyphs() {
        let text = summarised(&grouped_by_all(), false);
        for glyph in [
            Glyphs::Unicode.tick(),
            Glyphs::Unicode.rule(),
            Glyphs::Unicode.dash(),
            Glyphs::Unicode.middot(),
            &Glyphs::Unicode.marker(0),
        ] {
            assert!(text.contains(glyph), "{glyph:?} is missing from:\n{text}");
        }
        assert!(
            summarised(&report_with(CveStatus::SkippedOffline), false)
                .contains(Glyphs::Unicode.circle())
        );
    }

    /// Two footnotes never share a marker, however many there are.
    #[test]
    fn footnote_markers_stay_distinct() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            let markers: Vec<String> = (0..9).map(|index| glyphs.marker(index)).collect();
            let mut unique = markers.clone();
            unique.sort();
            unique.dedup();
            assert_eq!(unique.len(), markers.len(), "{glyphs:?}: {markers:?}");
        }
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------

    /// The summary is handed back, not left for the caller to find by
    /// position — `--quiet` used to take the last line of the report, which
    /// stopped being the summary the moment anything printed below it.
    #[test]
    fn the_summary_is_returned_and_is_not_the_last_line() {
        let rendered = render(&layered_report(), options(false));

        assert_eq!(
            rendered.summary,
            "Scan complete: 7 defects, 1 observation, 0 coverage gaps"
        );
        assert!(rendered.text.contains(&rendered.summary));
        assert_ne!(
            rendered.text.lines().next_back(),
            Some(rendered.summary.as_str()),
            "the summary is no longer last, which is why it is returned"
        );
        assert_eq!(rendered.text.lines().next_back(), Some("Exit status: 1"));
    }

    #[test]
    fn counts_are_pluralised() {
        assert_eq!(plural(0, "file", "files"), "0 files");
        assert_eq!(plural(1, "file", "files"), "1 file");
        assert_eq!(plural(2, "file", "files"), "2 files");
        assert_eq!(
            plural(1, "dependency", "dependencies"),
            "1 dependency",
            "an irregular plural must use the explicit form"
        );
    }

    #[test]
    fn empty_report_renders_cleanly() {
        let text = summarised(&empty_report(), false);
        assert!(text.contains("No defects found."));
        assert!(text.contains("No observations."));
        assert!(text.contains("Scan complete: 0 defects, 0 observations, 0 coverage gaps"));
        assert!(!text.contains('\u{1b}'));
    }

    /// A severity the fixture does not carry never appears in the breakdown.
    #[test]
    fn the_severity_breakdown_names_only_what_is_there() {
        let mut report = empty_report();
        let mut low = defect();
        low.severity = Severity::Low;
        report.findings.push(low);
        report.summary.defects = 1;

        let text = summarised(&report, false);
        assert!(text.contains("1 defect found: 1 low"), "{text}");
        assert!(!text.contains("0 critical"), "{text}");
    }
}
