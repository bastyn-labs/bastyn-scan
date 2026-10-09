//! The scan pipeline: walk, analyse, merge, partition, sort.
//!
//! One function ties the analysers together and produces the single [`Report`]
//! every output format renders from. Most of the ordering here exists to keep
//! default output believable rather than merely complete.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use crate::cve::{self, Dependency, UnresolvedDependency};
use crate::dotenv;
use crate::error::{Error, Result};
use crate::finding::{Finding, Kind};
use crate::generated;
use crate::infra;
use crate::instructions;
use crate::mcp;
use crate::observe::{Observer, Phase, Silent};
use crate::report::{Coverage, CoveredSkip, CveStatus, Report, Skip, Summary};
use crate::rules::{RuleSet, ScanOutcome, SourceLanguage, scan_source_checked};
use crate::skill;
use crate::walk::{WalkOptions, collect_files};

/// How a scan should behave.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// How the tree is traversed.
    pub walk: WalkOptions,
    /// Skip the CVE lookup, the only step that uses the network.
    pub offline: bool,
    /// Include context-dependent observations alongside defects.
    ///
    /// Off by default. A missing control is not a bug when the repository
    /// cannot show that its absence is wrong, and putting those in front of a
    /// developer by default is what makes a scanner get uninstalled.
    pub include_observations: bool,
}

/// Scan `root` and produce a report.
///
/// # Errors
///
/// Returns an error only if the root itself cannot be traversed, or the
/// embedded rules fail to load. A single unreadable or unparseable file is
/// recorded in [`Report::skipped`], never fatal and never silently dropped — a
/// scan that quietly covered less than it claimed is worse than one that
/// failed.
pub fn scan(root: &Path, options: &ScanOptions) -> Result<Report> {
    scan_observed(root, options, &Silent)
}

/// Scan `root`, reporting progress to `observer`.
///
/// Behaviour is identical to [`scan`] — the observer only watches.
///
/// # Errors
///
/// As [`scan`].
pub fn scan_observed(
    root: &Path,
    options: &ScanOptions,
    observer: &dyn Observer,
) -> Result<Report> {
    let walking = Phase::Walking;
    observer.phase_started(&walking);
    let walked = collect_files(root, &options.walk)?;
    let files = walked.files;
    let ruleset = RuleSet::embedded().map_err(|source| Error::Rules {
        source: Box::new(source),
    })?;
    observer.phase_finished(&walking);

    let work = Workload::from(files.as_slice());
    let analysing = Phase::Analysing {
        files: work.readable,
        rules: ruleset.len(),
        mcp_configs: work.mcp_configs,
    };
    observer.phase_started(&analysing);

    let mut analysis = Analysis::default();
    // What the traversal deliberately left out joins what the analysis could
    // not cover, in the same list, before either is counted. An exclusion the
    // report does not mention is a hiding place.
    analysis.skipped.extend(walked.skipped);
    analyse(root, &files, &ruleset, observer, &mut analysis);

    // Structural, not a lookup: no network involved, so this runs
    // unconditionally, including under `--offline`.
    for finding in cve::check_wildcard_framework_dependencies(&analysis.unresolved_dependencies) {
        observer.found(&finding);
        analysis.findings.push(finding);
    }

    observer.phase_finished(&analysing);

    let checking = Phase::Cve {
        dependencies: analysis.dependencies.len(),
    };
    observer.phase_started(&checking);
    let (cve_findings, cve_status) = if analysis.dependencies.is_empty() && !options.offline {
        (Vec::new(), CveStatus::NoManifest)
    } else {
        cve::check(&analysis.dependencies, options.offline)
    };
    for finding in cve_findings {
        observer.found(&finding);
        analysis.findings.push(finding);
    }
    observer.phase_finished(&checking);

    let reporting = Phase::Reporting;
    observer.phase_started(&reporting);

    let mut findings = analysis.findings;
    dedupe(&mut findings);

    let defects = findings.iter().filter(|f| f.kind == Kind::Defect).count();
    let observations = findings.len() - defects;

    if !options.include_observations {
        findings.retain(|finding| finding.kind == Kind::Defect);
    }

    sort_findings(&mut findings);
    observer.phase_finished(&reporting);

    Ok(Report {
        bastyn_version: crate::VERSION.to_owned(),
        root: root.display().to_string(),
        summary: Summary {
            files_scanned: analysis.scanned,
            files_skipped: analysis.skipped.len(),
            defects,
            observations,
        },
        cve: cve_status,
        findings,
        coverage: Coverage {
            skipped: analysis.skipped.iter().map(CoveredSkip::from).collect(),
            ..analysis.coverage
        },
        skipped: analysis.skipped.into_iter().collect(),
        // Grouping is a presentation choice the caller makes, not a fact the
        // scan discovers, so the engine never fills this in. A caller that
        // wants a crosswalk calls `compliance::crosswalk` on the finished
        // report, once per framework it wants grouped.
        crosswalks: Vec::new(),
    })
}

/// How much work the analysis pass has, counted before it runs so the phase can
/// announce a total rather than a running tally.
#[derive(Debug, Default)]
struct Workload {
    /// Files at least one analyser will open.
    readable: usize,
    mcp_configs: usize,
}

impl From<&[PathBuf]> for Workload {
    fn from(files: &[PathBuf]) -> Self {
        let mut work = Self::default();
        for relative in files {
            if is_analysed(relative) {
                work.readable += 1;
            }
            if mcp::is_mcp_config(relative) {
                work.mcp_configs += 1;
            }
        }
        work
    }
}

/// Whether any analyser will open this file.
///
/// Decided from the path alone, so it can be asked before a scan starts —
/// [`Workload`] uses it to announce a total, and [`biggest_first`] uses it to
/// avoid a `stat` on a file nothing is going to read.
fn is_analysed(relative: &Path) -> bool {
    SourceLanguage::from_path(relative).is_some()
        || mcp::is_mcp_config(relative)
        || cve::is_manifest(relative)
        || infra::is_infra_file(relative)
        || instructions::is_instruction_file(relative)
        || skill::is_skill_file(relative)
        || dotenv::is_env_file(relative)
}

/// What one pass over the tree produced.
#[derive(Debug, Default)]
struct Analysis {
    findings: Vec<Finding>,
    dependencies: Vec<Dependency>,
    /// Dependencies pinned to a range rather than an exact version. Not
    /// queried against OSV — see [`collect_dependencies`] — but still
    /// structurally checkable: `BAS-LLM04-001` reads the constraint text
    /// directly, no version lookup required.
    unresolved_dependencies: Vec<UnresolvedDependency>,
    /// Everything the scan could not cover, ordered so the report is stable.
    skipped: BTreeSet<Skip>,
    scanned: usize,
    /// The paths covered per agent-file kind, in file order.
    coverage: Coverage,
}

/// The agent-file kinds one file was successfully read as.
#[derive(Debug, Default, Clone, Copy)]
struct Covered {
    mcp_manifest: bool,
    skill_file: bool,
    instruction_file: bool,
}

/// What one file's analysers produced, before it is folded into the whole
/// scan's [`Analysis`].
///
/// Exists so [`analyse_file`] can be a pure function of one path: nothing in
/// it reaches for scan-wide state, which is what lets the pass run in
/// parallel. The fields are the per-file slices of [`Analysis`], with
/// `skipped` a `Vec` rather than a `BTreeSet` because one file contributes at
/// most a handful of entries and the scan-wide set does the ordering.
#[derive(Debug, Default)]
struct FileAnalysis {
    findings: Vec<Finding>,
    dependencies: Vec<Dependency>,
    unresolved_dependencies: Vec<UnresolvedDependency>,
    skipped: Vec<Skip>,
    /// Which agent-file kinds this file was read as, for [`Report::coverage`].
    covered: Covered,
    /// The display path to list under each kind in `covered`; `None` when the
    /// file was not read.
    covered_path: Option<String>,
    /// Whether an analyser actually covered this file, for
    /// [`Summary::files_scanned`].
    scanned: bool,
}

/// Read and analyse every file an analyser claims, in one pass.
///
/// Files no analyser wants are never opened, so a repository full of images or
/// binaries costs nothing.
///
/// # Parallelism and determinism
///
/// Files are analysed in parallel and merged in file order. Every analyser
/// called here is a pure function of one path and its contents, so the only
/// shared state is the read-only [`RuleSet`], and the work per file — a
/// tree-sitter parse, which dominates the profile now that the per-rule tree
/// walks are gone — is far above the size where handing it to another thread
/// pays for itself.
///
/// The merge is what keeps the report byte-identical run to run, which the
/// scanner's contract requires: an agent re-runs a scan to check its own fix.
/// Results come back in [`biggest_first`] order and are put back in file order
/// before anything reads them, and the fold below then runs on one thread — so
/// findings, dependencies, skipped entries, the scanned count, and the order
/// [`Observer::found`] is called in are all exactly what a sequential pass
/// produces. Nothing here can observe which thread finished first, and
/// `the_report_is_identical_whatever_the_thread_count` pins that.
fn analyse(
    root: &Path,
    files: &[PathBuf],
    ruleset: &RuleSet,
    observer: &dyn Observer,
    out: &mut Analysis,
) {
    let schedule = biggest_first(root, files);

    // `with_max_len(1)` is load-bearing, not a tuning knob. Rayon splits an
    // indexed iterator by halving its *index* range, and only so far before it
    // needs a thread to steal from to split further -- which is fine when
    // neighbouring indices cost about the same, and wrong here, because
    // `schedule` has deliberately gathered every expensive file into its first
    // few indices. Left to the default, one thread inherits that whole
    // expensive prefix as a single chunk and the parallel scan runs at
    // single-thread speed: measured on DB-GPT, 54.9s against 25.1s with one
    // file per job.
    let analysed: Vec<Option<FileAnalysis>> = schedule
        .par_iter()
        .with_max_len(1)
        .map(|&index| analyse_file(root, &files[index], ruleset))
        .collect();

    // Back into file order before anything reads it, so the schedule stays a
    // scheduling decision and cannot reach the report.
    let mut per_file: Vec<Option<FileAnalysis>> = files.iter().map(|_| None).collect();
    for (&index, analysis) in schedule.iter().zip(analysed) {
        per_file[index] = analysis;
    }

    for file in per_file.into_iter().flatten() {
        for finding in file.findings {
            observer.found(&finding);
            out.findings.push(finding);
        }
        out.dependencies.extend(file.dependencies);
        out.unresolved_dependencies
            .extend(file.unresolved_dependencies);
        out.skipped.extend(file.skipped);
        out.scanned += usize::from(file.scanned);
        if let Some(path) = file.covered_path {
            if file.covered.mcp_manifest {
                out.coverage.mcp_manifests.push(path.clone());
            }
            if file.covered.skill_file {
                out.coverage.skill_files.push(path.clone());
            }
            if file.covered.instruction_file {
                out.coverage.instruction_files.push(path);
            }
        }
    }
}

/// Indices into `files`, biggest file first.
///
/// Longest-processing-time-first scheduling. Parse cost tracks file size
/// closely, and a repository whose work is concentrated in a few very large
/// files — committed bundler output is the usual reason — otherwise leaves
/// most cores idle behind the one thread that picked a 20 MB file up last.
/// Measured on a calibration-corpus repository whose `_next/static` output
/// holds seven minified JavaScript bundles of roughly 20 MB each: in file
/// order, four threads finished barely sooner than two (29.7s against 35.8s),
/// because two of them inherited the adjacent runs of bundles and ground
/// through them while the rest ran out of work. Biggest-first, four threads
/// take 20.8s. The win is largest exactly where it matters most — a CI runner
/// with two or four cores, not a developer laptop with ten.
///
/// A file no analyser will open is never `stat`ed and sorts last, where it
/// costs a `None` and nothing else.
///
/// This decides *when* a file is analysed, never what the scan reports:
/// [`analyse`] puts the results back in file order before reading them.
fn biggest_first(root: &Path, files: &[PathBuf]) -> Vec<usize> {
    let sizes: Vec<u64> = files
        .par_iter()
        .map(|relative| {
            if !is_analysed(relative) {
                return 0;
            }
            std::fs::metadata(root.join(relative)).map_or(0, |metadata| metadata.len())
        })
        .collect();

    let mut schedule: Vec<usize> = (0..files.len()).collect();
    // Index breaks size ties, so the schedule is the same on every run over an
    // unchanged tree. Nothing downstream depends on that, but a benchmark that
    // reshuffles itself between runs is not one worth reading.
    schedule.sort_unstable_by_key(|&index| (std::cmp::Reverse(sizes[index]), index));
    schedule
}

/// Run every analyser that claims `relative` over it.
///
/// `None` when no analyser wants the file at all — it is never opened, and
/// contributes nothing to the report, not even an empty entry.
fn analyse_file(root: &Path, relative: &Path, ruleset: &RuleSet) -> Option<FileAnalysis> {
    let source_language = SourceLanguage::from_path(relative);
    let mcp_config = mcp::is_mcp_config(relative);
    let manifest = cve::is_manifest(relative);
    let infra_file = infra::is_infra_file(relative);
    let instruction_file = instructions::is_instruction_file(relative);
    let skill_file = skill::is_skill_file(relative);
    let env_file = dotenv::is_env_file(relative);
    if source_language.is_none()
        && !mcp_config
        && !manifest
        && !infra_file
        && !instruction_file
        && !skill_file
        && !env_file
    {
        return None;
    }

    let mut out = FileAnalysis::default();
    let full = root.join(relative);

    // Before reading the file, let alone parsing it. A committed bundle can be
    // 20 MB on one line and costs hundreds of megabytes of parse tree, and
    // nothing it yields is actionable -- see `crate::generated` for why the
    // verdict comes from the bytes rather than the path.
    let generated = source_language.and_then(|_| generated::inspect(&full));
    if let Some(found) = &generated {
        out.skipped
            .push(Skip::generated(display_path(relative), found.measurement()));
        if !mcp_config && !manifest && !infra_file && !instruction_file && !skill_file {
            // Nothing else claims this file, so there is nothing left to read
            // it for. The usual case: `no_source_extension_is_claimed_by_
            // another_analyser` records the two names that are the exception.
            return Some(out);
        }
    }

    let Ok(contents) = std::fs::read_to_string(&full) else {
        // Unreadable, or not valid UTF-8. Either way we cannot analyse it,
        // and the report must say so rather than quietly covering less.
        out.skipped.push(Skip::unreadable(display_path(relative)));
        return Some(out);
    };

    if source_language.is_some() && generated.is_none() {
        // `scan_source_checked`, not `scan_source`: a source file that
        // reads fine but does not parse (invalid syntax, or a file whose
        // real format does not match its extension) must not be counted
        // as scanned -- no rule ran over it, so "scanned" would claim
        // coverage this file did not get. `scan_source`'s plain `Vec`
        // cannot tell that case apart from "parsed clean, zero findings".
        match scan_source_checked(ruleset, relative, &contents) {
            ScanOutcome::Scanned(findings) => {
                out.scanned = true;
                out.findings.extend(findings);
            }
            ScanOutcome::Unparseable => {
                out.skipped.push(Skip::unparseable(display_path(relative)));
            }
        }
    } else {
        // Either not a source file at all, or a source file judged generated
        // whose name another analyser also claims -- that analyser runs below
        // and does cover it, so `scanned` is true either way. The generated
        // verdict is already in `skipped`, so the report says both things.
        out.scanned = true;
    }

    if mcp_config {
        // An MCP server launched from a registry is a dependency nothing
        // else vets: it appears in no package.json or requirements.txt, so
        // a manifest-driven CVE scan never sees it, yet it runs inside the
        // agent's trust boundary.
        out.dependencies
            .extend(mcp::server_dependencies(relative, &contents));

        // A config that read but did not parse is not listed as covered: it
        // already produces the `BAS-MCP-000` defect.
        let (found, parsed) = mcp::inspect_config(relative, &contents);
        out.findings.extend(found);
        out.covered.mcp_manifest = parsed;
    }

    if infra_file {
        // Container configuration is the only place the sandbox boundary is
        // written down. A Compose file that does not parse is listed as
        // skipped, so the report does not claim coverage it did not get.
        match infra::inspect(relative, &contents) {
            Ok(found) => out.findings.extend(found),
            Err(_) => out.skipped.push(Skip::unparseable(display_path(relative))),
        }
    }

    out.covered_path = Some(display_path(relative));
    out.covered.skill_file = skill_file;
    // An MCP config and a `SKILL.md` are also instruction files internally,
    // but each is listed only under its own kind, never twice.
    out.covered.instruction_file = instruction_file && !mcp_config && !skill_file;

    if instruction_file {
        // An agent instruction file (or an MCP config, which can inline
        // a tool description too) is text a human reviews but a model
        // also reads -- the one place a hidden Unicode payload matters.
        out.findings
            .extend(instructions::inspect(relative, &contents));
    }

    if skill_file {
        // A SKILL.md manifest: frontmatter completeness, embedded prompt
        // injection, and excessive-agency language -- see `crate::skill`.
        out.findings.extend(skill::inspect(relative, &contents));
    }

    if env_file {
        // A .env file is walked by walk.rs's own always-walk allowlist
        // specifically because it holds credentials -- see dotenv module docs.
        out.findings.extend(dotenv::inspect(relative, &contents));
    }

    if manifest {
        collect_dependencies(relative, &contents, &mut out);
    }

    Some(out)
}

/// Parse one dependency manifest into the pending CVE query.
fn collect_dependencies(relative: &Path, contents: &str, out: &mut FileAnalysis) {
    match cve::parse_manifest(relative, contents) {
        Ok((resolved, unresolved)) => {
            out.dependencies.extend(resolved);
            // An unpinned range is not a finding and not an error. It is a gap
            // in what we could check, and belongs with the other things the
            // report admits it did not cover. Guessing a version and matching
            // advisories against the guess produces confident nonsense.
            for dep in unresolved {
                out.skipped.push(Skip::unpinned(
                    format!("{}:{}", display_path(&dep.file), dep.line),
                    dep.name.clone(),
                    &dep.constraint,
                ));
                out.unresolved_dependencies.push(dep);
            }
        }
        Err(_) => {
            out.skipped.push(Skip::unparseable(display_path(relative)));
        }
    }
}

/// Render a path with forward slashes, so a report is identical on every
/// platform.
fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Collapse identical findings.
///
/// Analysers run independently and can reach the same conclusion, so this runs
/// across all of them rather than within each.
fn dedupe(findings: &mut Vec<Finding>) {
    let mut seen = BTreeSet::new();
    findings.retain(|finding| {
        let (rule, file, line, column, title) = finding.dedupe_key();
        seen.insert((
            rule.to_owned(),
            file.clone(),
            line,
            column,
            title.to_owned(),
        ))
    });
}

/// Defects before observations, then severity descending, then confidence
/// descending, then location — so a reader hits the thing that matters first,
/// and two runs over unchanged code produce identical output.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| b.confidence.cmp(&a.confidence))
            .then_with(|| a.location.cmp(&b.location))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    use std::fs;
    use std::sync::Mutex;

    use tempfile::TempDir;

    use crate::report::SkipReason;

    fn tree(entries: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (path, contents) in entries {
            let full = dir.path().join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&full, contents).unwrap();
        }
        dir
    }

    fn rule_ids(report: &Report) -> Vec<&str> {
        let mut ids: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        ids.sort_unstable();
        ids
    }

    fn offline() -> ScanOptions {
        ScanOptions {
            offline: true,
            ..ScanOptions::default()
        }
    }

    #[test]
    fn container_configuration_is_analysed_by_the_scan() {
        let dir = tree(&[
            (
                "Dockerfile",
                "FROM python:3.12\nENV OPENAI_API_KEY=sk-proj-9f2b7d41c6a8e35019bd\nUSER root\n",
            ),
            (
                "docker-compose.yml",
                "services:\n  agent:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
            ),
        ]);

        let report = scan(dir.path(), &offline()).unwrap();

        assert_eq!(
            rule_ids(&report),
            [
                "BAS-INFRA-001",
                "BAS-INFRA-002",
                "BAS-INFRA-003",
                "BAS-INFRA-004"
            ]
        );
        assert_eq!(
            report.summary.files_scanned, 2,
            "both container files must be counted as scanned"
        );
        assert!(report.skipped.is_empty(), "{:#?}", report.skipped);
    }

    /// `.env` is one of `walk.rs`'s always-walked security-relevant dot-paths,
    /// but only [`is_analysed`]/`analyse_file` actually opening it makes that
    /// promise real. Before `dotenv` existed, a `.env` sitting right at the
    /// scan root -- exactly where `walk.rs`'s allowlist reaches -- was walked
    /// and then silently dropped: `analyse_file` returned `None`, so it was
    /// never read, never counted as scanned, and the report still claimed
    /// full coverage. This is `container_configuration_is_analysed_by_the_
    /// scan`'s sibling for that gap: the tree is built at `TempDir`'s own
    /// root specifically so `.env` sits where `walk.rs`'s allowlist doc
    /// comment says it always reaches, which `tests/corpus/vulnerable/
    /// dotenv_leak/.env` (nested two levels under this corpus's single
    /// shared scan root) cannot exercise — see the comment in
    /// `tests/corpus/expected.toml` next to that fixture.
    #[test]
    fn dot_env_credentials_are_analysed_by_the_scan() {
        let dir = tree(&[(
            ".env",
            "OPENAI_API_KEY=sk-proj-7f3a9c1eAbCdEfGh1234\nDB_PASSWORD=hunter2million\nDEBUG=true\n",
        )]);

        let report = scan(dir.path(), &offline()).unwrap();

        assert_eq!(rule_ids(&report), ["BAS-ZT1-021", "BAS-ZT1-022"]);
        assert_eq!(
            report.summary.files_scanned, 1,
            ".env must be counted as scanned, not silently skipped"
        );
        assert!(report.skipped.is_empty(), "{:#?}", report.skipped);
    }

    /// `.env.example` is still one of `walk.rs`'s always-walked paths and
    /// must stay counted as scanned -- the placeholder-suffix guard in
    /// `dotenv::inspect` is "looked at, nothing to report", not "never
    /// opened". A `.env.example` that quietly fell out of coverage would be
    /// exactly the silent-narrowing failure `walk.rs`'s own module doc
    /// comment exists to prevent.
    #[test]
    fn a_dot_env_example_file_is_scanned_but_never_flagged() {
        let dir = tree(&[(
            ".env.example",
            "OPENAI_API_KEY=sk-your-key-here\nDB_PASSWORD=changeme\n",
        )]);

        let report = scan(dir.path(), &offline()).unwrap();

        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert_eq!(
            report.summary.files_scanned, 1,
            ".env.example must still be counted as scanned"
        );
        assert!(report.skipped.is_empty(), "{:#?}", report.skipped);
    }

    #[test]
    fn a_dockerfile_observation_is_hidden_unless_asked_for() {
        let dir = tree(&[("Dockerfile", "FROM python:3.12\nCMD [\"python\"]\n")]);

        let hidden = scan(dir.path(), &offline()).unwrap();
        assert!(hidden.findings.is_empty(), "{:#?}", hidden.findings);
        assert_eq!(hidden.summary.observations, 1);

        let shown = scan(
            dir.path(),
            &ScanOptions {
                include_observations: true,
                ..offline()
            },
        )
        .unwrap();
        assert_eq!(rule_ids(&shown), ["BAS-INFRA-001"]);
    }

    #[test]
    fn a_malformed_compose_file_is_listed_as_skipped_not_reported_as_a_finding() {
        // A compose file that does not parse cannot be checked for the
        // container boundary it claims to describe, so the scan lists it as
        // skipped rather than counting it as covered.
        let dir = tree(&[("docker-compose.yml", "services: [unclosed\n")]);

        let report = scan(dir.path(), &offline()).unwrap();

        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert!(
            report
                .skipped
                .iter()
                .any(|skip| skip.reason == SkipReason::Unparseable
                    && skip.path == "docker-compose.yml"),
            "{:#?}",
            report.skipped
        );
    }

    #[test]
    fn a_compose_file_that_does_not_parse_is_listed_as_skipped() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("compose.yaml"),
            "services:\n  app: [\n    privileged: true\n",
        )
        .unwrap();
        let report = scan(
            dir.path(),
            &ScanOptions {
                offline: true,
                ..ScanOptions::default()
            },
        )
        .unwrap();
        assert!(
            report
                .skipped
                .iter()
                .any(|skip| skip.reason == SkipReason::Unparseable && skip.path == "compose.yaml"),
            "{:?}",
            report.skipped
        );
        assert_eq!(report.findings, Vec::<crate::finding::Finding>::new());
    }

    #[test]
    fn a_file_that_fails_to_parse_is_skipped_not_scanned() {
        // Valid extension (`.py` has a grammar), but content tree-sitter
        // cannot make sense of -- reading it succeeds, so pre-fix this used
        // to increment `scanned` before parsing was even attempted. No rule
        // ever ran over it; counting it as scanned claims coverage the scan
        // did not have.
        let dir = tree(&[("broken.py", "def(:::: not python at all @#$%^&*(\0\0\0")]);

        let report = scan(dir.path(), &offline()).unwrap();

        assert_eq!(
            report.summary.files_scanned, 0,
            "an unparseable file must not be counted as scanned"
        );
        assert_eq!(report.skipped.len(), 1, "{:#?}", report.skipped);
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.line().contains("broken.py")),
            "{:#?}",
            report.skipped
        );
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
    }

    /// The same secret, in a file whose bytes say a human wrote it and in a
    /// file whose bytes say a bundler produced it.
    ///
    /// A minified bundle is generated vendor output: nobody in the repository
    /// wrote it, and its remediation is "rebuild it", which no rule can say.
    /// It is also where the scan's time and memory go — see
    /// `crate::generated`.
    #[test]
    fn a_minified_bundle_is_skipped_as_generated_and_never_parsed() {
        const SECRET: &str = "const OPENAI_API_KEY=\"sk-proj-7f3a9c1e5d8b2a6f4c0e9d7b3a5f8c1e\";";

        let mut bundle = String::from("!function(e,t){");
        bundle.push_str(&"return e.n(t),".repeat(4000));
        bundle.push_str(SECRET);
        bundle.push_str("}();\n");
        assert!(
            bundle.len() > 32_768,
            "fixture must be a real bundle, not a line"
        );

        let dir = tree(&[
            ("src/app.js", &format!("{SECRET}\n")),
            ("web/bundle.js", &bundle),
        ]);

        let report = scan(dir.path(), &offline()).unwrap();

        let mut found: Vec<String> = report
            .findings
            .iter()
            .map(|finding| display_path(&finding.location.file))
            .collect();
        found.dedup();
        assert_eq!(
            found,
            ["src/app.js"],
            "the handwritten copy must still be found: {:#?}",
            report.findings
        );
        assert!(
            report.skipped.iter().any(|entry| entry
                .line()
                .starts_with("web/bundle.js \u{2014} generated:")),
            "a skipped bundle must be reported, and say why: {:#?}",
            report.skipped
        );
        assert_eq!(report.summary.files_scanned, 1);
    }

    /// The three coverage lists name what was read, each file once, and
    /// `coverage.skipped` is `skipped` with the reason as data.
    #[test]
    fn coverage_lists_the_agent_files_that_were_read_and_parsed() {
        let mut bundle = String::from("!function(e,t){");
        bundle.push_str(&"return e.n(t),".repeat(4000));
        bundle.push_str("}();\n");

        let dir = tree(&[
            (".mcp.json", r#"{"mcpServers":{}}"#),
            ("sub/mcp.json", "{ this is not json"),
            (
                "skills/x/SKILL.md",
                "---\nname: x\ndescription: does x\n---\nBody.\n",
            ),
            ("AGENTS.md", "# Agents\nBe careful.\n"),
            ("web/bundle.js", &bundle),
            ("broken.py", "def(:::: not python at all @#$%^&*(\0\0\0"),
        ]);

        let report = scan(dir.path(), &offline()).unwrap();
        let coverage = &report.coverage;

        assert_eq!(coverage.mcp_manifests, [".mcp.json"]);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "BAS-MCP-000"
                    && display_path(&f.location.file) == "sub/mcp.json"),
            "the malformed config must still be reported: {:#?}",
            report.findings
        );
        assert_eq!(coverage.skill_files, ["skills/x/SKILL.md"]);
        assert_eq!(coverage.instruction_files, ["AGENTS.md"]);

        assert_eq!(coverage.skipped.len(), report.skipped.len());
        for (structured, line) in coverage.skipped.iter().zip(&report.skipped) {
            assert_eq!(structured.path, line.path);
            assert_eq!(structured.reason, line.reason);
        }
        let reasons: Vec<(&str, SkipReason)> = coverage
            .skipped
            .iter()
            .map(|skip| (skip.path.as_str(), skip.reason))
            .collect();
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons.contains(&("web/bundle.js", SkipReason::Generated)));
        assert!(reasons.contains(&("broken.py", SkipReason::Unparseable)));
        let generated = coverage
            .skipped
            .iter()
            .find(|skip| skip.reason == SkipReason::Generated)
            .unwrap();
        assert!(!generated.detail.is_empty(), "{generated:?}");
    }

    /// A config the caller excluded was not read, so it is a skip and not
    /// coverage.
    #[test]
    fn an_excluded_mcp_config_is_a_coverage_skip_and_not_a_manifest() {
        let dir = tree(&[
            (".mcp.json", r#"{"mcpServers":{}}"#),
            ("vendor/mcp.json", r#"{"mcpServers":{}}"#),
        ]);
        let options = ScanOptions {
            offline: true,
            walk: WalkOptions {
                excludes: vec!["vendor/".to_owned()],
                ..WalkOptions::default()
            },
            ..ScanOptions::default()
        };

        let report = scan(dir.path(), &options).unwrap();

        assert_eq!(report.coverage.mcp_manifests, [".mcp.json"]);
        assert!(
            report
                .coverage
                .skipped
                .iter()
                .any(|skip| skip.reason == SkipReason::Excluded && skip.path.starts_with("vendor/")),
            "{:#?}",
            report.coverage.skipped
        );
    }

    /// `static/`, `assets/` and `public/` hold handwritten browser JavaScript
    /// in real repositories — 60 files under `static/` alone across the
    /// calibration corpus. A path blocklist hides every one of them; the
    /// content signal does not, and this pins that difference.
    #[test]
    fn handwritten_javascript_under_a_generated_sounding_directory_is_scanned() {
        let handwritten = "const OPENAI_API_KEY = \"sk-proj-7f3a9c1e5d8b2a6f4c0e9d7b3a5f8c1e\";\n\
             function boot() {\n    return fetch(\"/api\", { headers: {} });\n}\n"
            .repeat(40);

        let dir = tree(&[
            ("app/static/js/app.js", handwritten.as_str()),
            ("dist/bundle.js", handwritten.as_str()),
            ("frontend/public/widget.js", handwritten.as_str()),
        ]);

        let report = scan(dir.path(), &offline()).unwrap();

        let mut found: Vec<String> = report
            .findings
            .iter()
            .map(|finding| display_path(&finding.location.file))
            .collect();
        found.sort_unstable();
        found.dedup();
        assert_eq!(
            found,
            [
                "app/static/js/app.js",
                "dist/bundle.js",
                "frontend/public/widget.js"
            ],
            "readable source is scanned wherever it lives"
        );
        assert!(report.skipped.is_empty(), "{:#?}", report.skipped);
    }

    /// [`analyse_file`] returns early when a source file is judged generated
    /// and nothing else claims it, so which names *are* claimed twice is
    /// load-bearing: get that set wrong and the early return drops an
    /// analyser's coverage without saying so.
    ///
    /// Exactly one stem overlaps, from the infrastructure analyser's prefix
    /// match on `Dockerfile`: `Dockerfile.py` is a source file and a
    /// container file at once, which is why the early return is conditional
    /// rather than unconditional. Nothing else overlaps, and a change that
    /// widens the set fails here.
    #[test]
    fn no_source_extension_is_claimed_by_another_analyser() {
        for extension in ["py", "js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"] {
            for stem in [
                "app",
                "index",
                "skill",
                "agents",
                "claude",
                "mcp",
                "package",
                "Dockerfile",
                "docker-compose",
                "requirements",
                "pyproject",
            ] {
                let path = PathBuf::from(format!("nested/{stem}.{extension}"));
                assert!(
                    SourceLanguage::from_path(&path).is_some(),
                    "{} must be a source file",
                    path.display()
                );
                let also_claimed = mcp::is_mcp_config(&path)
                    || cve::is_manifest(&path)
                    || infra::is_infra_file(&path)
                    || instructions::is_instruction_file(&path)
                    || skill::is_skill_file(&path);
                assert_eq!(
                    also_claimed,
                    stem == "Dockerfile",
                    "{} was claimed by an unexpected set of analysers",
                    path.display()
                );
            }
        }
    }

    /// Python holding a hardcoded key and calling `eval` on a model reply:
    /// findings from more than one rule, at more than one location, in one
    /// file.
    const VULNERABLE: &str = r#"
import openai

OPENAI_API_KEY = "sk-proj-7f3a9c1e5d8b2a6f4c0e9d7b3a5f8c1e"


def advise(question):
    reply = openai.chat.completions.create(messages=[{"role": "user", "content": question}])
    return eval(reply.choices[0].message.content)
"#;

    /// A tree wide enough that the analysis pass really is split several ways,
    /// and varied enough that every channel the parallel merge has to keep
    /// ordered actually carries something: findings, skipped-because-
    /// unparseable, skipped-because-unreadable, and skipped-because-unpinned.
    ///
    /// Sizes vary deliberately. The pass schedules the biggest file first, so
    /// a fixture of identically-sized files would run in file order by
    /// accident and never exercise the reordering at all.
    fn wide_tree() -> TempDir {
        let dir = TempDir::new().unwrap();
        for index in 0..96 {
            let stem = format!("pkg{index:03}");
            fs::create_dir_all(dir.path().join(&stem)).unwrap();
            // Padding rises and falls against path order, so file size and
            // file order disagree in both directions.
            let padding = "# pad\n".repeat((index * 37) % 400);
            fs::write(
                dir.path().join(&stem).join("agent.py"),
                format!("{padding}{VULNERABLE}"),
            )
            .unwrap();
            // Every third package holds a file that cannot be parsed, so
            // `skipped` is fed from all over the tree, not one corner of it.
            if index % 3 == 0 {
                fs::write(
                    dir.path().join(&stem).join("broken.py"),
                    "def(:::: not python at all @#$%^&*(\0\0\0",
                )
                .unwrap();
            }
            // And every fifth holds bytes that are not UTF-8 at all, which is
            // the other way into `skipped`.
            if index % 5 == 0 {
                fs::write(
                    dir.path().join(&stem).join("binary.py"),
                    [0xffu8, 0xfe, 0x00, 0x80],
                )
                .unwrap();
            }
        }
        // One unpinned dependency: a `skipped` entry that comes from a
        // manifest rather than a source file, and an unresolved dependency a
        // later phase reads back.
        fs::write(
            dir.path().join("requirements.txt"),
            "requests==2.19.1\nflask>=2.0\n",
        )
        .unwrap();
        dir
    }

    fn in_pool<T: Send>(threads: usize, work: impl Fn() -> T + Sync + Send) -> T {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(work)
    }

    /// The scanner's contract is that an agent can re-run a scan to check its
    /// own fix, so identical code must give an identical report. The analysis
    /// pass runs on however many threads the machine has, and every ordered
    /// thing in the report — findings, `skipped`, the scanned count — is built
    /// from its results.
    ///
    /// Putting one tree through pools of several sizes is what makes this test
    /// able to fail. A merge that leaked completion order into the report
    /// would still agree with itself on a fixed machine, so re-running a scan
    /// there could keep producing the same wrong answer; it would not survive
    /// the same work being cut up a different number of ways.
    #[test]
    fn the_report_is_identical_whatever_the_thread_count() {
        let dir = wide_tree();
        let scan_it = || scan(dir.path(), &offline()).unwrap();

        let expected = in_pool(1, scan_it);

        // Guard the guard: a fixture that stopped producing findings or skips
        // would make every assertion below pass vacuously.
        assert!(expected.findings.len() > 90, "{:#?}", expected.summary);
        assert!(expected.skipped.len() > 40, "{:#?}", expected.skipped);
        assert!(
            expected.summary.files_scanned > 90,
            "{:#?}",
            expected.summary
        );

        for threads in [2, 3, 5, 8, 16] {
            for attempt in 1..=3 {
                assert_eq!(
                    in_pool(threads, scan_it),
                    expected,
                    "report differed on {threads} threads, attempt {attempt}"
                );
            }
        }
    }

    /// [`Observer::found`] is the one ordered thing the report's own sort
    /// cannot repair: it is called as the merge walks per-file results, so it
    /// reports whatever order the merge chose. A terminal listing findings in
    /// thread-completion order would be non-deterministic in a way no
    /// assertion on the finished report could see.
    ///
    /// The order is also asserted absolutely, not only against itself: it must
    /// be file order. That is what pins the schedule as a scheduling decision
    /// — the pass analyses the biggest file first, and unpicking that
    /// permutation wrongly would show up here and almost nowhere else, since
    /// the report gets sorted afterwards either way.
    #[test]
    fn the_observer_sees_findings_in_file_order_whatever_the_thread_count() {
        #[derive(Default)]
        struct Recorder {
            seen: Mutex<Vec<(String, usize)>>,
        }

        impl Observer for Recorder {
            fn found(&self, finding: &Finding) {
                if let Ok(mut seen) = self.seen.lock() {
                    seen.push((display_path(&finding.location.file), finding.location.line));
                }
            }
        }

        let dir = wide_tree();
        let record = || {
            let recorder = Recorder::default();
            scan_observed(dir.path(), &offline(), &recorder).unwrap();
            recorder.seen.into_inner().unwrap()
        };

        let expected = in_pool(1, record);
        assert!(expected.len() > 90, "{}", expected.len());

        let mut in_file_order = expected.clone();
        in_file_order.sort();
        assert_eq!(
            expected, in_file_order,
            "findings must reach the observer in file order, not schedule order"
        );

        for threads in [2, 3, 5, 8, 16] {
            assert_eq!(
                in_pool(threads, record),
                expected,
                "observer order differed on {threads} threads"
            );
        }
    }
}
