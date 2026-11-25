//! `bastyn scan` — analyse a repository and report what is wrong.

use std::cell::Cell;
use std::io::{BufWriter, Write};
use std::time::SystemTime;

use anyhow::Context as _;
use bastyn_core::render::{CrosswalkDetail, ScanResult, StdoutOptions};
use bastyn_core::reporting::session::{self, Reported, Request};
use bastyn_core::reporting::state;
use bastyn_core::reporting::upload::{
    Endpoint, Policy, ThreadSleeper, Timeouts, UreqTransport, random_jitter,
};
use bastyn_core::{
    Finding, Framework, Observer, Phase, Report, ScanOptions, Severity, WalkOptions, render,
    scan_observed,
};

use crate::cli::{FailOn, Format, GlobalArgs, ScanArgs};
use crate::exit;
use crate::progress::{self, Progress};
use crate::terminal::{TerminalInputs, color_decision, glyph_decision};

/// The outcome of a scan, as far as the exit code is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Nothing at or above the threshold.
    Clean,
    /// Something at or above the threshold.
    Findings,
}

impl Outcome {
    /// The process exit code this outcome produces.
    ///
    /// The report prints this number, and `main` returns it. One function, so
    /// the printed status and `$?` cannot drift apart.
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::Clean => exit::CLEAN,
            Self::Findings => exit::FINDINGS,
        }
    }

    /// How the report states it.
    const fn result(self) -> ScanResult {
        match self {
            Self::Clean => ScanResult::Passed,
            Self::Findings => ScanResult::Failed,
        }
    }
}

/// Run the `scan` subcommand.
pub(crate) fn run(args: &ScanArgs, global: &GlobalArgs) -> anyhow::Result<Outcome> {
    let options = ScanOptions {
        walk: WalkOptions {
            respect_ignore_files: !args.no_ignore,
            include_hidden: args.hidden,
            follow_symlinks: args.follow_symlinks,
            max_depth: args.max_depth,
            excludes: args.exclude.clone(),
        },
        offline: args.offline,
        include_observations: args.show_observations,
        inspect_remote: args.inspect_remote,
        save_snapshots: args.save_snapshots.clone(),
    };

    let progress = Progress::start(global);
    let watched = Counts::watching(&progress);

    let started_at = SystemTime::now();
    let scanned = scan_observed(&args.path, &options, &watched);
    let finished_at = SystemTime::now();
    let mut report = scanned.with_context(|| format!("could not scan {}", args.path.display()))?;

    // Grouping is applied to the finished report rather than threaded into the
    // scan: it regroups what was found and changes nothing about what was
    // found, so the engine has no business knowing which view was asked for.
    //
    // Every framework by default, one when `--group-by` names one. A reader
    // who has to remember a flag to see the EU AI Act would also have to
    // remember a second one to see NIST, and whichever they forgot would look
    // like an area with nothing in it. `--group-by` therefore chooses which
    // framework to expand in full, not whether compliance areas appear at all.
    let frameworks: Vec<Framework> = match args.group_by.framework() {
        Some(framework) => vec![framework],
        None => Framework::ALL.to_vec(),
    };
    report.crosswalks = frameworks
        .into_iter()
        .map(|framework| bastyn_core::crosswalk(&report, framework))
        .collect();
    let report = report;

    // Decided before anything is printed, because the report states it: the
    // `RESULT` line and the process exit code are the same fact, and deriving
    // them separately is how they end up disagreeing.
    let outcome = outcome(&report, args.fail_on);

    // Detail level is stated, never inferred from how many crosswalks came
    // out: one framework asked for by name is one the reader wants the
    // findings of, and three they did not ask for are three they want the
    // shape of.
    let crosswalks = if args.group_by.framework().is_some() {
        CrosswalkDetail::Detailed
    } else {
        CrosswalkDetail::Summary
    };

    let terminal = TerminalInputs::gathered(global);
    let (payload, summary) = match global.format {
        Format::Text => {
            let rendered = render::stdout(
                &report,
                StdoutOptions {
                    color: color_decision(terminal),
                    glyphs: glyph_decision(terminal),
                    crosswalks,
                    offline: args.offline,
                    rules: watched.rules.get(),
                    dependencies: watched.dependencies.get(),
                    result: outcome.result(),
                    exit_code: outcome.exit_code(),
                    show_coverage: args.show_coverage,
                },
            );
            (rendered.text, Some(rendered.summary))
        }
        Format::Json => (
            render::json(&report).context("could not render JSON")?,
            None,
        ),
        Format::Sarif => (
            render::sarif(&report).context("could not render SARIF")?,
            None,
        ),
    };

    // `--quiet` prints the summary the renderer handed back, never a line the
    // caller went looking for by position.
    let payload = match summary.filter(|_| global.quiet) {
        Some(summary) => format!("{summary}\n"),
        None => payload,
    };
    write_out(&payload)?;
    // Only where stdout is not already carrying the verdict — see
    // `progress::summary_enabled`.
    progress::summary(&report, global);

    // Last, so nothing it does can precede or alter the output above, and
    // infallible by construction: it returns nothing the exit code could be
    // derived from.
    report_summary(args, &report, started_at, finished_at);

    if let Some(path) = &args.debug_unresolved {
        write_unresolved(args, &options.walk, path)?;
    }

    Ok(outcome)
}

/// Write the `--debug-unresolved` file: one JSON object per line.
fn write_unresolved(
    args: &ScanArgs,
    walk: &WalkOptions,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    let sinks = bastyn_core::collect_unresolved_sinks(&args.path, walk).with_context(|| {
        format!(
            "could not collect unresolved sinks in {}",
            args.path.display()
        )
    })?;
    let mut text = String::new();
    for sink in &sinks {
        text.push_str(&serde_json::to_string(sink).context("could not render JSON")?);
        text.push('\n');
    }
    std::fs::write(path, text).with_context(|| format!("could not write {}", path.display()))
}

/// Send the anonymous scan summary, unless reporting is off.
///
/// Whatever happens is at most one line on stderr: the scan's output and exit
/// code were settled before this runs, and nothing here returns an error.
fn report_summary(
    args: &ScanArgs,
    report: &Report,
    started_at: SystemTime,
    finished_at: SystemTime,
) {
    let env = |name: &str| std::env::var_os(name);
    let state_dir = state::state_dir(&env);
    let request = Request {
        report,
        scan_root: &args.path,
        env: &env,
        state_dir: state_dir.as_deref(),
        no_reporting: args.no_reporting,
        offline: args.offline,
        started_at,
        finished_at,
    };

    let Some((endpoint, timeouts)) = destination() else {
        // Only reachable with the `test-endpoint` feature.
        warn("bastyn: skipped the anonymous scan summary: invalid test endpoint.");
        return;
    };
    let transport = UreqTransport::new(&endpoint, timeouts);
    let mut notice = |text: &str| warn(text);

    match session::run(
        &request,
        &transport,
        &ThreadSleeper,
        &random_jitter,
        &Policy::default(),
        &mut notice,
    ) {
        Reported::Failed(reason) => warn(&format!(
            "bastyn: could not send the anonymous scan summary: {reason}. The scan result is unchanged."
        )),
        Reported::NoProjectId(reason) => warn(&format!(
            "bastyn: skipped the anonymous scan summary: no project ID ({reason})."
        )),
        Reported::Disabled(_) | Reported::Sent => {}
    }
}

/// One line on stderr. A closed stderr leaves nowhere to complain to.
fn warn(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// Where the summary goes and how long to wait for it: always the production
/// collector with the default limits, except in a build with the
/// `test-endpoint` feature, where the environment can override both. `None`
/// means the override was set to something unusable.
#[cfg(not(feature = "test-endpoint"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the `test-endpoint` variant, which can fail"
)]
fn destination() -> Option<(Endpoint, Timeouts)> {
    Some((Endpoint::production(), Timeouts::default()))
}

/// See the non-feature variant. This one reads two variables that exist only
/// in test builds.
#[cfg(feature = "test-endpoint")]
fn destination() -> Option<(Endpoint, Timeouts)> {
    let endpoint = match std::env::var_os("BASTYN_REPORTING_ENDPOINT_FOR_TESTS") {
        Some(value) => Endpoint::custom(value.to_str()?)?,
        None => Endpoint::production(),
    };
    let mut timeouts = Timeouts::default();
    if let Some(millis) = std::env::var("BASTYN_REPORTING_TIMEOUT_MS_FOR_TESTS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        let limit = std::time::Duration::from_millis(millis);
        timeouts = Timeouts {
            connect: limit,
            global: limit,
        };
    }
    Some((endpoint, timeouts))
}

/// An [`Observer`] that forwards to `inner` and keeps the two counts the
/// finished report does not carry.
///
/// The rule count and the resolved-dependency count are facts about the scan
/// that ran, and the report's shape is a published contract that has no field
/// for either. Announcing them is already the engine's job, so this listens
/// rather than asking the engine to say the same thing twice.
///
/// `Cell` rather than an atomic because the engine announces phases from the
/// thread that called it; the parallel pass never touches the observer.
struct Counts<'a> {
    inner: &'a dyn Observer,
    rules: Cell<usize>,
    dependencies: Cell<usize>,
}

impl<'a> Counts<'a> {
    fn watching(inner: &'a dyn Observer) -> Self {
        Self {
            inner,
            rules: Cell::new(0),
            dependencies: Cell::new(0),
        }
    }
}

impl Observer for Counts<'_> {
    fn phase_started(&self, phase: &Phase) {
        match phase {
            Phase::Analysing { rules, .. } => self.rules.set(*rules),
            Phase::Cve { dependencies } => self.dependencies.set(*dependencies),
            _ => {}
        }
        self.inner.phase_started(phase);
    }

    fn phase_finished(&self, phase: &Phase) {
        self.inner.phase_finished(phase);
    }

    fn found(&self, finding: &Finding) {
        self.inner.found(finding);
    }
}

/// Decide the exit outcome from the report and the threshold.
///
/// Only defects count. An observation must never fail a build — the repository
/// has not shown that the missing control is wrong, so blocking on it is the
/// behaviour that gets a scanner removed from CI.
fn outcome(report: &Report, fail_on: FailOn) -> Outcome {
    let Some(threshold) = threshold(fail_on) else {
        return Outcome::Clean;
    };

    let blocking = report
        .findings
        .iter()
        .filter(|finding| finding.kind == bastyn_core::Kind::Defect)
        .any(|finding| finding.severity >= threshold);

    if blocking {
        Outcome::Findings
    } else {
        Outcome::Clean
    }
}

/// The severity floor for a threshold, or `None` for "never fail".
const fn threshold(fail_on: FailOn) -> Option<Severity> {
    match fail_on {
        FailOn::None => None,
        FailOn::Low => Some(Severity::Low),
        FailOn::Medium => Some(Severity::Medium),
        FailOn::High => Some(Severity::High),
        FailOn::Critical => Some(Severity::Critical),
    }
}

/// Write to stdout, treating a closed downstream pipe as success.
///
/// `bastyn scan | head` is a normal thing to type; the reader disappearing is
/// not a failure of the scan.
fn write_out(payload: &str) -> anyhow::Result<()> {
    let stdout = std::io::stdout().lock();
    let mut out = BufWriter::new(stdout);

    let result = out.write_all(payload.as_bytes()).and_then(|()| out.flush());
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(anyhow::Error::new(error).context("could not write output")),
    }
}

#[cfg(test)]
mod tests {
    use super::Outcome;
    use crate::exit;

    /// The number the report prints is the number the process returns.
    #[test]
    fn the_printed_exit_status_is_the_real_one() {
        assert_eq!(Outcome::Clean.exit_code(), exit::CLEAN);
        assert_eq!(Outcome::Findings.exit_code(), exit::FINDINGS);
        assert_ne!(Outcome::Clean.exit_code(), Outcome::Findings.exit_code());
    }
}
