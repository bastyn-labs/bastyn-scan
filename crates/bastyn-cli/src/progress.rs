//! Live terminal progress for `bastyn scan`.
//!
//! Everything here writes to stderr, never stdout, and only when stderr is a
//! real terminal that has not asked to be left alone (`--quiet`,
//! `--no-color`, `NO_COLOR`, or a machine-readable `--format`). The engine
//! ([`bastyn_core::observe`]) knows nothing about any of this: it only
//! announces phases and findings through the [`Observer`] trait, and this
//! module is the only thing that turns those announcements into escape
//! sequences.
//!
//! The scan itself is synchronous and will not yield, so a spinner needs its
//! own thread. [`Progress::start`] spawns one and returns a value that
//! implements `Observer`; dropping it disconnects the channel the thread is
//! waiting on, which is what makes the thread exit on every path — a clean
//! return, an early `?`, or a panic unwinding through the caller's stack —
//! and it also restores the cursor if this module hid it.
//!
//! The closing summary is a separate decision from the spinner, and the two
//! are gated on different questions. The spinner asks "is anyone watching a
//! terminal"; the summary asks "does stdout already carry the verdict". See
//! [`summary_enabled`].

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{IsTerminal, Write as _};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use bastyn_core::{Finding, Kind, Observer, Phase, Report, Severity};

use crate::cli::{Format, GlobalArgs};

/// Braille dot frames.
///
/// Chosen over the classic `|/-\` because progress is only ever shown when
/// stderr is a real terminal ([`IsTerminal`]), and any terminal emulator that
/// still gets used today renders braille correctly; a non-interactive stream
/// (CI logs, a pipe, a redirect) never reaches this code at all. If a
/// supported terminal ever turns up that cannot render these, the fix is a
/// one-line swap of this constant for `['|', '/', '-', '\\']`.
const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// How often the spinner advances, and how long the render thread will ever
/// block waiting for the next event before it checks in again.
const FRAME_INTERVAL: Duration = Duration::from_millis(80);

/// How many phases get a numbered step line.
///
/// [`Phase::Reporting`] is deliberately excluded: dedup and sort take no
/// visible time and start and finish with no work in between, so a step for
/// it would be on screen for zero frames and only clutter the count.
const TOTAL_STEPS: u8 = 4;

/// The step number a phase appears as, or `None` for a phase that gets no
/// numbered line.
///
/// [`Phase`] is `#[non_exhaustive]`, so this has a wildcard arm; a future
/// phase the engine adds before this mapping is updated simply renders no
/// step, which is the safe default.
fn step_number(phase: &Phase) -> Option<u8> {
    match phase {
        Phase::Walking => Some(1),
        Phase::Analysing { .. } => Some(2),
        Phase::Cve { .. } => Some(3),
        Phase::Reporting => Some(4),
        _ => None,
    }
}

/// Everything [`progress_enabled`] needs, gathered in one place so the
/// suppression rule is a pure function a test can drive through every
/// combination without a real terminal or environment.
#[derive(Debug, Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is an independent suppression condition; a state machine would obscure which ones are set"
)]
pub(crate) struct ProgressInputs {
    /// `--quiet` was passed.
    pub(crate) quiet: bool,
    /// `--no-color` was passed.
    pub(crate) no_color_flag: bool,
    /// The `NO_COLOR` environment variable is set.
    pub(crate) no_color_env: bool,
    /// The chosen output format.
    pub(crate) format: Format,
    /// Whether stderr is an interactive terminal.
    pub(crate) stderr_is_tty: bool,
}

/// Whether live progress should be shown at all.
///
/// Every one of these suppresses it on its own; none of them need to combine:
/// not an interactive terminal, `--quiet`, `--no-color`, `NO_COLOR`, or a
/// machine-readable format (`json`, `sarif`) whose byte-for-byte shape is a
/// contract other tools parse.
#[must_use]
pub(crate) fn progress_enabled(inputs: ProgressInputs) -> bool {
    inputs.stderr_is_tty
        && inputs.format == Format::Text
        && !inputs.quiet
        && !inputs.no_color_flag
        && !inputs.no_color_env
}

/// One thing the engine told us, translated into what the render thread needs
/// to draw it. Carries owned data because it crosses a thread boundary — the
/// [`Phase`] or [`Finding`] it came from does not outlive the `Observer`
/// call.
enum Event {
    /// A phase started.
    Started(Phase),
    /// A phase finished.
    Finished(Phase),
    /// A finding was produced.
    Found {
        /// The finding's leading framework category, e.g. `"LLM10"`.
        category: String,
        /// The finding's title.
        title: String,
        /// `file:line`.
        location: String,
    },
}

/// Live progress, or nothing. Both implement [`Observer`]; a caller does not
/// need to know which one it has.
pub(crate) enum Progress {
    /// Progress is enabled and its render thread is running.
    Live(Live),
    /// Progress is suppressed. Every `Observer` method is a no-op.
    Off,
}

/// The running half of [`Progress`]: a channel to the render thread and what
/// it takes to shut both down cleanly.
pub(crate) struct Live {
    /// The sender half of the channel the render thread listens on.
    ///
    /// `Option` so [`Drop`] can take it out and drop it explicitly, which is
    /// what makes the render thread's next receive return `Disconnected`
    /// instead of waiting out the full frame interval forever.
    tx: Option<Sender<Event>>,
    /// The render thread, joined on drop so nothing outlives this process's
    /// own cleanup.
    handle: Option<JoinHandle<()>>,
}

impl Progress {
    /// Decide whether to show progress and, if so, start it.
    ///
    /// This is the one place that reads the piece of environment
    /// [`progress_enabled`] cannot be handed as a plain argument in a unit
    /// test: whether stderr is really a terminal, and whether `NO_COLOR` is
    /// set.
    #[must_use]
    pub(crate) fn start(global: &GlobalArgs) -> Self {
        let inputs = ProgressInputs {
            quiet: global.quiet,
            no_color_flag: global.no_color,
            no_color_env: std::env::var_os("NO_COLOR").is_some(),
            format: global.format,
            stderr_is_tty: std::io::stderr().is_terminal(),
        };

        if !progress_enabled(inputs) {
            return Self::Off;
        }

        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || render_loop(&rx));
        hide_cursor();

        Self::Live(Live {
            tx: Some(tx),
            handle: Some(handle),
        })
    }
}

/// Print the closing summary to stderr, if anything is left to say.
///
/// Deliberately not gated on [`Progress`]: the spinner is suppressed for the
/// machine formats precisely because stdout is a contract, and that is exactly
/// the invocation where this line is the only thing telling an interactive
/// user what happened. `bastyn scan --format json > out.json` used to finish
/// in silence.
pub(crate) fn summary(report: &Report, global: &GlobalArgs) {
    let inputs = SummaryInputs {
        quiet: global.quiet,
        no_color_flag: global.no_color,
        no_color_env: std::env::var_os("NO_COLOR").is_some(),
        format: global.format,
        stdout_is_tty: std::io::stdout().is_terminal(),
        stderr_is_tty: std::io::stderr().is_terminal(),
    };
    if !summary_enabled(inputs) {
        return;
    }

    let text = summary_block(report, summary_color(inputs));
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}

/// Everything [`summary_enabled`] needs, gathered so the rule stays a pure
/// function a test can drive without a terminal.
#[derive(Debug, Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is an independent condition; a state machine would obscure which ones are set"
)]
pub(crate) struct SummaryInputs {
    /// `--quiet` was passed.
    pub(crate) quiet: bool,
    /// `--no-color` was passed.
    pub(crate) no_color_flag: bool,
    /// The `NO_COLOR` environment variable is set.
    pub(crate) no_color_env: bool,
    /// The chosen output format.
    pub(crate) format: Format,
    /// Whether stdout is an interactive terminal.
    pub(crate) stdout_is_tty: bool,
    /// Whether stderr is an interactive terminal.
    pub(crate) stderr_is_tty: bool,
}

/// Whether the closing summary goes to stderr.
///
/// The rule, stated positively: **emit it unless a text report is going to a
/// terminal.** There, and only there, the reader already has the verdict —
/// `RESULT: FAILED` and `3 defects found: 1 critical, 2 high` are three lines
/// above where this would land, and two statements of one fact on one screen
/// make a reader reconcile them instead of acting on either.
///
/// Everywhere else stdout is carrying something that is not the verdict, or is
/// not being read by a person at all: `--format json`, `--format sarif`, or a
/// text report redirected into a file. Those invocations finished in silence
/// once, and an interactive user had no way to tell a clean scan from a
/// failing one without opening the output.
///
/// `--quiet` is the one other suppressor, and for the same reason rather than
/// a different one: it already prints the summary line, on stdout. A second
/// copy on stderr is what it asked not to have.
///
/// Notably *not* conditions: `--no-color`, `NO_COLOR`, and a non-terminal
/// stderr. Those say how to render, not whether to speak, and this is one
/// plain line rather than the escape sequences a spinner needs — a CI log is a
/// place it belongs. [`summary_color`] is where they apply.
#[must_use]
pub(crate) fn summary_enabled(inputs: SummaryInputs) -> bool {
    if inputs.quiet {
        return false;
    }
    !(inputs.format == Format::Text && inputs.stdout_is_tty)
}

/// Whether that line may carry colour.
///
/// The usual rule, on the stream it is actually written to.
#[must_use]
pub(crate) const fn summary_color(inputs: SummaryInputs) -> bool {
    inputs.stderr_is_tty && !inputs.no_color_flag && !inputs.no_color_env
}

impl Observer for Progress {
    fn phase_started(&self, phase: &Phase) {
        if let Self::Live(live) = self {
            live.send(Event::Started(phase.clone()));
        }
    }

    fn phase_finished(&self, phase: &Phase) {
        if let Self::Live(live) = self {
            live.send(Event::Finished(phase.clone()));
        }
    }

    fn found(&self, finding: &Finding) {
        if let Self::Live(live) = self {
            let category = finding
                .categories
                .first()
                .map_or("", |category| category.id())
                .to_owned();
            live.send(Event::Found {
                category,
                title: finding.title.clone(),
                location: format!(
                    "{}:{}",
                    finding.location.file.display(),
                    finding.location.line
                ),
            });
        }
    }
}

impl Live {
    /// Send an event to the render thread, discarding it if the thread is
    /// already gone.
    ///
    /// The render thread never hangs up on its own; a send error only
    /// happens if it already exited unexpectedly. Either way the scan must
    /// keep running — progress is a courtesy, not a dependency.
    fn send(&self, event: Event) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        let Self::Live(live) = self else { return };

        // Drop the sender first so the render thread's next receive returns
        // `Disconnected` instead of idling out the frame interval, then join
        // it so no thread outlives this process's own cleanup.
        live.tx.take();
        if let Some(handle) = live.handle.take() {
            let _ = handle.join();
        }

        show_cursor();
    }
}

fn hide_cursor() {
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(b"\x1b[?25l");
    let _ = stderr.flush();
}

fn show_cursor() {
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(b"\x1b[?25h");
    let _ = stderr.flush();
}

/// One phase the render thread is currently waiting on, in the order it was
/// started.
///
/// The engine starts `Parsing`, `Rules`, and `Mcp` back to back with no work
/// between the calls — the real elapsed time is inside the one loop that
/// produces all three phases' results — so this queue is what turns that
/// back-to-back announcement into a sequence of separate step lines: the
/// spinner tracks the front, and a finish is applied to whichever queued
/// phase it names, wherever in the queue that is.
struct Active {
    /// The phase itself, so its label can be rendered.
    phase: Phase,
    /// Its step number.
    step: u8,
}

/// Owns the terminal for as long as progress is live. Runs on its own thread
/// because the scan that drives it is synchronous and will not yield.
fn render_loop(rx: &mpsc::Receiver<Event>) {
    let mut queue: VecDeque<Active> = VecDeque::new();
    let mut frame = 0usize;
    let mut spinner_on_screen = false;
    let mut stderr = std::io::stderr();

    loop {
        match rx.recv_timeout(FRAME_INTERVAL) {
            Ok(Event::Started(phase)) => {
                if let Some(step) = step_number(&phase) {
                    let was_idle = queue.is_empty();
                    queue.push_back(Active { phase, step });
                    if was_idle {
                        frame = 0;
                        if let Some(active) = queue.front() {
                            draw_spinner(&mut stderr, active, frame, &mut spinner_on_screen);
                        }
                    }
                }
            }
            Ok(Event::Finished(phase)) => {
                let Some(pos) = queue.iter().position(|active| active.phase == phase) else {
                    continue;
                };
                let Some(active) = queue.remove(pos) else {
                    continue;
                };
                clear_line(&mut stderr, &mut spinner_on_screen);
                let _ = writeln!(
                    stderr,
                    "{}",
                    done_line(active.step, TOTAL_STEPS, &active.phase.label(), true)
                );
                if let Some(next) = queue.front() {
                    frame = 0;
                    draw_spinner(&mut stderr, next, frame, &mut spinner_on_screen);
                }
            }
            Ok(Event::Found {
                category,
                title,
                location,
            }) => {
                clear_line(&mut stderr, &mut spinner_on_screen);
                let _ = writeln!(stderr, "{}", found_line(&category, &title, &location, true));
                if let Some(active) = queue.front() {
                    draw_spinner(&mut stderr, active, frame, &mut spinner_on_screen);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Some(active) = queue.front() {
                    frame = frame.wrapping_add(1);
                    draw_spinner(&mut stderr, active, frame, &mut spinner_on_screen);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                clear_line(&mut stderr, &mut spinner_on_screen);
                return;
            }
        }
    }
}

/// Erase the in-progress spinner line, if one is currently on screen.
fn clear_line(stderr: &mut std::io::Stderr, spinner_on_screen: &mut bool) {
    if *spinner_on_screen {
        let _ = write!(stderr, "\r\x1b[2K");
        *spinner_on_screen = false;
    }
}

/// (Re)draw the spinner line for `active` at `frame`, overwriting whatever
/// was on screen.
fn draw_spinner(
    stderr: &mut std::io::Stderr,
    active: &Active,
    frame: usize,
    spinner_on_screen: &mut bool,
) {
    let glyph = SPINNER_FRAMES[frame % SPINNER_FRAMES.len()];
    let text = spinner_line(glyph, active.step, TOTAL_STEPS, &active.phase.label(), true);
    let _ = write!(stderr, "\r\x1b[2K{text}");
    let _ = stderr.flush();
    *spinner_on_screen = true;
}

/// ANSI SGR codes used only when `color` is true.
mod ansi {
    pub(super) const RESET: &str = "\x1b[0m";
    pub(super) const CYAN: &str = "\x1b[36m";
    pub(super) const GREEN: &str = "\x1b[32m";
    pub(super) const RED: &str = "\x1b[1;31m";
    pub(super) const DIM: &str = "\x1b[2m";
}

fn paint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("{code}{text}{}", ansi::RESET)
    } else {
        text.to_owned()
    }
}

/// The in-progress line for one step: a spinner frame, `[n/total]`, and the
/// phase's own label from [`Phase::label`]. No trailing newline — the caller
/// overwrites this line in place until the phase finishes.
fn spinner_line(frame: char, step: u8, total: u8, label: &str, color: bool) -> String {
    format!(
        "  {} {} {label}",
        paint(&frame.to_string(), ansi::CYAN, color),
        paint(&format!("[{step}/{total}]"), ansi::DIM, color),
    )
}

/// The line a step becomes once it finishes.
fn done_line(step: u8, total: u8, label: &str, color: bool) -> String {
    format!(
        "  {} {} {label}",
        paint("✓", ansi::GREEN, color),
        paint(&format!("[{step}/{total}]"), ansi::DIM, color),
    )
}

/// An inline finding, nested under the step it was found during.
fn found_line(category: &str, title: &str, location: &str, color: bool) -> String {
    format!(
        "      {} {:<6} {title}    {}",
        paint("\u{21b3}", ansi::DIM, color),
        paint(category, ansi::CYAN, color),
        paint(location, ansi::DIM, color),
    )
}

/// The one line stderr gets: how many defects, and the shape of them.
///
/// Printed only where stdout is not already carrying the verdict — see
/// [`summary_enabled`].
fn summary_block(report: &Report, color: bool) -> String {
    let defects: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.kind == Kind::Defect)
        .collect();

    let mut out = String::new();

    if defects.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            paint("\u{2713} No defects found", ansi::GREEN, color)
        );
        return out;
    }

    // One line, not a list. Where this prints, stdout is holding JSON, SARIF,
    // or a file — a reader wants to know whether to go and look, not to read
    // the report twice in two formats. The severity shape is what decides
    // that.
    let mut counts = [0_usize; 4];
    for finding in &defects {
        let slot = match finding.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        };
        counts[slot] += 1;
    }
    let spread: Vec<String> = ["critical", "high", "medium", "low"]
        .iter()
        .zip(counts)
        .filter(|(_, n)| *n > 0)
        .map(|(label, n)| format!("{n} {label}"))
        .collect();

    let heading = format!(
        "\u{2716} {} found ({})",
        plural(defects.len(), "defect", "defects"),
        spread.join(", ")
    );
    let _ = writeln!(out, "{}", paint(&heading, ansi::RED, color));

    out
}

/// `"1 defect"`, `"3 defects"`.
fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("{count} {one}")
    } else {
        format!("{count} {many}")
    }
}

#[cfg(test)]
mod tests {
    use bastyn_core::{Category, Confidence, Location, Severity};

    use super::{
        Format, ProgressInputs, SPINNER_FRAMES, SummaryInputs, done_line, found_line, plural,
        progress_enabled, spinner_line, step_number, summary_block, summary_color, summary_enabled,
    };

    fn baseline() -> ProgressInputs {
        ProgressInputs {
            quiet: false,
            no_color_flag: false,
            no_color_env: false,
            format: Format::Text,
            stderr_is_tty: true,
        }
    }

    #[test]
    fn progress_is_enabled_when_every_condition_is_favourable() {
        assert!(progress_enabled(baseline()));
    }

    #[test]
    fn quiet_suppresses_progress() {
        let inputs = ProgressInputs {
            quiet: true,
            ..baseline()
        };
        assert!(!progress_enabled(inputs));
    }

    #[test]
    fn no_color_flag_suppresses_progress() {
        let inputs = ProgressInputs {
            no_color_flag: true,
            ..baseline()
        };
        assert!(!progress_enabled(inputs));
    }

    #[test]
    fn no_color_env_suppresses_progress() {
        let inputs = ProgressInputs {
            no_color_env: true,
            ..baseline()
        };
        assert!(!progress_enabled(inputs));
    }

    #[test]
    fn json_format_suppresses_progress() {
        let inputs = ProgressInputs {
            format: Format::Json,
            ..baseline()
        };
        assert!(!progress_enabled(inputs));
    }

    #[test]
    fn sarif_format_suppresses_progress() {
        let inputs = ProgressInputs {
            format: Format::Sarif,
            ..baseline()
        };
        assert!(!progress_enabled(inputs));
    }

    #[test]
    fn no_tty_suppresses_progress() {
        let inputs = ProgressInputs {
            stderr_is_tty: false,
            ..baseline()
        };
        assert!(!progress_enabled(inputs));
    }

    #[test]
    fn spinner_frames_cycle_through_all_ten_and_wrap() {
        assert_eq!(SPINNER_FRAMES.len(), 10);
        let sequence: Vec<char> = (0..13).map(|tick| SPINNER_FRAMES[tick % 10]).collect();
        assert_eq!(sequence[0], SPINNER_FRAMES[0]);
        assert_eq!(sequence[9], SPINNER_FRAMES[9]);
        assert_eq!(
            sequence[10], SPINNER_FRAMES[0],
            "the sequence must wrap back to the first frame"
        );
        assert_eq!(sequence[12], SPINNER_FRAMES[2]);
    }

    #[test]
    fn spinner_line_without_color_carries_no_escape_byte() {
        let text = spinner_line(
            '\u{280b}',
            2,
            5,
            "Parsing Python (tree-sitter) — 12 files",
            false,
        );
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("[2/5]"));
        assert!(text.contains("Parsing Python (tree-sitter) — 12 files"));
    }

    #[test]
    fn done_line_shows_a_checkmark_and_the_label() {
        let text = done_line(3, 5, "Matching rules (ast-grep) — 8 rules", false);
        assert!(text.contains('\u{2713}'));
        assert!(text.contains("[3/5]"));
        assert!(text.contains("Matching rules (ast-grep) — 8 rules"));
    }

    #[test]
    fn found_line_carries_category_title_and_location() {
        let text = found_line(
            "LLM10",
            "Model output concatenated into SQL",
            "tools.py:214",
            false,
        );
        assert!(text.contains("LLM10"));
        assert!(text.contains("Model output concatenated into SQL"));
        assert!(text.contains("tools.py:214"));
    }

    #[test]
    fn step_numbers_match_the_documented_sequence() {
        assert_eq!(step_number(&bastyn_core::Phase::Walking), Some(1));
        assert_eq!(
            step_number(&bastyn_core::Phase::Analysing {
                files: 1,
                rules: 8,
                mcp_configs: 0,
            }),
            Some(2)
        );
        assert_eq!(
            step_number(&bastyn_core::Phase::Cve { dependencies: 0 }),
            Some(3)
        );
        assert_eq!(step_number(&bastyn_core::Phase::Reporting), Some(4));
    }

    /// The interactive text run: stdout already says `RESULT: FAILED` and the
    /// severity spread three lines above where this would land.
    fn text_on_a_terminal() -> SummaryInputs {
        SummaryInputs {
            quiet: false,
            no_color_flag: false,
            no_color_env: false,
            format: Format::Text,
            stdout_is_tty: true,
            stderr_is_tty: true,
        }
    }

    #[test]
    fn the_summary_is_silent_where_the_report_already_says_it() {
        assert!(
            !summary_enabled(text_on_a_terminal()),
            "a text report on a terminal must not be summarised twice"
        );
    }

    /// The regression this rule exists for: `--format json > out.json`
    /// rendered no text report at all, so nothing told the user what happened.
    #[test]
    fn the_summary_speaks_wherever_stdout_is_not_the_verdict() {
        for format in [Format::Json, Format::Sarif] {
            assert!(
                summary_enabled(SummaryInputs {
                    format,
                    ..text_on_a_terminal()
                }),
                "{format:?} renders no report, so stderr is the only thing that can speak"
            );
        }

        assert!(
            summary_enabled(SummaryInputs {
                stdout_is_tty: false,
                ..text_on_a_terminal()
            }),
            "a text report redirected into a file leaves the terminal silent"
        );
    }

    /// `--quiet` already prints the summary, on stdout. A second copy on
    /// stderr is what it asked not to have.
    #[test]
    fn quiet_silences_the_summary_in_every_format() {
        for format in [Format::Text, Format::Json, Format::Sarif] {
            for stdout_is_tty in [true, false] {
                assert!(
                    !summary_enabled(SummaryInputs {
                        quiet: true,
                        format,
                        stdout_is_tty,
                        ..text_on_a_terminal()
                    }),
                    "--quiet must silence {format:?} (tty: {stdout_is_tty})"
                );
            }
        }
    }

    /// Colour is how it renders, never whether it speaks — unlike the spinner,
    /// whose escape sequences would corrupt a captured log.
    #[test]
    fn no_color_and_a_piped_stderr_change_the_rendering_not_the_decision() {
        let piped = SummaryInputs {
            format: Format::Json,
            stderr_is_tty: false,
            ..text_on_a_terminal()
        };
        assert!(summary_enabled(piped), "a CI log is a place this belongs");
        assert!(!summary_color(piped));

        for suppressed in [
            SummaryInputs {
                no_color_flag: true,
                format: Format::Json,
                ..text_on_a_terminal()
            },
            SummaryInputs {
                no_color_env: true,
                format: Format::Json,
                ..text_on_a_terminal()
            },
        ] {
            assert!(summary_enabled(suppressed));
            assert!(!summary_color(suppressed));
        }

        assert!(summary_color(SummaryInputs {
            format: Format::Json,
            ..text_on_a_terminal()
        }));
    }

    /// The two decisions are independent, and the machine formats are where
    /// they disagree: no spinner, because stdout is a contract; a summary,
    /// because nothing else will say anything.
    #[test]
    fn the_spinner_and_the_summary_are_not_the_same_question() {
        let json = SummaryInputs {
            format: Format::Json,
            ..text_on_a_terminal()
        };
        assert!(!progress_enabled(ProgressInputs {
            quiet: json.quiet,
            no_color_flag: json.no_color_flag,
            no_color_env: json.no_color_env,
            format: json.format,
            stderr_is_tty: json.stderr_is_tty,
        }));
        assert!(summary_enabled(json));
    }

    #[test]
    fn plural_is_regular_except_where_told_otherwise() {
        assert_eq!(plural(0, "defect", "defects"), "0 defects");
        assert_eq!(plural(1, "defect", "defects"), "1 defect");
        assert_eq!(plural(2, "defect", "defects"), "2 defects");
    }

    fn finding(rule: &str, title: &str, category: Category) -> Finding {
        Finding {
            rule_id: rule.to_owned(),
            title: title.to_owned(),
            kind: Kind::Defect,
            severity: Severity::Critical,
            confidence: Confidence::High,
            categories: vec![category],
            location: Location {
                file: "tools.py".into(),
                line: 214,
                column: 1,
            },
            snippet: String::new(),
            description: String::new(),
            remediation: String::new(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        }
    }

    use bastyn_core::CveStatus;
    use bastyn_core::{Finding, Kind, Report, Summary};

    /// A report carrying one defect per `(severity, title)` pair.
    fn report_with_defects(defects: &[(Severity, &str)]) -> Report {
        let findings = defects
            .iter()
            .map(|(severity, title)| {
                let mut f = finding("BAS-TEST-001", title, Category::Llm10);
                f.severity = *severity;
                f
            })
            .collect();
        report_with(findings)
    }

    fn report_with(findings: Vec<Finding>) -> Report {
        Report {
            bastyn_version: "0.0.0".to_owned(),
            root: ".".to_owned(),
            summary: Summary {
                files_scanned: 1,
                files_skipped: 0,
                defects: findings.len(),
                observations: 0,
            },
            cve: CveStatus::SkippedOffline,
            findings,
            skipped: Vec::new(),
            coverage: bastyn_core::Coverage::default(),
            crosswalks: Vec::new(),
        }
    }

    #[test]
    fn summary_block_shows_a_checkmark_when_there_are_no_defects() {
        let text = summary_block(&report_with(Vec::new()), false);
        assert!(text.contains('\u{2713}'));
        assert!(text.contains("No defects found"));
    }

    #[test]
    fn summary_is_one_line_with_the_severity_spread() {
        // Deliberately not a list. The report sits immediately above this on
        // the same screen, so repeating the findings makes a reader reconcile
        // two lists instead of acting on one. The severity shape is the thing
        // the report cannot show at a glance.
        let report = report_with_defects(&[
            (Severity::Critical, "One"),
            (Severity::High, "Two"),
            (Severity::High, "Three"),
        ]);

        let text = summary_block(&report, false);

        assert_eq!(text.lines().count(), 1, "must be a single line: {text:?}");
        assert!(text.contains("3 defects found"), "{text}");
        assert!(text.contains("1 critical"), "{text}");
        assert!(text.contains("2 high"), "{text}");
        assert!(!text.contains("One"), "titles belong in the report: {text}");
    }

    #[test]
    fn summary_is_singular_for_one_defect() {
        let report = report_with_defects(&[(Severity::High, "Only")]);

        let text = summary_block(&report, false);

        assert!(text.contains("1 defect found"), "{text}");
        assert!(!text.contains("1 defects"), "{text}");
    }
}
