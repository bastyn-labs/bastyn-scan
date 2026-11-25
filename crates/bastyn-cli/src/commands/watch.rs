//! `bastyn --watch`: continuous watching of skill and instruction files.
//!
//! The analysis, the retry rules and the delivery all live in
//! [`bastyn_core::watch`]. This module wires them to the terminal and to the
//! process: it checks the arguments, renders events, and keeps the process
//! alive.
//!
//! # Two processes
//!
//! Release builds abort on a panic, so a bug that panics would end a watcher
//! that is meant to run for days. The command therefore runs twice. Started
//! normally it is a *supervisor* that starts itself again as a *worker* (the
//! same executable and arguments, with `BASTYN_WATCH_WORKER` set) and waits.
//! The worker does the watching. When it stops abnormally the supervisor
//! starts a new one after a growing pause. Alerts that were delivered are
//! remembered on disk by the core, so a new worker does not send them again.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bastyn_core::Severity;
use bastyn_core::reporting::upload::ThreadSleeper;
use bastyn_core::watch::{
    Alert, DeliverOutcome, Event, FsSource, OpenClawReporter, ReportUrl, Reporter, SeenStore,
    WatchConfig, Watcher, run as run_watcher,
};

use crate::cli::{GlobalArgs, Reporter as ReporterKind, WatchArgs};
use crate::exit;
use crate::terminal::{TerminalInputs, color_decision};

/// Set in the worker's environment by the supervisor.
const WORKER_ENV: &str = "BASTYN_WATCH_WORKER";

/// The environment variable the webhook token is read from.
const TOKEN_ENV: &str = "BASTYN_OPENCLAW_TOKEN";

/// The first pause before a worker is restarted.
const RESTART_MIN: Duration = Duration::from_secs(1);

/// The longest pause before a worker is restarted.
const RESTART_MAX: Duration = Duration::from_secs(30);

/// A worker that ran at least this long starts the pauses over.
const HEALTHY_RUN: Duration = Duration::from_secs(60);

/// Runs watch mode: the supervisor, or the worker when the supervisor started
/// this process.
pub(crate) fn run(args: &WatchArgs, global: &GlobalArgs) -> anyhow::Result<u8> {
    if std::env::var_os(WORKER_ENV).is_some() {
        worker(args, global)
    } else {
        supervise()
    }
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// What the supervisor does about a worker that ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Exit with this code.
    Stop(u8),
    /// Start another worker.
    Restart,
}

/// Starts workers until one ends in a way that should not be retried.
fn supervise() -> anyhow::Result<u8> {
    let exe = std::env::current_exe().context("could not find the bastyn executable")?;
    let mut pause = RESTART_MIN;
    loop {
        let started = Instant::now();
        let status = Command::new(&exe)
            .args(std::env::args_os().skip(1))
            .env(WORKER_ENV, "1")
            .spawn()
            .context("could not start the watch worker")?
            .wait()
            .context("could not wait for the watch worker")?;
        match verdict(status) {
            Verdict::Stop(code) => return Ok(code),
            Verdict::Restart => {}
        }
        if started.elapsed() >= HEALTHY_RUN {
            pause = RESTART_MIN;
        }
        let mut stderr = std::io::stderr().lock();
        // If stderr is gone nobody is reading; the restart goes ahead anyway.
        let _ = writeln!(
            stderr,
            "bastyn: watch worker stopped ({status}); restarting in {}s",
            pause.as_secs()
        );
        drop(stderr);
        std::thread::sleep(pause);
        pause = (pause * 2).min(RESTART_MAX);
    }
}

/// Decides what a worker's end means.
///
/// A clean end and a startup or usage error (code 2) are final: restarting
/// would only repeat them. A stop by a terminal or a termination signal is the
/// user's doing and is passed on as the shell would see it. Anything else (an
/// abort, a panic exit, a kill by the system) is a crash.
fn verdict(status: ExitStatus) -> Verdict {
    match status.code() {
        Some(0) => return Verdict::Stop(exit::CLEAN),
        Some(code) if code == i32::from(exit::EXECUTION_ERROR) => {
            return Verdict::Stop(exit::EXECUTION_ERROR);
        }
        _ => {}
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        // SIGHUP, SIGINT, SIGTERM.
        if let Some(signal @ (1 | 2 | 15)) = status.signal() {
            return Verdict::Stop(128 + u8::try_from(signal).unwrap_or(0));
        }
    }
    Verdict::Restart
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// Watches until the process is stopped.
fn worker(args: &WatchArgs, global: &GlobalArgs) -> anyhow::Result<u8> {
    let Some(root) = args.watch.as_deref() else {
        anyhow::bail!("--watch needs a directory");
    };
    check_root(root)?;
    let reporter = build_reporter(args)?;

    let config = tuned(WatchConfig::new(root.to_path_buf()));

    let color = color_decision(TerminalInputs::gathered(global));
    announce(
        root,
        args.report_url.as_deref().filter(|_| reporter.is_some()),
    );

    let env = |name: &str| std::env::var_os(name);
    let seen = if reporter.is_some() {
        SeenStore::for_root(root, &env)
    } else {
        // Nothing is delivered in terminal-only mode, so nothing may be
        // recorded as delivered: a later run with a reporter must still send
        // everything.
        SeenStore::in_memory()
    };

    let mut watcher = Watcher::new(config.clone(), seen);
    let renderer = RefCell::new(Renderer::new(color, reporter.is_some(), &config));
    let output_closed = Cell::new(false);
    #[cfg(feature = "test-endpoint")]
    let delivered = Cell::new(false);
    let parent = parent_pid();

    let mut emit = |event: Event| {
        #[cfg(feature = "test-endpoint")]
        if matches!(event, Event::Delivered { .. }) {
            delivered.set(true);
        }
        for line in renderer.borrow_mut().render(&event) {
            if line.write().is_err() {
                output_closed.set(true);
            }
        }
    };
    let stop = || {
        #[cfg(feature = "test-endpoint")]
        if delivered.get() {
            hooks::crash_once();
        }
        output_closed.get() || supervisor_gone(parent)
    };

    let none = NoReporter;
    let reporter_ref: &dyn Reporter = match &reporter {
        Some(reporter) => reporter,
        None => &none,
    };
    run_watcher(
        &mut watcher,
        &FsSource,
        reporter_ref,
        &mut emit,
        &ThreadSleeper,
        &stop,
    );
    Ok(exit::CLEAN)
}

/// Fails unless `root` is an existing directory.
fn check_root(root: &Path) -> anyhow::Result<()> {
    let metadata =
        std::fs::metadata(root).with_context(|| format!("cannot watch {}", root.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "cannot watch {}: not a directory",
        root.display()
    );
    Ok(())
}

/// The reporter the arguments ask for, or `None` for terminal-only watching.
fn build_reporter(args: &WatchArgs) -> anyhow::Result<Option<OpenClawReporter>> {
    let Some(ReporterKind::Openclaw) = args.reporter else {
        return Ok(None);
    };
    let url = args
        .report_url
        .as_deref()
        .context("--reporter needs --report-url")?;
    let url = ReportUrl::parse(url).context("invalid --report-url")?;
    let token = std::env::var_os(TOKEN_ENV)
        .with_context(|| format!("{TOKEN_ENV} is not set; --reporter openclaw needs it"))?
        .into_string()
        .map_err(|_| anyhow::anyhow!("{TOKEN_ENV} is not valid text"))?;
    let reporter = OpenClawReporter::new(&url, token, args.openclaw_agent_id.clone())
        .with_context(|| format!("cannot use {TOKEN_ENV} or --openclaw-agent-id"))?;
    Ok(Some(reporter))
}

/// Prints the startup line. Only the host and port of the report URL are
/// shown: the path of a webhook can be a credential.
fn announce(root: &Path, report_url: Option<&str>) {
    let mut line = format!("bastyn: watching {}", root.display());
    if let Some(url) = report_url {
        line = format!("{line}, reporting to {} via openclaw", host_port(url));
    }
    line.push('\n');
    let _ = Output::stderr(line).write();
}

/// The `host:port` part of a URL, without scheme, path or query.
fn host_port(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

/// The process id of whoever started this process.
#[cfg(unix)]
fn parent_pid() -> u32 {
    std::os::unix::process::parent_id()
}

#[cfg(not(unix))]
fn parent_pid() -> u32 {
    0
}

/// Whether the parent has changed since start, which means the supervisor
/// died and this worker was adopted by another process. On other platforms
/// the check does not exist.
#[cfg(unix)]
fn supervisor_gone(original: u32) -> bool {
    std::os::unix::process::parent_id() != original
}

#[cfg(not(unix))]
fn supervisor_gone(_original: u32) -> bool {
    false
}

/// The reporter of terminal-only watching: it takes every alert, so the
/// watcher never queues or retries anything.
struct NoReporter;

impl Reporter for NoReporter {
    fn deliver(&self, _alert: &Alert) -> DeliverOutcome {
        DeliverOutcome::Delivered
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

/// Text for one of the two streams.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Output {
    to_stderr: bool,
    text: String,
}

impl Output {
    fn stdout(text: String) -> Self {
        Self {
            to_stderr: false,
            text,
        }
    }

    fn stderr(text: String) -> Self {
        Self {
            to_stderr: true,
            text,
        }
    }

    /// Writes and flushes. An error means the stream is closed.
    fn write(&self) -> std::io::Result<()> {
        if self.to_stderr {
            let mut stream = std::io::stderr().lock();
            write!(stream, "{}", self.text)?;
            stream.flush()
        } else {
            let mut stream = std::io::stdout().lock();
            write!(stream, "{}", self.text)?;
            stream.flush()
        }
    }
}

/// Turns events into text. Everything it prints from the scanned tree has
/// already been sanitised by the core.
#[derive(Debug)]
struct Renderer {
    color: bool,
    /// Whether anything is being delivered; terminal-only watching has no
    /// delivery events worth showing.
    reporting: bool,
    /// Attempts in one delivery cycle, the first included.
    attempts: u32,
    cooldown: Duration,
    /// For each raised alert not yet settled, `rule path:line`, so a delivery
    /// message can say which alert it is about.
    labels: BTreeMap<String, String>,
}

impl Renderer {
    fn new(color: bool, reporting: bool, config: &WatchConfig) -> Self {
        Self {
            color,
            reporting,
            attempts: config.retry.retries.saturating_add(1),
            cooldown: config.retry.cooldown,
            labels: BTreeMap::new(),
        }
    }

    fn label(&self, key: &str) -> String {
        self.labels
            .get(key)
            .cloned()
            .unwrap_or_else(|| "an alert".to_owned())
    }

    fn render(&mut self, event: &Event) -> Vec<Output> {
        match event {
            Event::Found(alert) => {
                self.labels.insert(
                    alert.key.clone(),
                    format!("{} {}:{}", alert.rule_id, alert.path, alert.line),
                );
                let text = format!(
                    "ALERT {} {} {}:{} {}\n  {}\n",
                    alert.rule_id,
                    severity_word(alert.severity),
                    alert.path,
                    alert.line,
                    alert.title,
                    alert.snippet,
                );
                let text = if self.color {
                    format!("{RED}{text}{RESET}")
                } else {
                    text
                };
                vec![Output::stdout(text)]
            }
            Event::Delivered { key } => {
                let label = self.labels.remove(key);
                if !self.reporting {
                    return Vec::new();
                }
                let label = label.unwrap_or_else(|| "an alert".to_owned());
                vec![Output::stderr(format!("bastyn: delivered {label}\n"))]
            }
            Event::DeliveryRetrying { key, attempt, wait } => vec![Output::stderr(format!(
                "bastyn: delivery attempt {attempt} failed, retrying in {}: {}\n",
                duration_text(*wait),
                self.label(key),
            ))],
            Event::DeliveryFailed {
                key,
                reason,
                will_retry,
            } => {
                let label = self.label(key);
                if *will_retry {
                    vec![Output::stderr(format!(
                        "bastyn: delivery failed after {} attempts (will retry in {}): {label} ({reason})\n",
                        self.attempts,
                        duration_text(self.cooldown),
                    ))]
                } else {
                    self.labels.remove(key);
                    vec![Output::stderr(format!(
                        "bastyn: delivery failed, alert dropped: {label} ({reason})\n"
                    ))]
                }
            }
            Event::ScanFailed { reason } => {
                vec![Output::stderr(format!("bastyn: scan failed: {reason}\n"))]
            }
            Event::QueueOverflow { dropped } => vec![Output::stderr(format!(
                "bastyn: {dropped} alert(s) dropped because the delivery queue is full\n"
            ))],
            Event::StateWriteFailed { reason } => vec![Output::stderr(format!(
                "bastyn: could not save delivered alerts ({reason}); a restart may send them again\n"
            ))],
        }
    }
}

fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// `250ms` below a second, whole seconds from there.
fn duration_text(duration: Duration) -> String {
    if duration < Duration::from_secs(1) {
        format!("{}ms", duration.as_millis())
    } else {
        format!("{}s", duration.as_secs())
    }
}

// ---------------------------------------------------------------------------
// Test hooks
// ---------------------------------------------------------------------------

/// The configuration with the test timing overrides applied. Without the
/// `test-endpoint` feature it is returned unchanged.
#[cfg(feature = "test-endpoint")]
fn tuned(mut config: WatchConfig) -> WatchConfig {
    hooks::apply(&mut config);
    config
}

#[cfg(not(feature = "test-endpoint"))]
const fn tuned(config: WatchConfig) -> WatchConfig {
    config
}

/// Environment hooks that let the integration tests run fast and crash the
/// worker on purpose. They exist only in a build with the `test-endpoint`
/// feature, which release builds do not enable.
#[cfg(feature = "test-endpoint")]
mod hooks {
    use std::time::Duration;

    use bastyn_core::watch::WatchConfig;

    fn millis(name: &str) -> Option<Duration> {
        std::env::var(name)
            .ok()?
            .parse::<u64>()
            .ok()
            .map(Duration::from_millis)
    }

    /// Applies the interval and retry timing overrides.
    pub(super) fn apply(config: &mut WatchConfig) {
        if let Some(interval) = millis("BASTYN_WATCH_INTERVAL_MS_FOR_TESTS") {
            config.interval = interval;
        }
        if let Some(wait) = millis("BASTYN_WATCH_RETRY_MS_FOR_TESTS") {
            config.retry.backoff = vec![wait; 3];
            config.retry.cooldown = wait * 4;
        }
    }

    /// Aborts the process once: when the marker file named by
    /// `BASTYN_WATCH_CRASH_ONCE_FOR_TESTS` does not exist yet, it is created
    /// and the process aborts.
    pub(super) fn crash_once() {
        let Some(path) = std::env::var_os("BASTYN_WATCH_CRASH_ONCE_FOR_TESTS") else {
            return;
        };
        if std::path::Path::new(&path).exists() {
            return;
        }
        if std::fs::write(&path, b"crashed").is_ok() {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RED, RESET, Renderer, Verdict, duration_text, host_port, severity_word};
    use bastyn_core::Severity;
    use bastyn_core::watch::{Alert, Event, WatchConfig};
    use std::path::PathBuf;
    use std::time::Duration;

    fn alert() -> Alert {
        Alert {
            key: "k".repeat(64),
            rule_id: "BAS-SKILL-013".to_owned(),
            severity: Severity::High,
            title: "Destructive instruction".to_owned(),
            path: "skills/x/SKILL.md".to_owned(),
            line: 7,
            snippet: "delete all the files".to_owned(),
        }
    }

    fn renderer(color: bool, reporting: bool) -> Renderer {
        Renderer::new(color, reporting, &WatchConfig::new(PathBuf::from(".")))
    }

    #[test]
    fn a_found_alert_is_red_only_when_colour_is_on() {
        let plain = renderer(false, true).render(&Event::Found(alert()));
        assert_eq!(plain.len(), 1);
        assert!(!plain[0].to_stderr);
        assert_eq!(
            plain[0].text,
            "ALERT BAS-SKILL-013 high skills/x/SKILL.md:7 Destructive instruction\n  delete all the files\n"
        );

        let coloured = renderer(true, true).render(&Event::Found(alert()));
        assert_eq!(coloured[0].text, format!("{RED}{}{RESET}", plain[0].text));
    }

    #[test]
    fn delivery_messages_name_the_alert_and_go_to_stderr() {
        let mut renderer = renderer(false, true);
        let alert = alert();
        let key = alert.key.clone();
        renderer.render(&Event::Found(alert));

        let failed = renderer.render(&Event::DeliveryFailed {
            key: key.clone(),
            reason: "HTTP 503".to_owned(),
            will_retry: true,
        });
        assert!(failed[0].to_stderr);
        assert_eq!(
            failed[0].text,
            "bastyn: delivery failed after 4 attempts (will retry in 60s): BAS-SKILL-013 skills/x/SKILL.md:7 (HTTP 503)\n"
        );

        let done = renderer.render(&Event::Delivered { key });
        assert_eq!(
            done[0].text,
            "bastyn: delivered BAS-SKILL-013 skills/x/SKILL.md:7\n"
        );
    }

    #[test]
    fn terminal_only_watching_is_silent_about_delivery() {
        let mut renderer = renderer(false, false);
        let alert = alert();
        let key = alert.key.clone();
        renderer.render(&Event::Found(alert));
        assert_eq!(renderer.render(&Event::Delivered { key }), Vec::new());
    }

    #[test]
    fn small_helpers() {
        assert_eq!(
            host_port("http://127.0.0.1:18789/hooks/agent?t=1"),
            "127.0.0.1:18789"
        );
        assert_eq!(host_port("https://example.com/secret"), "example.com");
        assert_eq!(duration_text(Duration::from_millis(250)), "250ms");
        assert_eq!(duration_text(Duration::from_secs(8)), "8s");
        assert_eq!(severity_word(Severity::Critical), "critical");
    }

    #[cfg(unix)]
    #[test]
    fn the_supervisor_restarts_only_after_a_crash() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::ExitStatus;
        let exited = |code: i32| ExitStatus::from_raw(code << 8);
        let signalled = |signal: i32| ExitStatus::from_raw(signal);
        assert_eq!(super::verdict(exited(0)), Verdict::Stop(0));
        assert_eq!(super::verdict(exited(2)), Verdict::Stop(2));
        assert_eq!(super::verdict(exited(101)), Verdict::Restart);
        assert_eq!(super::verdict(signalled(6)), Verdict::Restart);
        assert_eq!(super::verdict(signalled(9)), Verdict::Restart);
        assert_eq!(super::verdict(signalled(2)), Verdict::Stop(130));
        assert_eq!(super::verdict(signalled(15)), Verdict::Stop(143));
    }
}
