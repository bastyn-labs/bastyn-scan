//! Continuous watching of skill and instruction files.
//!
//! A [`Watcher`] is a state machine that is driven one [`tick`](Watcher::tick)
//! at a time. A tick fingerprints the watched files, scans them when they
//! changed and have stopped changing, raises an [`Alert`] for each reportable
//! finding it has not seen before, and makes one delivery attempt for every
//! alert that is due. It never blocks: it returns how long the caller should
//! wait before the next tick. The file system, the destination and the clock
//! are all passed in, so the whole machine is tested without real time.
//! [`run`] is the loop the command line uses.
//!
//! What is watched is deliberately narrow: skill manifests, the text files of
//! a skill and agent instruction files, scanned by [`scan_watched`] for
//! defects and high-severity findings. See [`scan_watched`] for the details.
//!
//! # Rules the watcher keeps
//!
//! - A change is acted on only when two consecutive ticks saw the same
//!   fingerprints (so a half-written file is not scanned) and they differ from
//!   the last scanned ones. The first tick counts as settled. Fingerprints use
//!   file content, not modification time.
//! - An alert is identified by [`Alert::key`], which ignores the line number.
//!   Each key is reported once per run, even if the finding goes away and
//!   comes back, and is never reported again after it was delivered in an
//!   earlier run (see [`SeenStore`]).
//! - A temporary failure is retried: one first attempt and then three
//!   retries after the [`RetryPolicy::backoff`] waits (or the destination's
//!   `Retry-After`, if longer). After that the alert waits out
//!   [`RetryPolicy::cooldown`] and the cycle starts again. A permanent
//!   failure drops the alert for this run.

mod alert;
mod openclaw;
mod reporter;
mod scan;
mod seen;

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::reporting::upload::Sleeper;

pub use alert::{Alert, sanitize};
pub use openclaw::{
    HookTransport, OpenClawError, OpenClawReporter, ReportUrl, ReportUrlError, UreqHookTransport,
};
pub use reporter::{DeliverOutcome, Reporter};
pub use scan::{FileKind, Fingerprints, FsSource, Source, scan_watched};
pub use seen::{MAX_SEEN_KEYS, SeenStore};

/// The longest wait after consecutive scan failures.
const MAX_FAILURE_WAIT: Duration = Duration::from_secs(60);

/// The longest single sleep in [`run`], so a stop request is noticed quickly.
const SLEEP_SLICE: Duration = Duration::from_millis(250);

/// How failed deliveries are retried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Retries after the first attempt.
    pub retries: u32,
    /// The wait before each retry, in order. The last value is reused if
    /// there are more retries than values.
    pub backoff: Vec<Duration>,
    /// The wait after the first attempt and all retries failed, before the
    /// cycle starts again.
    pub cooldown: Duration,
    /// The most undelivered alerts held. Beyond it the oldest is dropped.
    pub queue_cap: usize,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            retries: 3,
            backoff: vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
            ],
            cooldown: Duration::from_secs(60),
            queue_cap: 1000,
        }
    }
}

/// What a [`Watcher`] watches and how it paces itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchConfig {
    /// The directory to watch.
    pub root: PathBuf,
    /// The time between ticks when all is well.
    pub interval: Duration,
    /// How failed deliveries are retried.
    pub retry: RetryPolicy,
}

impl WatchConfig {
    /// A configuration for `root` with a 2 second interval and the default
    /// [`RetryPolicy`].
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            interval: Duration::from_secs(2),
            retry: RetryPolicy::default(),
        }
    }
}

/// Something the watcher wants the caller to know. Text in an event comes from
/// the scanned tree only through [`Alert`], whose fields are sanitised, and
/// never includes a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A reportable finding appeared for the first time: show it.
    Found(Alert),
    /// The alert with this key was delivered.
    Delivered {
        /// The alert's key.
        key: String,
    },
    /// A delivery attempt failed and another will follow.
    DeliveryRetrying {
        /// The alert's key.
        key: String,
        /// How many attempts have failed so far in this cycle.
        attempt: u32,
        /// How long until the next attempt.
        wait: Duration,
    },
    /// A delivery cycle failed.
    DeliveryFailed {
        /// The alert's key.
        key: String,
        /// The last failure, in one line.
        reason: String,
        /// Whether the alert stays queued for another cycle after the
        /// cooldown. `false` means it was dropped.
        will_retry: bool,
    },
    /// A scan could not run. The watcher keeps going, with longer waits.
    ScanFailed {
        /// The failure, in one line.
        reason: String,
    },
    /// The queue was full and the oldest alerts were dropped.
    QueueOverflow {
        /// How many alerts were dropped.
        dropped: usize,
    },
    /// The delivered-alert file could not be written. Reported once; the
    /// watcher continues with memory only.
    StateWriteFailed {
        /// The failure, in one line.
        reason: String,
    },
}

/// An alert waiting for delivery.
#[derive(Debug)]
struct Pending {
    alert: Alert,
    /// Failed attempts in the current cycle.
    attempts: u32,
    next_at: Instant,
}

/// The watch state machine. See the [module documentation](self).
#[derive(Debug)]
pub struct Watcher {
    config: WatchConfig,
    seen: SeenStore,
    /// The snapshot of the previous tick.
    previous: Option<Fingerprints>,
    /// The snapshot that was last scanned.
    scanned: Option<Fingerprints>,
    /// Keys raised in this run, whether or not they were delivered.
    handled: BTreeSet<String>,
    pending: VecDeque<Pending>,
    failures: u32,
    state_failure_reported: bool,
}

impl Watcher {
    /// A watcher for `config` that skips every alert already in `seen`.
    #[must_use]
    pub fn new(config: WatchConfig, seen: SeenStore) -> Self {
        Self {
            config,
            seen,
            previous: None,
            scanned: None,
            handled: BTreeSet::new(),
            pending: VecDeque::new(),
            failures: 0,
            state_failure_reported: false,
        }
    }

    /// How many alerts are waiting for delivery.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Runs one step at time `now` and returns how long to wait before the
    /// next one.
    ///
    /// `source` supplies the tree, `reporter` takes the alerts and `emit`
    /// receives every [`Event`]. At most one delivery attempt is made per
    /// pending alert, and only for alerts that are due.
    pub fn tick(
        &mut self,
        now: Instant,
        source: &dyn Source,
        reporter: &dyn Reporter,
        emit: &mut dyn FnMut(Event),
    ) -> Duration {
        match self.refresh(now, source, emit) {
            Ok(()) => self.failures = 0,
            Err(reason) => {
                self.failures = self.failures.saturating_add(1);
                emit(Event::ScanFailed { reason });
            }
        }
        self.deliver_due(now, reporter, emit);

        let base = if self.failures == 0 {
            self.config.interval
        } else {
            let factor = 1u32.checked_shl(self.failures).unwrap_or(u32::MAX);
            self.config
                .interval
                .saturating_mul(factor)
                .min(MAX_FAILURE_WAIT)
                .max(self.config.interval)
        };
        match self.pending.iter().map(|p| p.next_at).min() {
            Some(next) => base.min(next.saturating_duration_since(now)),
            None => base,
        }
    }

    /// Fingerprints the tree and, when it is settled and changed, scans it.
    /// The error is the text of the failure.
    fn refresh(
        &mut self,
        now: Instant,
        source: &dyn Source,
        emit: &mut dyn FnMut(Event),
    ) -> Result<(), String> {
        let snapshot = source
            .snapshot(&self.config.root)
            .map_err(|e| sanitize(&e.to_string()))?;
        let settled = self.previous.as_ref().is_none_or(|p| *p == snapshot);
        self.previous = Some(snapshot.clone());
        if !settled || self.scanned.as_ref() == Some(&snapshot) {
            return Ok(());
        }
        let findings = source
            .scan(&self.config.root)
            .map_err(|e| sanitize(&e.to_string()))?;
        self.scanned = Some(snapshot);

        let mut dropped = 0;
        for finding in &findings {
            let alert = Alert::from_finding(finding);
            if !self.handled.insert(alert.key.clone()) || self.seen.contains(&alert.key) {
                continue;
            }
            emit(Event::Found(alert.clone()));
            if self.pending.len() >= self.config.retry.queue_cap.max(1) {
                self.pending.pop_front();
                dropped += 1;
            }
            self.pending.push_back(Pending {
                alert,
                attempts: 0,
                next_at: now,
            });
        }
        if dropped > 0 {
            emit(Event::QueueOverflow { dropped });
        }
        Ok(())
    }

    /// One attempt for each pending alert whose time has come.
    fn deliver_due(&mut self, now: Instant, reporter: &dyn Reporter, emit: &mut dyn FnMut(Event)) {
        let queue = std::mem::take(&mut self.pending);
        let mut keep = VecDeque::with_capacity(queue.len());
        for mut item in queue {
            if item.next_at > now {
                keep.push_back(item);
                continue;
            }
            match reporter.deliver(&item.alert) {
                DeliverOutcome::Delivered => {
                    let key = item.alert.key;
                    if let Err(error) = self.seen.insert(&key)
                        && !self.state_failure_reported
                    {
                        self.state_failure_reported = true;
                        emit(Event::StateWriteFailed {
                            reason: sanitize(&error.to_string()),
                        });
                    }
                    emit(Event::Delivered { key });
                }
                DeliverOutcome::Retry { after, reason } => {
                    let policy = &self.config.retry;
                    item.attempts += 1;
                    let key = item.alert.key.clone();
                    if item.attempts <= policy.retries {
                        let index = usize::try_from(item.attempts - 1).unwrap_or(usize::MAX);
                        let scheduled = policy
                            .backoff
                            .get(index)
                            .or(policy.backoff.last())
                            .copied()
                            .unwrap_or(policy.cooldown);
                        let wait = scheduled.max(after.unwrap_or_default());
                        emit(Event::DeliveryRetrying {
                            key,
                            attempt: item.attempts,
                            wait,
                        });
                        item.next_at = now + wait;
                    } else {
                        emit(Event::DeliveryFailed {
                            key,
                            reason: sanitize(&reason),
                            will_retry: true,
                        });
                        item.attempts = 0;
                        item.next_at = now + policy.cooldown.max(after.unwrap_or_default());
                    }
                    keep.push_back(item);
                }
                DeliverOutcome::Fatal { reason } => emit(Event::DeliveryFailed {
                    key: item.alert.key,
                    reason: sanitize(&reason),
                    will_retry: false,
                }),
            }
        }
        // Alerts queued by `refresh` during this tick are already in `keep`
        // or were attempted; nothing is added to `self.pending` meanwhile.
        self.pending = keep;
    }
}

/// Ticks `watcher` until `stop` returns true, sleeping between ticks in
/// slices of at most 250 ms so a stop request is noticed promptly. `stop` is
/// checked before every tick and every slice; the command line passes
/// `|| false` and ends the process with a signal.
pub fn run(
    watcher: &mut Watcher,
    source: &dyn Source,
    reporter: &dyn Reporter,
    emit: &mut dyn FnMut(Event),
    sleeper: &dyn Sleeper,
    stop: &dyn Fn() -> bool,
) {
    run_with_clock(
        watcher,
        source,
        reporter,
        emit,
        sleeper,
        stop,
        &Instant::now,
    );
}

/// [`run`] with the clock supplied, for tests.
fn run_with_clock(
    watcher: &mut Watcher,
    source: &dyn Source,
    reporter: &dyn Reporter,
    emit: &mut dyn FnMut(Event),
    sleeper: &dyn Sleeper,
    stop: &dyn Fn() -> bool,
    clock: &dyn Fn() -> Instant,
) {
    while !stop() {
        let mut remaining = watcher.tick(clock(), source, reporter, emit);
        while !remaining.is_zero() && !stop() {
            let slice = remaining.min(SLEEP_SLICE);
            sleeper.sleep(slice);
            remaining -= slice;
        }
    }
}

#[cfg(test)]
mod tests;
