//! Where alerts go.

use std::time::Duration;

use super::alert::Alert;

/// The result of one attempt to deliver an alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliverOutcome {
    /// The destination accepted the alert.
    Delivered,
    /// The attempt failed in a way that may pass: try again later.
    Retry {
        /// How long the destination asked the sender to wait, when it said.
        after: Option<Duration>,
        /// A short, single-line description. It never contains a secret.
        reason: String,
    },
    /// The attempt failed in a way a repeat cannot fix. The alert is dropped.
    Fatal {
        /// A short, single-line description. It never contains a secret.
        reason: String,
    },
}

/// A destination for alerts. One attempt per call; the watcher owns retrying.
pub trait Reporter {
    /// Makes one attempt to deliver `alert`.
    fn deliver(&self, alert: &Alert) -> DeliverOutcome;
}
