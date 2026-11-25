//! Sending a built summary to the collector, with bounded retries.
//!
//! The network sits behind the [`Transport`] trait and the waiting behind
//! [`Sleeper`], so [`send`] is tested entirely with fakes. [`UreqTransport`]
//! is the real transport.
//!
//! # Where the summary can go
//!
//! A default build can only talk to [`PRODUCTION_URL`]: [`Endpoint`] has no
//! public constructor other than [`Endpoint::production`]. The
//! `test-endpoint` cargo feature adds [`Endpoint::custom`], which tests use to
//! point the transport at a local listener. The feature is off by default and
//! no environment variable, flag or file read from the scanned tree can reach
//! it.
//!
//! # What a request carries
//!
//! A `POST` of the caller's bytes with `Content-Type: application/json` and a
//! `User-Agent` of `bastyn/<version>`. No authentication, no cookies, no
//! content encoding. Redirects are not followed, so a collector response can
//! never send the body somewhere else.
//!
//! # What is retried
//!
//! `202` means stored. `400`, `409`, `413`, `415` and `422` are problems with
//! the summary itself, so repeating it would not help and it is dropped. `503`,
//! `429`, any other `5xx`, a timeout and a network failure are retried with
//! the *identical* body (so the run identifier is unchanged and a replay is
//! harmless), within the limits of a [`Policy`]. Every other status is
//! dropped without a retry.

use std::time::Duration;

use super::summary::MAX_BODY_BYTES;

/// The collector's endpoint. The only address a default build can use.
pub const PRODUCTION_URL: &str = "https://reports.trustyouragent.org/v1/runs";

/// Where a summary is posted.
///
/// There is deliberately no way to build one from arbitrary text in a default
/// build; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    url: String,
}

impl Endpoint {
    /// The production collector, over HTTPS.
    #[must_use]
    pub fn production() -> Self {
        Self {
            url: PRODUCTION_URL.to_owned(),
        }
    }

    /// An endpoint for tests, available only with the `test-endpoint` cargo
    /// feature.
    ///
    /// Accepts any `https://` URL with a host, and `http://` only when the
    /// host is exactly `127.0.0.1`, `localhost` or `[::1]` (optionally with a
    /// numeric port). Anything else, including userinfo tricks such as
    /// `http://localhost@evil.com/`, returns `None`.
    #[cfg(feature = "test-endpoint")]
    #[must_use]
    pub fn custom(url: &str) -> Option<Self> {
        let valid = if let Some(rest) = url.strip_prefix("https://") {
            !authority(rest).is_empty()
        } else if let Some(rest) = url.strip_prefix("http://") {
            is_loopback_authority(authority(rest))
        } else {
            false
        };
        valid.then(|| Self {
            url: url.to_owned(),
        })
    }

    /// The URL requests are sent to.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether the endpoint uses plain HTTP. Only a loopback test endpoint
    /// can; the production constant is HTTPS.
    fn is_plain_http(&self) -> bool {
        self.url.starts_with("http://")
    }
}

/// The authority part of a URL with its scheme removed: everything up to the
/// first `/`, `?` or `#`.
pub(crate) fn authority(rest: &str) -> &str {
    rest.find(['/', '?', '#']).map_or(rest, |end| &rest[..end])
}

/// Whether an authority is exactly a loopback host with an optional numeric
/// port, and has no userinfo.
pub(crate) fn is_loopback_authority(authority: &str) -> bool {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        match rest.split_once(']') {
            Some((host, tail)) => (format!("[{host}]"), tail.strip_prefix(':')),
            None => return false,
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port)),
            None => (authority.to_owned(), None),
        }
    };
    let host_ok = matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]");
    // After a bracketed host only an empty tail or `:port` is allowed.
    let tail_ok = if authority.starts_with('[') {
        authority.ends_with(']') || port.is_some()
    } else {
        true
    };
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    host_ok && tail_ok && port_ok
}

/// What the collector answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// The HTTP status code.
    pub status: u16,
    /// The `Retry-After` header, when present in the delta-seconds form. An
    /// HTTP date or any other value is treated as absent.
    pub retry_after: Option<Duration>,
}

/// Why a request produced no reply. Coarse on purpose: it never carries a
/// URL or any part of the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The request did not finish within its time limit.
    Timeout,
    /// Any other failure: DNS, connection, TLS, protocol.
    Network,
}

/// Sends one request. A fake implements this in tests.
pub trait Transport {
    /// POSTs `body` and returns the collector's reply. Every HTTP status,
    /// including 3xx, 4xx and 5xx, is a [`Reply`], not an error.
    fn post(&self, body: &[u8]) -> Result<Reply, TransportError>;
}

/// Waits between attempts. A fake implements this in tests.
pub trait Sleeper {
    /// Blocks for `duration`.
    fn sleep(&self, duration: Duration);
}

/// The real sleeper, backed by [`std::thread::sleep`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Limits on retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// The most requests made, the first included.
    pub max_attempts: u32,
    /// The most time spent waiting between attempts, summed. A wait that
    /// would exceed what remains is not started.
    pub max_total_wait: Duration,
    /// The wait before the first retry when the collector gave no
    /// `Retry-After`; it doubles for each further retry.
    pub base_backoff: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            max_total_wait: Duration::from_secs(5),
            base_backoff: Duration::from_millis(500),
        }
    }
}

/// Why a summary was not delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// `409`: the collector already holds a different body for this run.
    Conflict,
    /// `400`, `415` or `422`: the collector refused the summary's form.
    Rejected(u16),
    /// The body exceeds the size limit, or the collector answered `413`.
    TooLarge,
    /// Attempts ran out while the collector kept answering `503` or another
    /// `5xx`.
    Unavailable,
    /// Attempts ran out while the collector kept answering `429`.
    RateLimited,
    /// Attempts ran out on timeouts or network failures.
    Network,
    /// A status the contract does not define (including redirects).
    Unexpected(u16),
    /// The next wait would have exceeded the policy's total wait budget, so
    /// no further attempt was made.
    GaveUp,
}

impl Dropped {
    /// A short, single-line explanation for the user. It never contains a
    /// URL or any part of the body.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Conflict => {
                "the collector already holds a different summary for this run (HTTP 409)".to_owned()
            }
            Self::Rejected(status) => {
                format!("the collector rejected the summary (HTTP {status})")
            }
            Self::TooLarge => "the summary is larger than the collector accepts".to_owned(),
            Self::Unavailable => "the collector was unavailable".to_owned(),
            Self::RateLimited => "the collector asked for fewer requests (HTTP 429)".to_owned(),
            Self::Network => "the collector could not be reached".to_owned(),
            Self::Unexpected(status) => {
                format!("the collector gave an unexpected answer (HTTP {status})")
            }
            Self::GaveUp => "the collector asked for a longer wait than is allowed".to_owned(),
        }
    }
}

/// The result of [`send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The collector answered `202`.
    Accepted,
    /// The summary was not delivered; see [`Dropped`].
    Dropped(Dropped),
}

/// What one attempt showed, before deciding whether to retry.
enum Attempt {
    Done(Outcome),
    Retry {
        retry_after: Option<Duration>,
        /// What to report if this was the last attempt.
        exhausted: Dropped,
    },
}

fn classify(result: Result<Reply, TransportError>) -> Attempt {
    match result {
        Ok(Reply { status: 202, .. }) => Attempt::Done(Outcome::Accepted),
        Ok(Reply { status: 409, .. }) => Attempt::Done(Outcome::Dropped(Dropped::Conflict)),
        Ok(Reply { status: 413, .. }) => Attempt::Done(Outcome::Dropped(Dropped::TooLarge)),
        Ok(Reply {
            status: status @ (400 | 415 | 422),
            ..
        }) => Attempt::Done(Outcome::Dropped(Dropped::Rejected(status))),
        Ok(Reply {
            status: 429,
            retry_after,
        }) => Attempt::Retry {
            retry_after,
            exhausted: Dropped::RateLimited,
        },
        Ok(Reply {
            status: 500..=599,
            retry_after,
        }) => Attempt::Retry {
            retry_after,
            exhausted: Dropped::Unavailable,
        },
        Ok(Reply { status, .. }) => Attempt::Done(Outcome::Dropped(Dropped::Unexpected(status))),
        Err(TransportError::Timeout | TransportError::Network) => Attempt::Retry {
            retry_after: None,
            exhausted: Dropped::Network,
        },
    }
}

/// Posts `body`, retrying within `policy`.
///
/// Refuses a body over [`MAX_BODY_BYTES`] before any network use. Each retry
/// sends the same `body`. The wait before retry `n` is the collector's
/// `Retry-After` when it gave one, otherwise `base_backoff * 2^(n-1)` plus
/// `jitter(base_backoff * 2^(n-1))`, where `jitter(d)` returns a value in
/// `[0, d]` (a larger value is clamped to `d`). When the wait would take the
/// total waited time past `policy.max_total_wait`, the call returns
/// [`Dropped::GaveUp`] immediately, without sleeping. When attempts run out
/// the result names the last failure: [`Dropped::Unavailable`] for `5xx`,
/// [`Dropped::RateLimited`] for `429`, [`Dropped::Network`] for a timeout or
/// network error.
pub fn send(
    body: &[u8],
    transport: &dyn Transport,
    sleeper: &dyn Sleeper,
    jitter: &dyn Fn(Duration) -> Duration,
    policy: &Policy,
) -> Outcome {
    if body.len() > MAX_BODY_BYTES {
        return Outcome::Dropped(Dropped::TooLarge);
    }
    let mut waited = Duration::ZERO;
    let mut attempt = 1u32;
    loop {
        let (retry_after, exhausted) = match classify(transport.post(body)) {
            Attempt::Done(outcome) => return outcome,
            Attempt::Retry {
                retry_after,
                exhausted,
            } => (retry_after, exhausted),
        };
        if attempt >= policy.max_attempts {
            return Outcome::Dropped(exhausted);
        }
        let wait = retry_after.unwrap_or_else(|| {
            let backoff = backoff_for(policy.base_backoff, attempt);
            backoff.saturating_add(jitter(backoff).min(backoff))
        });
        match waited.checked_add(wait) {
            Some(total) if total <= policy.max_total_wait => waited = total,
            _ => return Outcome::Dropped(Dropped::GaveUp),
        }
        sleeper.sleep(wait);
        attempt += 1;
    }
}

/// `base * 2^(attempt - 1)`, saturating.
fn backoff_for(base: Duration, attempt: u32) -> Duration {
    let factor = 1u32
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u32::MAX);
    base.saturating_mul(factor)
}

/// A uniformly random duration in `[0, bound]`, to the millisecond. Falls
/// back to zero when the system has no source of randomness: a missing
/// jitter only makes retries line up, it never blocks the upload.
#[must_use]
pub fn random_jitter(bound: Duration) -> Duration {
    let millis = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX);
    if millis == 0 {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return Duration::ZERO;
    }
    let value = u64::from_le_bytes(bytes);
    let pick = match millis.checked_add(1) {
        Some(span) => value % span,
        None => value,
    };
    Duration::from_millis(pick)
}

/// Time limits for the real transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// DNS, TCP and TLS handshake.
    pub connect: Duration,
    /// The whole request, from connect to the end of the response head.
    pub global: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(2),
            global: Duration::from_secs(4),
        }
    }
}

/// The real transport: blocking HTTP via `ureq`, over rustls.
///
/// HTTPS only unless the endpoint is a loopback test endpoint, redirects
/// disabled, and HTTP error statuses delivered as replies rather than
/// errors. No cookie store is compiled in and no credentials are sent.
pub struct UreqTransport {
    agent: ureq::Agent,
    url: String,
}

impl UreqTransport {
    /// Builds a transport for `endpoint` with the given time limits.
    #[must_use]
    pub fn new(endpoint: &Endpoint, timeouts: Timeouts) -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(!endpoint.is_plain_http())
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_connect(Some(timeouts.connect))
            .timeout_global(Some(timeouts.global))
            .user_agent(concat!("bastyn/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: config.into(),
            url: endpoint.url().to_owned(),
        }
    }
}

impl Transport for UreqTransport {
    fn post(&self, body: &[u8]) -> Result<Reply, TransportError> {
        let response = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .send(body)
            .map_err(|error| transport_error(&error))?;
        Ok(reply_from(&response))
    }
}

/// Maps a `ureq` failure to the coarse [`TransportError`].
pub(crate) fn transport_error(error: &ureq::Error) -> TransportError {
    match error {
        ureq::Error::Timeout(_) => TransportError::Timeout,
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => TransportError::Timeout,
        _ => TransportError::Network,
    }
}

/// The status and `Retry-After` of a response. The body is left unread.
pub(crate) fn reply_from(response: &ureq::http::Response<ureq::Body>) -> Reply {
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after);
    Reply {
        status: response.status().as_u16(),
        retry_after,
    }
}

/// Parses the delta-seconds form of `Retry-After`: ASCII digits only, after
/// trimming whitespace. An HTTP date, a sign, a fraction or anything else is
/// `None`.
fn parse_retry_after(value: &str) -> Option<Duration> {
    let text = value.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    struct FakeTransport {
        script: RefCell<VecDeque<Result<Reply, TransportError>>>,
        bodies: RefCell<Vec<Vec<u8>>>,
    }

    impl FakeTransport {
        fn new(script: Vec<Result<Reply, TransportError>>) -> Self {
            Self {
                script: RefCell::new(script.into()),
                bodies: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> usize {
            self.bodies.borrow().len()
        }
    }

    impl Transport for FakeTransport {
        fn post(&self, body: &[u8]) -> Result<Reply, TransportError> {
            self.bodies.borrow_mut().push(body.to_vec());
            self.script
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(TransportError::Network))
        }
    }

    #[derive(Default)]
    struct FakeSleeper {
        slept: RefCell<Vec<Duration>>,
    }

    impl Sleeper for FakeSleeper {
        fn sleep(&self, duration: Duration) {
            self.slept.borrow_mut().push(duration);
        }
    }

    #[expect(clippy::unnecessary_wraps, reason = "scripts mix replies and errors")]
    fn status(code: u16) -> Result<Reply, TransportError> {
        Ok(Reply {
            status: code,
            retry_after: None,
        })
    }

    #[expect(clippy::unnecessary_wraps, reason = "scripts mix replies and errors")]
    fn status_after(code: u16, seconds: u64) -> Result<Reply, TransportError> {
        Ok(Reply {
            status: code,
            retry_after: Some(Duration::from_secs(seconds)),
        })
    }

    fn no_jitter(_: Duration) -> Duration {
        Duration::ZERO
    }

    fn run(
        script: Vec<Result<Reply, TransportError>>,
        policy: &Policy,
    ) -> (Outcome, FakeTransport, FakeSleeper) {
        let transport = FakeTransport::new(script);
        let sleeper = FakeSleeper::default();
        let outcome = send(b"{\"a\":1}", &transport, &sleeper, &no_jitter, policy);
        (outcome, transport, sleeper)
    }

    #[test]
    fn accepted_on_202_with_one_call() {
        let (outcome, transport, sleeper) = run(vec![status(202)], &Policy::default());
        assert_eq!(outcome, Outcome::Accepted);
        assert_eq!(transport.calls(), 1);
        assert!(sleeper.slept.borrow().is_empty());
    }

    #[test]
    fn client_side_statuses_are_dropped_after_one_call() {
        let table = [
            (409, Dropped::Conflict),
            (400, Dropped::Rejected(400)),
            (413, Dropped::TooLarge),
            (415, Dropped::Rejected(415)),
            (422, Dropped::Rejected(422)),
            (200, Dropped::Unexpected(200)),
            (204, Dropped::Unexpected(204)),
            (301, Dropped::Unexpected(301)),
            (307, Dropped::Unexpected(307)),
            (404, Dropped::Unexpected(404)),
            (405, Dropped::Unexpected(405)),
        ];
        for (code, dropped) in table {
            let (outcome, transport, sleeper) = run(vec![status(code)], &Policy::default());
            assert_eq!(outcome, Outcome::Dropped(dropped), "status {code}");
            assert_eq!(transport.calls(), 1, "status {code}");
            assert!(sleeper.slept.borrow().is_empty(), "status {code}");
        }
    }

    #[test]
    fn retryable_failures_are_retried_then_succeed() {
        let failures = [
            status(503),
            status(429),
            status(500),
            status(502),
            Err(TransportError::Timeout),
            Err(TransportError::Network),
        ];
        for failure in failures {
            let (outcome, transport, _) = run(vec![failure, status(202)], &Policy::default());
            assert_eq!(outcome, Outcome::Accepted, "{failure:?}");
            assert_eq!(transport.calls(), 2, "{failure:?}");
        }
    }

    #[test]
    fn exhausting_attempts_names_the_last_failure() {
        let table = [
            (status(503), Dropped::Unavailable),
            (status(500), Dropped::Unavailable),
            (status(429), Dropped::RateLimited),
            (Err(TransportError::Timeout), Dropped::Network),
            (Err(TransportError::Network), Dropped::Network),
        ];
        for (failure, dropped) in table {
            let (outcome, transport, _) = run(vec![failure, failure, failure], &Policy::default());
            assert_eq!(outcome, Outcome::Dropped(dropped), "{failure:?}");
            assert_eq!(transport.calls(), 3, "{failure:?}");
        }
    }

    #[test]
    fn a_later_client_error_stops_the_retries() {
        let (outcome, transport, _) = run(vec![status(503), status(422)], &Policy::default());
        assert_eq!(outcome, Outcome::Dropped(Dropped::Rejected(422)));
        assert_eq!(transport.calls(), 2);
    }

    #[test]
    fn every_attempt_receives_identical_bytes() {
        let (_, transport, _) = run(
            vec![status(503), status(500), status(202)],
            &Policy::default(),
        );
        let bodies = transport.bodies.borrow();
        assert_eq!(bodies.len(), 3);
        assert!(bodies.iter().all(|body| body == b"{\"a\":1}"));
    }

    #[test]
    fn max_attempts_is_respected() {
        let policy = Policy {
            max_attempts: 5,
            max_total_wait: Duration::from_secs(3600),
            base_backoff: Duration::from_millis(1),
        };
        let (outcome, transport, _) = run(vec![status(503); 10], &policy);
        assert_eq!(outcome, Outcome::Dropped(Dropped::Unavailable));
        assert_eq!(transport.calls(), 5);

        let single = Policy {
            max_attempts: 1,
            ..Policy::default()
        };
        let (_, transport, sleeper) = run(vec![status(503); 10], &single);
        assert_eq!(transport.calls(), 1);
        assert!(sleeper.slept.borrow().is_empty());
    }

    #[test]
    fn backoff_doubles_without_jitter() {
        let policy = Policy {
            max_attempts: 4,
            max_total_wait: Duration::from_secs(60),
            base_backoff: Duration::from_millis(500),
        };
        let (_, _, sleeper) = run(vec![status(503); 4], &policy);
        assert_eq!(
            *sleeper.slept.borrow(),
            [
                Duration::from_millis(500),
                Duration::from_millis(1000),
                Duration::from_millis(2000)
            ]
        );
    }

    #[test]
    fn jitter_is_added_and_clamped_to_its_bound() {
        let transport = FakeTransport::new(vec![status(503), status(503), status(202)]);
        let sleeper = FakeSleeper::default();
        let policy = Policy::default();
        // Asks for far more than the bound: clamped to the bound.
        let outcome = send(
            b"x",
            &transport,
            &sleeper,
            &|_| Duration::from_secs(99),
            &policy,
        );
        assert_eq!(outcome, Outcome::Accepted);
        assert_eq!(
            *sleeper.slept.borrow(),
            [Duration::from_millis(1000), Duration::from_millis(2000)]
        );
    }

    #[test]
    fn random_jitter_stays_within_its_bound() {
        let bound = Duration::from_millis(50);
        for _ in 0..2000 {
            assert!(random_jitter(bound) <= bound);
        }
        assert_eq!(random_jitter(Duration::ZERO), Duration::ZERO);
        let _ = random_jitter(Duration::MAX);
    }

    #[test]
    fn retry_after_is_honoured() {
        let (outcome, _, sleeper) =
            run(vec![status_after(503, 3), status(202)], &Policy::default());
        assert_eq!(outcome, Outcome::Accepted);
        assert_eq!(*sleeper.slept.borrow(), [Duration::from_secs(3)]);
    }

    #[test]
    fn retry_after_beyond_the_budget_gives_up_without_sleeping() {
        for code in [503, 429] {
            let (outcome, transport, sleeper) = run(
                vec![status_after(code, 30), status(202)],
                &Policy::default(),
            );
            assert_eq!(outcome, Outcome::Dropped(Dropped::GaveUp), "status {code}");
            assert_eq!(transport.calls(), 1);
            assert!(sleeper.slept.borrow().is_empty());
        }
    }

    #[test]
    fn total_wait_budget_is_cumulative() {
        let (outcome, transport, sleeper) = run(
            vec![status_after(503, 3), status_after(503, 3), status(202)],
            &Policy::default(),
        );
        assert_eq!(outcome, Outcome::Dropped(Dropped::GaveUp));
        assert_eq!(transport.calls(), 2);
        assert_eq!(sleeper.slept.borrow().len(), 1);
    }

    #[test]
    fn oversize_body_is_refused_without_a_call() {
        let transport = FakeTransport::new(vec![status(202)]);
        let sleeper = FakeSleeper::default();
        let body = vec![b'x'; MAX_BODY_BYTES + 1];
        let outcome = send(&body, &transport, &sleeper, &no_jitter, &Policy::default());
        assert_eq!(outcome, Outcome::Dropped(Dropped::TooLarge));
        assert_eq!(transport.calls(), 0);

        let exact = vec![b'x'; MAX_BODY_BYTES];
        assert_eq!(
            send(&exact, &transport, &sleeper, &no_jitter, &Policy::default()),
            Outcome::Accepted
        );
    }

    #[test]
    fn reasons_are_single_line_and_free_of_urls() {
        let all = [
            Dropped::Conflict,
            Dropped::Rejected(422),
            Dropped::TooLarge,
            Dropped::Unavailable,
            Dropped::RateLimited,
            Dropped::Network,
            Dropped::Unexpected(307),
            Dropped::GaveUp,
        ];
        for dropped in all {
            let reason = dropped.reason();
            assert_ne!(reason, "");
            assert!(!reason.contains('\n'), "{reason}");
            assert!(
                !reason.contains("http://") && !reason.contains("https://"),
                "{reason}"
            );
            assert!(!reason.contains("trustyouragent"), "{reason}");
        }
        assert_eq!(
            Dropped::Rejected(422).reason(),
            "the collector rejected the summary (HTTP 422)"
        );
    }

    #[test]
    fn retry_after_parsing_accepts_only_delta_seconds() {
        assert_eq!(parse_retry_after("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after(" 300 "), Some(Duration::from_secs(300)));
        assert_eq!(parse_retry_after("0"), Some(Duration::ZERO));
        for bad in [
            "soon",
            "",
            "-5",
            "+5",
            "1.5",
            "Wed, 21 Oct 2026 07:28:00 GMT",
            "99999999999999999999999999",
        ] {
            assert_eq!(parse_retry_after(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn production_endpoint_is_the_https_constant() {
        let endpoint = Endpoint::production();
        assert_eq!(endpoint.url(), PRODUCTION_URL);
        assert!(endpoint.url().starts_with("https://"));
        assert!(!endpoint.is_plain_http());
    }

    #[cfg(feature = "test-endpoint")]
    #[test]
    fn custom_endpoint_validation() {
        for ok in [
            "https://example.com/x",
            "http://127.0.0.1:1/x",
            "http://localhost:1/x",
            "http://[::1]:1/x",
            "http://127.0.0.1/x",
            "http://localhost",
        ] {
            assert_eq!(
                Endpoint::custom(ok).map(|e| e.url().to_owned()),
                Some(ok.to_owned()),
                "{ok}"
            );
        }
        for bad in [
            "http://example.com/x",
            "ftp://127.0.0.1/x",
            "",
            "https://",
            "http://",
            "http://127.0.0.1.evil.com/x",
            "http://localhost@evil.com/x",
            "http://127.0.0.1@evil.com/x",
            "http://localhost:80@evil.com/x",
            "http://[::1]evil/x",
            "http://localhost:abc/x",
            "http://localhost:/x",
            "HTTP://127.0.0.1/x",
            "127.0.0.1:80",
        ] {
            assert!(Endpoint::custom(bad).is_none(), "{bad}");
        }
    }
}

#[cfg(all(test, feature = "test-endpoint"))]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod ureq_tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    fn short() -> Timeouts {
        Timeouts {
            connect: Duration::from_millis(200),
            global: Duration::from_millis(200),
        }
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut data = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                return data;
            }
            data.extend_from_slice(&buf[..n]);
            if let Some(head_end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..head_end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if data.len() >= head_end + 4 + length {
                    return data;
                }
            }
        }
    }

    /// Serves one canned response and returns the raw request it received.
    fn serve_once(response: String) -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/runs", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let request = read_request(&mut stream);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                let _ = tx.send(request);
            }
        });
        (url, rx)
    }

    fn transport_for(url: &str, timeouts: Timeouts) -> UreqTransport {
        UreqTransport::new(&Endpoint::custom(url).unwrap(), timeouts)
    }

    fn reply(code: &str, extra: &str) -> String {
        format!("HTTP/1.1 {code}\r\nContent-Length: 0\r\nConnection: close\r\n{extra}\r\n")
    }

    #[test]
    fn a_202_reply_and_the_request_shape() {
        let (url, rx) = serve_once(reply("202 Accepted", ""));
        let transport = transport_for(&url, Timeouts::default());
        let body = b"{\"run_id\":\"abc\"}";
        let got = transport.post(body).unwrap();
        assert_eq!(
            got,
            Reply {
                status: 202,
                retry_after: None
            }
        );

        let raw = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8(raw[..head_end].to_vec()).unwrap();
        assert!(head.starts_with("POST /v1/runs HTTP/1.1\r\n"), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(
            lower.contains("\r\ncontent-type: application/json"),
            "{head}"
        );
        assert!(lower.contains("\r\nuser-agent: bastyn/"), "{head}");
        for forbidden in [
            "authorization:",
            "cookie:",
            "content-encoding:",
            "proxy-authorization:",
        ] {
            assert!(!lower.contains(forbidden), "{forbidden} present in {head}");
        }
        assert_eq!(&raw[head_end + 4..], body);
    }

    #[test]
    fn a_redirect_is_not_followed() {
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        second.set_nonblocking(true).unwrap();
        let target = format!("http://{}/elsewhere", second.local_addr().unwrap());
        let (url, _rx) = serve_once(reply(
            "307 Temporary Redirect",
            &format!("Location: {target}\r\n"),
        ));
        let got = transport_for(&url, Timeouts::default())
            .post(b"{}")
            .unwrap();
        assert_eq!(got.status, 307);
        thread::sleep(Duration::from_millis(100));
        assert!(
            second.accept().is_err(),
            "the second listener was contacted"
        );
    }

    #[test]
    fn retry_after_header_is_parsed() {
        let (url, _rx) = serve_once(reply("503 Service Unavailable", "Retry-After: 30\r\n"));
        let got = transport_for(&url, Timeouts::default())
            .post(b"{}")
            .unwrap();
        assert_eq!(got.status, 503);
        assert_eq!(got.retry_after, Some(Duration::from_secs(30)));

        let (url, _rx) = serve_once(reply("503 Service Unavailable", "Retry-After: soon\r\n"));
        let got = transport_for(&url, Timeouts::default())
            .post(b"{}")
            .unwrap();
        assert_eq!(got.status, 503);
        assert_eq!(got.retry_after, None);
    }

    #[test]
    fn a_server_that_never_answers_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/runs", listener.local_addr().unwrap());
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let held = listener.accept().ok();
            let _ = done_rx.recv_timeout(Duration::from_secs(10));
            drop(held);
        });
        let result = transport_for(&url, short()).post(b"{}");
        assert_eq!(result, Err(TransportError::Timeout));
        let _ = done_tx.send(());
        handle.join().unwrap();
    }

    #[test]
    fn a_closed_port_is_a_network_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/runs", listener.local_addr().unwrap());
        drop(listener);
        // Windows reports a refused connection only after about two seconds of
        // connection retries, so the timeouts must outlast that.
        let patient = Timeouts {
            connect: Duration::from_secs(10),
            global: Duration::from_secs(10),
        };
        assert_eq!(
            transport_for(&url, patient).post(b"{}"),
            Err(TransportError::Network)
        );
    }
}
