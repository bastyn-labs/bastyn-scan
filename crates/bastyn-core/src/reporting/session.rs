//! One reporting attempt, from the consent decision to the upload.
//!
//! [`run`] is what the CLI calls after a scan has finished. It is the only
//! place that fixes the order of the steps, and that order is a contract:
//!
//! 1. Consent ([`consent::decide`]). When reporting is off the function
//!    returns at once having done nothing: no state directory read or
//!    written, no project identifier resolved, no request made.
//! 2. Project identifier ([`project_id::resolve`], allowed to create the local
//!    identifier). If none can be produced nothing is sent; an identifier is
//!    never invented.
//! 3. The first-run notice, emitted before any network attempt.
//! 4. The summary is built, with a fresh run identifier.
//! 5. The upload ([`upload::send`]).
//!
//! The summary body is never returned, logged or passed to the notice
//! callback; the only text that leaves this function is a short reason.

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::consent::{self, Decision, DisabledBy};
use super::notice;
use super::project_id::{self, Resolution};
use super::summary::{self, Environment, ScanSummary, SummaryMeta};
use super::upload::{self, Policy, Sleeper, Transport};
use crate::report::Report;

/// Everything one reporting attempt reads.
pub struct Request<'a> {
    /// The finished scan.
    pub report: &'a Report,
    /// The directory that was scanned.
    pub scan_root: &'a Path,
    /// Environment lookup, injected so tests never use the real one.
    pub env: &'a dyn Fn(&str) -> Option<OsString>,
    /// The per-user state directory (see [`super::state::state_dir`]), if
    /// one could be determined.
    pub state_dir: Option<&'a Path>,
    /// Whether `--no-reporting` was given.
    pub no_reporting: bool,
    /// Whether `--offline` was given.
    pub offline: bool,
    /// When the scan began.
    pub started_at: SystemTime,
    /// When the scan ended.
    pub finished_at: SystemTime,
}

/// How a reporting attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reported {
    /// Reporting is off; nothing was read, written or sent.
    Disabled(DisabledBy),
    /// No project identifier could be produced, so nothing was sent. The
    /// string says why.
    NoProjectId(String),
    /// The collector accepted the summary.
    Sent,
    /// The summary was built but not delivered. The string is a short,
    /// single-line reason with no URL or body text.
    Failed(String),
}

/// Runs one reporting attempt. See the module documentation for the order of
/// steps.
///
/// `notice` receives the first-run text ([`notice::NOTICE`]) when it is due:
/// once per state directory, or on every run when there is no state
/// directory. Failing to record that the notice was shown is ignored, so the
/// notice may simply print again next time.
pub fn run(
    req: &Request<'_>,
    transport: &dyn Transport,
    sleeper: &dyn Sleeper,
    jitter: &dyn Fn(Duration) -> Duration,
    policy: &Policy,
    notice: &mut dyn FnMut(&str),
) -> Reported {
    if let Decision::Disabled(reason) = consent::decide(req.no_reporting, req.offline, req.env) {
        return Reported::Disabled(reason);
    }

    let resolution = project_id::resolve(&project_id::Inputs {
        scan_root: req.scan_root,
        env: req.env,
        state_dir: req.state_dir,
        create_local: true,
    });
    let project = match resolution {
        Resolution::Resolved(project) => project,
        Resolution::Unavailable(reason) => return Reported::NoProjectId(reason),
        Resolution::LocalNotCreated => {
            return Reported::NoProjectId("no local project identifier exists".to_owned());
        }
    };

    show_notice_once(req.state_dir, notice);

    let Ok(run_id) = summary::new_run_id() else {
        return Reported::Failed("no source of randomness for the run identifier".to_owned());
    };
    let meta = SummaryMeta {
        run_id,
        project_id: project.id,
        id_source: project.source,
        started_at: req.started_at,
        finished_at: req.finished_at,
        environment: Environment::detect(req.env),
    };
    let Ok(body) = ScanSummary::build(req.report, &meta).to_json() else {
        return Reported::Failed("the summary could not be serialised".to_owned());
    };

    match upload::send(&body, transport, sleeper, jitter, policy) {
        upload::Outcome::Accepted => Reported::Sent,
        upload::Outcome::Dropped(dropped) => Reported::Failed(dropped.reason()),
    }
}

/// Emits the notice when it has not been shown for this state directory, and
/// records that it was. Without a state directory there is nowhere to record
/// it, so it is emitted every time.
fn show_notice_once(state_dir: Option<&Path>, emit: &mut dyn FnMut(&str)) {
    match state_dir {
        Some(dir) if notice::already_shown(dir) => {}
        Some(dir) => {
            emit(notice::NOTICE);
            // A failure here only means the notice prints again next time.
            let _ = notice::record_shown(dir);
        }
        None => emit(notice::NOTICE),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::report::{CveStatus, Summary};
    use crate::reporting::upload::{Reply, TransportError};

    type Log = RefCell<Vec<String>>;

    struct FakeTransport<'a> {
        log: &'a Log,
        reply: Result<Reply, TransportError>,
        bodies: RefCell<Vec<Vec<u8>>>,
    }

    impl<'a> FakeTransport<'a> {
        fn accepting(log: &'a Log) -> Self {
            Self {
                log,
                reply: Ok(Reply {
                    status: 202,
                    retry_after: None,
                }),
                bodies: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> usize {
            self.bodies.borrow().len()
        }
    }

    impl Transport for FakeTransport<'_> {
        fn post(&self, body: &[u8]) -> Result<Reply, TransportError> {
            self.log.borrow_mut().push("post".to_owned());
            self.bodies.borrow_mut().push(body.to_vec());
            self.reply
        }
    }

    struct NoSleep;

    impl Sleeper for NoSleep {
        fn sleep(&self, _: Duration) {}
    }

    fn report() -> Report {
        Report {
            bastyn_version: "0.2.0".to_owned(),
            root: ".".to_owned(),
            summary: Summary {
                files_scanned: 1,
                files_skipped: 0,
                defects: 0,
                observations: 0,
            },
            cve: CveStatus::NoManifest,
            findings: Vec::new(),
            skipped: Vec::new(),
            coverage: crate::report::Coverage::default(),
            crosswalks: Vec::new(),
        }
    }

    /// A scan root with a remote, so the project identifier never needs the
    /// state directory.
    fn repo_with_remote() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git/config"),
            "[remote \"origin\"]\n\turl = https://github.com/acme/xpto.git\n",
        )
        .unwrap();
        dir
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn zero(_: Duration) -> Duration {
        Duration::ZERO
    }

    struct Setup<'a> {
        report: Report,
        root: &'a Path,
        state: Option<&'a Path>,
        no_reporting: bool,
        offline: bool,
        env: &'a dyn Fn(&str) -> Option<OsString>,
    }

    impl<'a> Setup<'a> {
        fn new(root: &'a Path, state: Option<&'a Path>) -> Self {
            Self {
                report: report(),
                root,
                state,
                no_reporting: false,
                offline: false,
                env: &no_env,
            }
        }

        fn go(&self, transport: &FakeTransport<'_>, log: &Log) -> (Reported, usize) {
            let request = Request {
                report: &self.report,
                scan_root: self.root,
                env: self.env,
                state_dir: self.state,
                no_reporting: self.no_reporting,
                offline: self.offline,
                started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
                finished_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_005),
            };
            let mut notices = 0usize;
            let mut emit = |text: &str| {
                assert_eq!(text, notice::NOTICE);
                notices += 1;
                log.borrow_mut().push("notice".to_owned());
            };
            let outcome = run(
                &request,
                transport,
                &NoSleep,
                &zero,
                &Policy::default(),
                &mut emit,
            );
            (outcome, notices)
        }
    }

    #[test]
    fn disabled_does_nothing_for_each_reason() {
        let dnt = |name: &str| (name == "DO_NOT_TRACK").then(|| OsString::from("1"));
        let cases: [(bool, bool, bool, DisabledBy); 3] = [
            (true, false, false, DisabledBy::NoReportingFlag),
            (false, true, false, DisabledBy::OfflineFlag),
            (false, false, true, DisabledBy::DoNotTrack),
        ];
        for (no_reporting, offline, use_dnt, reason) in cases {
            // No remote and no CI variables: resolution would create a local
            // identifier in the state directory if it were reached.
            let root = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let log = Log::default();
            let transport = FakeTransport::accepting(&log);
            let mut setup = Setup::new(root.path(), Some(state.path()));
            setup.no_reporting = no_reporting;
            setup.offline = offline;
            if use_dnt {
                setup.env = &dnt;
            }
            let (outcome, notices) = setup.go(&transport, &log);
            assert_eq!(outcome, Reported::Disabled(reason));
            assert_eq!(notices, 0);
            assert_eq!(transport.calls(), 0);
            assert!(log.borrow().is_empty());
            assert_eq!(
                std::fs::read_dir(state.path()).unwrap().count(),
                0,
                "state directory must stay empty for {reason:?}"
            );
        }
    }

    #[test]
    fn no_project_id_sends_nothing_and_returns_the_reason() {
        let root = tempfile::tempdir().unwrap();
        let log = Log::default();
        let transport = FakeTransport::accepting(&log);
        // No remote, no CI variables and no state directory: nothing to
        // derive an identifier from.
        let setup = Setup::new(root.path(), None);
        let (outcome, notices) = setup.go(&transport, &log);
        let Reported::NoProjectId(reason) = &outcome else {
            unreachable!("expected NoProjectId, got {outcome:?}");
        };
        assert_ne!(reason, "");
        assert!(!reason.contains('\n'));
        assert_eq!(transport.calls(), 0);
        assert_eq!(notices, 0, "no notice when nothing will be sent");
    }

    #[test]
    fn a_local_project_id_is_created_and_the_summary_is_sent() {
        let root = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let log = Log::default();
        let transport = FakeTransport::accepting(&log);
        let setup = Setup::new(root.path(), Some(state.path()));
        let (outcome, _) = setup.go(&transport, &log);
        assert_eq!(outcome, Reported::Sent);
        assert_eq!(transport.calls(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&transport.bodies.borrow()[0]).unwrap();
        assert_eq!(body["id_source"], "local");
    }

    #[test]
    fn notice_is_shown_once_and_before_the_first_post() {
        let repo = repo_with_remote();
        let state = tempfile::tempdir().unwrap();
        let state_path = state.path().join("bastyn");
        let log = Log::default();
        let transport = FakeTransport::accepting(&log);
        let setup = Setup::new(repo.path(), Some(&state_path));

        let (first, notices) = setup.go(&transport, &log);
        assert_eq!(first, Reported::Sent);
        assert_eq!(notices, 1);
        assert_eq!(*log.borrow(), ["notice", "post"]);
        assert!(notice::already_shown(&state_path));

        let (second, notices) = setup.go(&transport, &log);
        assert_eq!(second, Reported::Sent);
        assert_eq!(notices, 0);
        assert_eq!(*log.borrow(), ["notice", "post", "post"]);
    }

    #[test]
    fn notice_is_shown_every_time_without_a_state_dir() {
        let repo = repo_with_remote();
        let log = Log::default();
        let transport = FakeTransport::accepting(&log);
        let setup = Setup::new(repo.path(), None);
        for _ in 0..2 {
            let (outcome, notices) = setup.go(&transport, &log);
            assert_eq!(outcome, Reported::Sent);
            assert_eq!(notices, 1);
        }
        assert_eq!(*log.borrow(), ["notice", "post", "notice", "post"]);
    }

    #[test]
    fn an_unwritable_state_dir_does_not_stop_the_upload() {
        let repo = repo_with_remote();
        let scratch = tempfile::tempdir().unwrap();
        // A regular file where the directory should be: nothing can be
        // created beneath it.
        let blocked = scratch.path().join("blocked");
        std::fs::write(&blocked, b"not a directory").unwrap();
        let state = blocked.join("bastyn");
        let log = Log::default();
        let transport = FakeTransport::accepting(&log);
        let setup = Setup::new(repo.path(), Some(&state));

        let (outcome, notices) = setup.go(&transport, &log);
        assert_eq!(outcome, Reported::Sent);
        assert_eq!(notices, 1);
        let (_, notices) = setup.go(&transport, &log);
        assert_eq!(
            notices, 1,
            "the notice prints again when it cannot be recorded"
        );
        assert_eq!(transport.calls(), 2);
    }

    #[test]
    fn a_dropped_upload_returns_a_short_reason() {
        let repo = repo_with_remote();
        let log = Log::default();
        let mut transport = FakeTransport::accepting(&log);
        transport.reply = Ok(Reply {
            status: 422,
            retry_after: None,
        });
        let setup = Setup::new(repo.path(), None);
        let (outcome, _) = setup.go(&transport, &log);
        assert_eq!(
            outcome,
            Reported::Failed("the collector rejected the summary (HTTP 422)".to_owned())
        );
        assert_eq!(transport.calls(), 1);
    }

    #[test]
    fn retries_reuse_the_identical_body() {
        let repo = repo_with_remote();
        let log = Log::default();
        let mut transport = FakeTransport::accepting(&log);
        transport.reply = Err(TransportError::Network);
        let setup = Setup::new(repo.path(), None);
        let (outcome, _) = setup.go(&transport, &log);
        assert_eq!(
            outcome,
            Reported::Failed("the collector could not be reached".to_owned())
        );
        let bodies = transport.bodies.borrow();
        assert_eq!(bodies.len(), 3);
        assert!(bodies.iter().all(|body| body == &bodies[0]));
    }
}
