//! The anonymous scan summary: counts and nothing else, built from a finished
//! [`Report`].
//!
//! The summary's body shape is fixed by a published JSON Schema
//! (`scan-summary.v1`), and this module is the only place that produces it.
//! It is pure: no network, no terminal, no filesystem. The caller supplies the
//! run identifier, project identifier, timestamps and environment through
//! [`SummaryMeta`], so every behaviour here is testable without a scan.
//!
//! # What can reach the output
//!
//! [`ScanSummary::build`] reads an explicit, field-by-field allowlist of the
//! report and nothing more:
//!
//! - [`Report::bastyn_version`]
//! - [`Summary::files_scanned`](crate::report::Summary::files_scanned) and
//!   [`Summary::files_skipped`](crate::report::Summary::files_skipped)
//! - [`Report::cve`], by variant only (never the payload, which carries a
//!   free-text reason)
//! - for each [`Skip`](crate::report::Skip), its `reason` only
//! - for each [`Finding`](crate::finding::Finding), its `rule_id`, `severity`
//!   and `kind` only
//!
//! The summary types own plain strings, numbers and maps. They never hold,
//! clone or serialise a `Finding`, a `Skip` or a `Report`, so a finding's
//! title, snippet, description, remediation, location, references,
//! categories or secondary rule ids, a skip's path or detail, the scanned
//! root, and the compliance crosswalks have no path into the body. Adding a
//! field to the body means adding a field here by hand.
//!
//! # Size
//!
//! The collector rejects bodies over [`MAX_BODY_BYTES`] and the schema caps
//! `findings` at 500 entries. [`ScanSummary::build`] enforces both itself, by
//! dropping the lowest-priority groups, so no caller can obtain an oversize
//! summary. The schema has no truncation flag, so a truncated summary says
//! so through `scan_status: "partial"`.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::project_id::IdSource;
use crate::finding::{Kind, Severity};
use crate::report::{CveStatus, Report, SkipReason};

/// The collector's hard limit on a request body. A larger body is rejected.
pub const MAX_BODY_BYTES: usize = 32 * 1024;

/// The size this module keeps bodies under, leaving headroom below
/// [`MAX_BODY_BYTES`] for anything a transport adds.
pub const TARGET_BODY_BYTES: usize = 28 * 1024;

/// The schema's cap on the number of `findings` entries.
const MAX_FINDING_GROUPS: usize = 500;

/// The schema's cap on every counter.
const MAX_COUNT: usize = 10_000_000;

/// The schema's cap on a rule id's length, and on the version string's.
const MAX_RULE_ID_CHARS: usize = 128;

/// The longest scanner version the schema accepts.
const MAX_VERSION_CHARS: usize = 64;

/// Sent when the report's own version string is not one the schema accepts,
/// so a malformed version cannot make the whole summary unsendable.
const FALLBACK_VERSION: &str = "0.0.0";

/// Largest value [`format_timestamp`] renders: `9999-12-31T23:59:59Z`. The
/// schema only accepts four-digit years.
const MAX_TIMESTAMP_SECS: u64 = 253_402_300_799;

/// Where a scan ran, as far as environment variables can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// GitHub Actions.
    GithubActions,
    /// GitLab CI.
    GitlabCi,
    /// Some other continuous-integration system.
    OtherCi,
    /// Not in CI.
    Local,
}

/// Variables whose presence (set and non-empty) marks a CI system that has no
/// dedicated [`Environment`] variant.
const OTHER_CI_VARIABLES: [&str; 11] = [
    "BUILD_NUMBER",
    "JENKINS_URL",
    "TF_BUILD",
    "CIRCLECI",
    "BITBUCKET_BUILD_NUMBER",
    "BUILDKITE",
    "TEAMCITY_VERSION",
    "TRAVIS",
    "APPVEYOR",
    "DRONE",
    "CODEBUILD_BUILD_ID",
];

impl Environment {
    /// The name used in the summary: `github-actions`, `gitlab-ci`,
    /// `other-ci` or `local`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GithubActions => "github-actions",
            Self::GitlabCi => "gitlab-ci",
            Self::OtherCi => "other-ci",
            Self::Local => "local",
        }
    }

    /// Classify the current environment.
    ///
    /// `env` looks a variable up, so a test can supply a fixed set instead of
    /// the process environment. The two named systems must say `true`
    /// exactly; for the rest, any of a list of well-known variables being set
    /// and non-empty counts, and a generic `CI` counts unless it is `false`
    /// or `0`.
    #[must_use]
    pub fn detect(env: &dyn Fn(&str) -> Option<OsString>) -> Self {
        let present = |name: &str| env(name).is_some_and(|value| !value.is_empty());
        let is_true = |name: &str| env(name).is_some_and(|value| value == "true");

        if is_true("GITHUB_ACTIONS") {
            return Self::GithubActions;
        }
        if is_true("GITLAB_CI") {
            return Self::GitlabCi;
        }
        let generic_ci = env("CI").is_some_and(|value| {
            !value.is_empty() && !value.eq_ignore_ascii_case("false") && value != "0"
        });
        if generic_ci || OTHER_CI_VARIABLES.iter().any(|name| present(name)) {
            Self::OtherCi
        } else {
            Self::Local
        }
    }
}

/// Everything about a run that the report itself does not carry.
#[derive(Debug, Clone)]
pub struct SummaryMeta {
    /// A fresh random identifier for this run; see [`new_run_id`].
    pub run_id: String,
    /// The opaque project identifier, 64 lowercase hex characters.
    pub project_id: String,
    /// How the project identifier was obtained.
    pub id_source: IdSource,
    /// When the scan began.
    pub started_at: SystemTime,
    /// When the scan ended.
    pub finished_at: SystemTime,
    /// Where the scan ran.
    pub environment: Environment,
}

/// One group of findings sharing a rule, severity and kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FindingGroup {
    rule_id: String,
    severity: &'static str,
    kind: &'static str,
    count: usize,
}

/// The `coverage` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Coverage {
    files_scanned: usize,
    files_skipped: usize,
    skips_by_reason: BTreeMap<&'static str, usize>,
    dependency_lookup: &'static str,
}

/// The anonymous summary of one scan, ready to serialise.
///
/// Fields are private and every one is a plain string, number or map: see
/// the module documentation for what that rules out. Field order here is the
/// order in the JSON.
#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    schema_version: u8,
    run_id: String,
    project_id: String,
    id_source: &'static str,
    scanner_version: String,
    started_at: String,
    finished_at: String,
    scan_status: &'static str,
    coverage: Coverage,
    findings: Vec<FindingGroup>,
    environment: &'static str,
    /// Not part of the body. How many groups were cut to fit.
    #[serde(skip)]
    dropped_groups: usize,
}

/// A group's sort position: most severe first, then most frequent, then by
/// name so ties never depend on hash or thread order.
fn priority(
    group: &FindingGroup,
    severity: Severity,
    kind: Kind,
) -> (Reverse<Severity>, Reverse<usize>, String, Kind) {
    (
        Reverse(severity),
        Reverse(group.count),
        group.rule_id.clone(),
        kind,
    )
}

impl ScanSummary {
    /// Build the summary of `report`.
    ///
    /// Reads only the allowlist in the module documentation. If the findings
    /// would exceed the schema's 500 groups or [`TARGET_BODY_BYTES`] of
    /// compact JSON, the lowest-priority groups are dropped until they fit
    /// (see [`Self::dropped_groups`]) and the scan is reported as `partial`.
    #[must_use]
    pub fn build(report: &Report, meta: &SummaryMeta) -> Self {
        let mut skips_by_reason: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut incomplete_scan = false;
        for skip in &report.skipped {
            *skips_by_reason
                .entry(skip_reason_key(skip.reason))
                .or_default() += 1;
            incomplete_scan |= matches!(
                skip.reason,
                SkipReason::Unreadable | SkipReason::Unparseable | SkipReason::Unpinned
            );
        }
        for count in skips_by_reason.values_mut() {
            *count = (*count).min(MAX_COUNT);
        }
        incomplete_scan |= matches!(
            report.cve,
            CveStatus::Partial { .. } | CveStatus::Unreachable { .. }
        );

        let mut grouped: BTreeMap<(String, Severity, Kind), usize> = BTreeMap::new();
        for finding in &report.findings {
            let key = (
                sanitise_rule_id(&finding.rule_id),
                finding.severity,
                finding.kind,
            );
            *grouped.entry(key).or_default() += 1;
        }
        let mut ordered: Vec<(FindingGroup, Severity, Kind)> = grouped
            .into_iter()
            .map(|((rule_id, severity, kind), count)| {
                let group = FindingGroup {
                    rule_id,
                    severity: severity_name(severity),
                    kind: kind_name(kind),
                    count: count.min(MAX_COUNT),
                };
                (group, severity, kind)
            })
            .collect();
        ordered.sort_by_cached_key(|(group, severity, kind)| priority(group, *severity, *kind));
        let groups: Vec<FindingGroup> = ordered.into_iter().map(|(group, ..)| group).collect();

        let version = if is_valid_version(&report.bastyn_version) {
            report.bastyn_version.clone()
        } else {
            FALLBACK_VERSION.to_owned()
        };

        let mut summary = Self {
            schema_version: 1,
            run_id: meta.run_id.clone(),
            project_id: meta.project_id.clone(),
            id_source: meta.id_source.as_str(),
            scanner_version: version,
            started_at: format_timestamp(meta.started_at),
            finished_at: format_timestamp(meta.finished_at),
            scan_status: scan_status(incomplete_scan),
            coverage: Coverage {
                files_scanned: report.summary.files_scanned.min(MAX_COUNT),
                files_skipped: report.summary.files_skipped.min(MAX_COUNT),
                skips_by_reason,
                dependency_lookup: dependency_lookup(&report.cve),
            },
            findings: groups,
            environment: meta.environment.as_str(),
            dropped_groups: 0,
        };
        summary.fit();
        summary
    }

    /// Drop lowest-priority groups until the body is within the schema's
    /// group cap and [`TARGET_BODY_BYTES`].
    ///
    /// The body's size only ever shrinks as groups are removed, so the
    /// largest prefix that fits is found by bisection rather than by
    /// re-serialising once per dropped group.
    fn fit(&mut self) {
        let total = self.findings.len();
        if total <= MAX_FINDING_GROUPS && self.body_len() <= TARGET_BODY_BYTES {
            return;
        }
        // A truncated body always says `partial`; measure with that status,
        // the longer of the two spellings, so the answer holds once it is set.
        self.scan_status = scan_status(true);
        let mut kept = self.findings.clone();
        let (mut low, mut high) = (0, total.min(MAX_FINDING_GROUPS));
        while low < high {
            let middle = (low + high).div_ceil(2);
            self.findings = kept[..middle].to_vec();
            if self.body_len() <= TARGET_BODY_BYTES {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        kept.truncate(low);
        self.findings = kept;
        self.dropped_groups = total - low;
    }

    /// The length of the compact JSON body as it currently stands.
    fn body_len(&self) -> usize {
        // Serialising plain strings, numbers and maps cannot fail. Were it to,
        // reporting the body as oversize is the safe direction.
        self.to_json().map_or(usize::MAX, |body| body.len())
    }

    /// The body as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns the serialiser's error. The summary holds only strings,
    /// numbers and maps, so in practice it does not fail.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// How many finding groups were cut to keep the body within the size
    /// limits. Zero unless the summary was truncated.
    #[must_use]
    pub const fn dropped_groups(&self) -> usize {
        self.dropped_groups
    }
}

/// `complete` or `partial`.
const fn scan_status(partial: bool) -> &'static str {
    if partial { "partial" } else { "complete" }
}

/// The `skips_by_reason` key for a reason.
///
/// Exhaustive on purpose: a new [`SkipReason`] must be given a key here.
const fn skip_reason_key(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::Excluded => "excluded",
        SkipReason::IgnoreFile => "ignore_file",
        SkipReason::Generated => "generated",
        SkipReason::Unreadable => "unreadable",
        SkipReason::Unparseable => "unparseable",
        SkipReason::Unpinned => "unpinned",
        SkipReason::Unstated => "unstated",
    }
}

/// The `dependency_lookup` value for a CVE status, by variant only.
///
/// Exhaustive on purpose: a new [`CveStatus`] variant must be mapped here.
const fn dependency_lookup(status: &CveStatus) -> &'static str {
    match status {
        CveStatus::Checked { .. } => "ok",
        CveStatus::Partial { .. } | CveStatus::Unreachable { .. } => "failed",
        CveStatus::NoManifest => "skipped",
        CveStatus::SkippedOffline => "offline",
    }
}

/// Lowercase severity name.
const fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

/// Lowercase kind name.
const fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Defect => "defect",
        Kind::Observation => "observation",
    }
}

/// Make a rule id acceptable to the schema: every character outside
/// `[A-Za-z0-9_.:-]` becomes `_`, the result is cut to 128 characters, and an
/// empty id becomes `unknown`.
///
/// Shipped rule ids already satisfy the schema and pass through unchanged;
/// this exists so that a rule id loaded from somewhere else cannot make a
/// body invalid, or smuggle arbitrary text into it.
#[must_use]
pub fn sanitise_rule_id(rule_id: &str) -> String {
    let cleaned: String = rule_id
        .chars()
        .take(MAX_RULE_ID_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "unknown".to_owned()
    } else {
        cleaned
    }
}

/// Whether `version` matches the schema's pattern
/// `^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$` and length limit.
fn is_valid_version(version: &str) -> bool {
    if version.len() > MAX_VERSION_CHARS {
        return false;
    }
    let (core, suffix) = match version.find(['-', '+']) {
        Some(at) => (&version[..at], Some(&version[at + 1..])),
        None => (version, None),
    };
    let mut parts = core.split('.');
    let numeric = |part: Option<&str>| {
        part.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    let core_ok = numeric(parts.next())
        && numeric(parts.next())
        && numeric(parts.next())
        && parts.next().is_none();
    let suffix_ok = suffix.is_none_or(|s| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    });
    core_ok && suffix_ok
}

/// A fresh random run identifier: a lowercase, hyphenated UUID version 4.
///
/// # Errors
///
/// Returns the operating system's error if it has no source of randomness.
pub fn new_run_id() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(uuid_v4(bytes))
}

/// Format 16 random bytes as a version 4, RFC 4122 variant UUID.
fn uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut out = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

/// One lowercase hexadecimal digit for the low four bits of `value`.
const fn hex_digit(value: u8) -> char {
    match value & 0x0f {
        digit @ 0..=9 => (b'0' + digit) as char,
        digit => (b'a' + digit - 10) as char,
    }
}

/// Render `time` as `YYYY-MM-DDTHH:MM:SSZ` in UTC, whole seconds.
///
/// Times before 1970 render as the epoch, and times after year 9999 as the
/// last second of it: the schema accepts only four-digit years, and a clock
/// that far off is better reported as a boundary than as an unsendable body.
#[must_use]
pub fn format_timestamp(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed: Duration| elapsed.as_secs())
        .min(MAX_TIMESTAMP_SECS);
    let days = seconds / 86_400;
    let in_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        in_day / 3600,
        in_day % 3600 / 60,
        in_day % 60
    )
}

/// Convert a count of days since 1970-01-01 to a proleptic Gregorian
/// `(year, month, day)`.
///
/// The era-based algorithm: shift the epoch to 0000-03-01 so the leap day
/// falls at the end of the year, split into 400-year eras of 146 097 days,
/// then read the year, month and day off the day within the era.
const fn civil_from_days(days_since_epoch: u64) -> (u64, u64, u64) {
    let shifted = days_since_epoch + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::finding::{Confidence, Finding, Location};
    use crate::report::{Skip, Summary};

    const PROJECT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn meta() -> SummaryMeta {
        SummaryMeta {
            run_id: "3f2b8c1e-9a4d-4e6f-8b2a-1c5d7e9f0a3b".to_owned(),
            project_id: PROJECT.to_owned(),
            id_source: IdSource::Remote,
            started_at: UNIX_EPOCH + Duration::from_secs(1_790_000_000),
            finished_at: UNIX_EPOCH + Duration::from_secs(1_790_000_042),
            environment: Environment::Local,
        }
    }

    fn report(cve: CveStatus, skipped: Vec<Skip>, findings: Vec<Finding>) -> Report {
        Report {
            bastyn_version: "0.2.0".to_owned(),
            root: ".".to_owned(),
            summary: Summary {
                files_scanned: 7,
                files_skipped: skipped.len(),
                defects: 0,
                observations: 0,
            },
            cve,
            findings,
            skipped,
            coverage: crate::report::Coverage::default(),
            crosswalks: Vec::new(),
        }
    }

    fn finding(rule: &str, severity: Severity, kind: Kind) -> Finding {
        Finding {
            rule_id: rule.to_owned(),
            title: String::new(),
            kind,
            severity,
            confidence: Confidence::High,
            categories: vec![crate::Category::Llm04],
            location: Location {
                file: "a.py".into(),
                line: 1,
                column: 1,
            },
            snippet: String::new(),
            description: String::new(),
            remediation: String::new(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        }
    }

    fn value(summary: &ScanSummary) -> serde_json::Value {
        serde_json::from_slice(&summary.to_json().unwrap()).unwrap()
    }

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn empty_report_is_complete_with_no_findings() {
        let summary = ScanSummary::build(&report(CveStatus::NoManifest, vec![], vec![]), &meta());
        let json = value(&summary);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["scan_status"], "complete");
        assert_eq!(json["findings"], serde_json::json!([]));
        assert_eq!(json["coverage"]["skips_by_reason"], serde_json::json!({}));
        assert_eq!(json["coverage"]["dependency_lookup"], "skipped");
        assert_eq!(json["id_source"], "remote");
        assert_eq!(json["environment"], "local");
        assert_eq!(json["scanner_version"], "0.2.0");
        assert_eq!(json["started_at"], "2026-09-21T14:13:20Z");
        assert_eq!(summary.dropped_groups(), 0);
    }

    #[test]
    fn dependency_lookup_and_status_follow_the_cve_status() {
        let cases = [
            (CveStatus::Checked { dependencies: 3 }, "ok", "complete"),
            (
                CveStatus::Partial {
                    dependencies: 3,
                    incomplete: 1,
                },
                "failed",
                "partial",
            ),
            (
                CveStatus::Unreachable {
                    reason: "dns".to_owned(),
                },
                "failed",
                "partial",
            ),
            (CveStatus::NoManifest, "skipped", "complete"),
            (CveStatus::SkippedOffline, "offline", "complete"),
        ];
        for (cve, lookup, status) in cases {
            let json = value(&ScanSummary::build(
                &report(cve.clone(), vec![], vec![]),
                &meta(),
            ));
            assert_eq!(json["coverage"]["dependency_lookup"], lookup, "{cve:?}");
            assert_eq!(json["scan_status"], status, "{cve:?}");
        }
    }

    #[test]
    fn only_involuntary_skips_make_a_scan_partial() {
        let skip = |reason: SkipReason| match reason {
            SkipReason::Excluded => Skip::excluded("a".into(), "p"),
            SkipReason::IgnoreFile => Skip::ignore_file("a".into()),
            SkipReason::Generated => Skip::generated("a".into(), "m".into()),
            SkipReason::Unreadable => Skip::unreadable("a".into()),
            SkipReason::Unparseable => Skip::unparseable("a".into()),
            SkipReason::Unpinned => Skip::unpinned("a".into(), "n".into(), ">=1"),
            SkipReason::Unstated => serde_json::from_str("\"a\"").unwrap(),
        };
        let cases = [
            (SkipReason::Excluded, "excluded", "complete"),
            (SkipReason::IgnoreFile, "ignore_file", "complete"),
            (SkipReason::Generated, "generated", "complete"),
            (SkipReason::Unreadable, "unreadable", "partial"),
            (SkipReason::Unparseable, "unparseable", "partial"),
            (SkipReason::Unpinned, "unpinned", "partial"),
            (SkipReason::Unstated, "unstated", "complete"),
        ];
        for (reason, key, status) in cases {
            let skipped = vec![skip(reason), skip(reason)];
            let json = value(&ScanSummary::build(
                &report(CveStatus::NoManifest, skipped, vec![]),
                &meta(),
            ));
            assert_eq!(json["scan_status"], status, "{key}");
            assert_eq!(
                json["coverage"]["skips_by_reason"],
                serde_json::json!({ key: 2 })
            );
            assert_eq!(json["coverage"]["files_skipped"], 2);
        }
    }

    #[test]
    fn findings_group_by_rule_severity_and_kind() {
        let findings = vec![
            finding("B", Severity::Low, Kind::Observation),
            finding("A", Severity::High, Kind::Defect),
            finding("A", Severity::High, Kind::Defect),
            finding("A", Severity::High, Kind::Observation),
            finding("C", Severity::Critical, Kind::Defect),
            finding("A", Severity::Medium, Kind::Defect),
        ];
        let json = value(&ScanSummary::build(
            &report(CveStatus::NoManifest, vec![], findings),
            &meta(),
        ));
        let expected = serde_json::json!([
            {"rule_id": "C", "severity": "critical", "kind": "defect", "count": 1},
            {"rule_id": "A", "severity": "high", "kind": "defect", "count": 2},
            {"rule_id": "A", "severity": "high", "kind": "observation", "count": 1},
            {"rule_id": "A", "severity": "medium", "kind": "defect", "count": 1},
            {"rule_id": "B", "severity": "low", "kind": "observation", "count": 1},
        ]);
        assert_eq!(json["findings"], expected);
    }

    #[test]
    fn rule_ids_are_sanitised() {
        assert_eq!(sanitise_rule_id("BAS-LLM10-001"), "BAS-LLM10-001");
        assert_eq!(sanitise_rule_id("a.b:c_d-E9"), "a.b:c_d-E9");
        assert_eq!(sanitise_rule_id("has space/and\u{e9}"), "has_space_and_");
        assert_eq!(sanitise_rule_id(""), "unknown");
        assert_eq!(sanitise_rule_id(&"x".repeat(300)).len(), 128);
        assert_eq!(sanitise_rule_id(&"\u{e9}".repeat(300)), "_".repeat(128));
    }

    #[test]
    fn rule_ids_that_collapse_to_the_same_text_share_a_group() {
        let findings = vec![
            finding("a b", Severity::Low, Kind::Defect),
            finding("a/b", Severity::Low, Kind::Defect),
        ];
        let json = value(&ScanSummary::build(
            &report(CveStatus::NoManifest, vec![], findings),
            &meta(),
        ));
        assert_eq!(json["findings"].as_array().unwrap().len(), 1);
        assert_eq!(json["findings"][0]["count"], 2);
    }

    #[test]
    fn counters_are_clamped_to_the_schema_maximum() {
        let mut r = report(CveStatus::NoManifest, vec![], vec![]);
        r.summary.files_scanned = usize::MAX;
        let json = value(&ScanSummary::build(&r, &meta()));
        assert_eq!(json["coverage"]["files_scanned"], 10_000_000);
    }

    #[test]
    fn crate_version_is_accepted_and_bad_versions_fall_back() {
        assert!(is_valid_version(env!("CARGO_PKG_VERSION")));
        for good in ["0.1.8", "10.20.30", "1.2.3-rc.1", "1.2.3+build-5"] {
            assert!(is_valid_version(good), "{good}");
        }
        for bad in [
            "", "1.2", "1.2.3.4", "v1.2.3", "1.2.3-", "1.2.3 x", "1..3", "a.b.c",
        ] {
            assert!(!is_valid_version(bad), "{bad}");
        }
        assert!(!is_valid_version(&format!("1.2.3-{}", "a".repeat(64))));

        let mut r = report(CveStatus::NoManifest, vec![], vec![]);
        r.bastyn_version = "dev build".to_owned();
        let json = value(&ScanSummary::build(&r, &meta()));
        assert_eq!(json["scanner_version"], "0.0.0");
    }

    #[test]
    fn building_twice_gives_identical_bytes() {
        let findings = (0..50)
            .map(|n| finding(&format!("R{}", n % 7), Severity::High, Kind::Defect))
            .collect();
        let r = report(
            CveStatus::SkippedOffline,
            vec![Skip::unreadable("x".into())],
            findings,
        );
        let first = ScanSummary::build(&r, &meta()).to_json().unwrap();
        let second = ScanSummary::build(&r, &meta()).to_json().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn timestamps_match_known_answers() {
        // Generated with:
        // python3 -c 'import datetime;print(datetime.datetime.fromtimestamp(N, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))'
        let cases: [(u64, &str); 8] = [
            (0, "1970-01-01T00:00:00Z"),
            (86_399, "1970-01-01T23:59:59Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_709_208_000, "2024-02-29T12:00:00Z"),
            (1_735_689_599, "2024-12-31T23:59:59Z"),
            (2_147_483_648, "2038-01-19T03:14:08Z"),
            (1_790_000_000, "2026-09-21T14:13:20Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ];
        for (seconds, expected) in cases {
            assert_eq!(
                format_timestamp(UNIX_EPOCH + Duration::from_secs(seconds)),
                expected
            );
        }
    }

    #[test]
    fn timestamps_clamp_at_both_ends_and_drop_fractions() {
        assert_eq!(
            format_timestamp(UNIX_EPOCH - Duration::from_secs(1)),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            format_timestamp(UNIX_EPOCH + Duration::from_millis(1_999)),
            "1970-01-01T00:00:01Z"
        );
        assert_eq!(
            format_timestamp(UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) * 100)),
            "9999-12-31T23:59:59Z"
        );
    }

    #[test]
    fn run_ids_are_distinct_version_4_uuids() {
        let first = new_run_id().unwrap();
        let second = new_run_id().unwrap();
        assert_ne!(first, second);
        for id in [&first, &second] {
            assert_eq!(id.len(), 36);
            let bytes = id.as_bytes();
            assert!([8, 13, 18, 23].iter().all(|&i| bytes[i] == b'-'));
            assert_eq!(bytes[14], b'4');
            assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
            assert!(
                id.bytes()
                    .all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
        }
    }

    #[test]
    fn uuid_formatting_sets_version_and_variant_bits() {
        assert_eq!(uuid_v4([0xff; 16]), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert_eq!(uuid_v4([0; 16]), "00000000-0000-4000-8000-000000000000");
    }

    #[test]
    fn environment_detection() {
        let cases: [(&[(&str, &str)], Environment); 17] = [
            (&[], Environment::Local),
            (
                &[("GITHUB_ACTIONS", "true"), ("CI", "true")],
                Environment::GithubActions,
            ),
            (
                &[("GITLAB_CI", "true"), ("CI", "true")],
                Environment::GitlabCi,
            ),
            (&[("GITHUB_ACTIONS", "false")], Environment::Local),
            (&[("GITLAB_CI", "")], Environment::Local),
            (&[("CI", "true")], Environment::OtherCi),
            (&[("CI", "1")], Environment::OtherCi),
            (&[("CI", "false")], Environment::Local),
            (&[("CI", "FALSE")], Environment::Local),
            (&[("CI", "0")], Environment::Local),
            (&[("CI", "")], Environment::Local),
            (&[("JENKINS_URL", "http://j")], Environment::OtherCi),
            (&[("BUILD_NUMBER", "12")], Environment::OtherCi),
            (&[("TF_BUILD", "True")], Environment::OtherCi),
            (&[("CIRCLECI", "true")], Environment::OtherCi),
            (&[("BUILDKITE", "true")], Environment::OtherCi),
            (&[("CODEBUILD_BUILD_ID", "x")], Environment::OtherCi),
        ];
        for (vars, expected) in cases {
            assert_eq!(Environment::detect(&lookup(vars)), expected, "{vars:?}");
        }
        for name in OTHER_CI_VARIABLES {
            assert_eq!(
                Environment::detect(&lookup(&[(name, "x")])),
                Environment::OtherCi,
                "{name}"
            );
            assert_eq!(
                Environment::detect(&lookup(&[(name, "")])),
                Environment::Local,
                "{name}"
            );
        }
    }

    #[test]
    fn environment_names() {
        assert_eq!(Environment::GithubActions.as_str(), "github-actions");
        assert_eq!(Environment::GitlabCi.as_str(), "gitlab-ci");
        assert_eq!(Environment::OtherCi.as_str(), "other-ci");
        assert_eq!(Environment::Local.as_str(), "local");
    }
}
