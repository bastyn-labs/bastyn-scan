//! Checks the anonymous scan summary against the published JSON Schema.
//!
//! The schema and its example documents are copied, unmodified, from the
//! collector's contract into `tests/data/reporting/`. Rejecting every
//! `invalid/` document is what proves the validator really enforces the
//! schema; validating every summary this crate can build is what proves the
//! builder stays inside it.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assumption in a test should fail the test"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use bastyn_core::finding::{Confidence, Finding, Kind, Location, Severity};
use bastyn_core::report::{CveStatus, Report, Skip, Summary};
use bastyn_core::reporting::project_id::IdSource;
use bastyn_core::reporting::summary::{
    Environment, MAX_BODY_BYTES, ScanSummary, SummaryMeta, TARGET_BODY_BYTES, new_run_id,
    sanitise_rule_id,
};
use bastyn_core::{Category, ScanOptions, scan};
use boon::{Compiler, Schemas};
use serde_json::Value;

const SCHEMA_URL: &str = "https://bastyn.ai/schemas/scan-summary.v1.schema.json";

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/reporting")
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn schema_json() -> Value {
    let text = fs::read_to_string(data_dir().join("scan-summary.v1.schema.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Validate `document` against the schema, returning the validator's message
/// on rejection.
fn validate(document: &Value) -> Result<(), String> {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    compiler.add_resource(SCHEMA_URL, schema_json()).unwrap();
    let index = compiler.compile(SCHEMA_URL, &mut schemas).unwrap();
    schemas
        .validate(document, index)
        .map_err(|error| format!("{error:#}"))
}

fn validate_bytes(body: &[u8]) -> Result<(), String> {
    validate(&serde_json::from_slice(body).unwrap())
}

fn json_files(dir: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(data_dir().join(dir))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

fn meta() -> SummaryMeta {
    SummaryMeta {
        run_id: new_run_id().unwrap(),
        project_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        id_source: IdSource::Local,
        started_at: UNIX_EPOCH + Duration::from_secs(1_790_000_000),
        finished_at: UNIX_EPOCH + Duration::from_secs(1_790_000_042),
        environment: Environment::GithubActions,
    }
}

fn finding(rule: &str, severity: Severity, kind: Kind) -> Finding {
    Finding {
        rule_id: rule.to_owned(),
        title: "title".to_owned(),
        kind,
        severity,
        confidence: Confidence::High,
        categories: vec![Category::Llm04],
        location: Location {
            file: "src/app.py".into(),
            line: 3,
            column: 1,
        },
        snippet: "snippet".to_owned(),
        description: "description".to_owned(),
        remediation: "remediation".to_owned(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    }
}

fn report(cve: CveStatus, skipped: Vec<Skip>, findings: Vec<Finding>) -> Report {
    Report {
        bastyn_version: env!("CARGO_PKG_VERSION").to_owned(),
        root: "some/root".to_owned(),
        summary: Summary {
            files_scanned: 12,
            files_skipped: skipped.len(),
            defects: 0,
            observations: 0,
        },
        cve,
        findings,
        skipped,
        coverage: bastyn_core::Coverage::default(),
        crosswalks: Vec::new(),
    }
}

fn one_of_every_skip() -> Vec<Skip> {
    vec![
        Skip::excluded("vendor/".into(), "vendor/"),
        Skip::ignore_file(".bastynignore".into()),
        Skip::generated("web/bundle.js".into(), "minified".into()),
        Skip::unreadable("a.bin".into()),
        Skip::unparseable("broken.py".into()),
        Skip::unpinned("requirements.txt:2".into(), "flask".into(), ">=2.0"),
        serde_json::from_str("\"read back from json\"").unwrap(),
    ]
}

fn every_cve_status() -> Vec<CveStatus> {
    vec![
        CveStatus::Checked { dependencies: 4 },
        CveStatus::Partial {
            dependencies: 4,
            incomplete: 1,
        },
        CveStatus::NoManifest,
        CveStatus::SkippedOffline,
        CveStatus::Unreachable {
            reason: "timed out".to_owned(),
        },
    ]
}

#[test]
fn every_valid_fixture_validates() {
    let files = json_files("valid");
    assert_eq!(files.len(), 3);
    for file in files {
        let document: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        if let Err(message) = validate(&document) {
            panic!("{} was rejected: {message}", file.display());
        }
    }
}

#[test]
fn every_invalid_fixture_is_rejected() {
    let files = json_files("invalid");
    assert_eq!(files.len(), 21);
    for file in files {
        let document: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        assert!(
            validate(&document).is_err(),
            "{} was accepted by the validator",
            file.display()
        );
    }
}

#[test]
fn empty_report_validates() {
    let summary = ScanSummary::build(&report(CveStatus::NoManifest, vec![], vec![]), &meta());
    validate_bytes(&summary.to_json().unwrap()).unwrap();
}

#[test]
fn busy_report_validates_for_every_cve_status() {
    let findings: Vec<Finding> = (0..300)
        .map(|n| {
            let severity = [
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ][n % 4];
            let kind = if n % 3 == 0 {
                Kind::Observation
            } else {
                Kind::Defect
            };
            finding(&format!("RULE-{}", n % 40), severity, kind)
        })
        .collect();
    for cve in every_cve_status() {
        let r = report(cve.clone(), one_of_every_skip(), findings.clone());
        let summary = ScanSummary::build(&r, &meta());
        validate_bytes(&summary.to_json().unwrap()).unwrap_or_else(|m| panic!("{cve:?}: {m}"));
        assert_eq!(summary.dropped_groups(), 0);
    }
}

#[test]
fn real_offline_scans_of_the_fixtures_validate() {
    for (name, observations) in [
        ("vulnerable_agent", false),
        ("vulnerable_agent", true),
        ("clean_agent", false),
        ("clean_agent", true),
    ] {
        let options = ScanOptions {
            offline: true,
            include_observations: observations,
            ..ScanOptions::default()
        };
        let scanned = scan(&fixtures_dir().join(name), &options).unwrap();
        let summary = ScanSummary::build(&scanned, &meta());
        let body = summary.to_json().unwrap();
        validate_bytes(&body).unwrap_or_else(|m| panic!("{name}: {m}"));
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["coverage"]["dependency_lookup"], "offline", "{name}");
        assert_eq!(
            json["coverage"]["files_scanned"].as_u64().unwrap(),
            scanned.summary.files_scanned as u64
        );
        if name == "vulnerable_agent" {
            assert_ne!(json["findings"].as_array().unwrap().len(), 0);
        }
    }
}

#[test]
fn no_free_text_reaches_the_body() {
    let marker = |what: &str| format!("LEAKMARK_{what}_Zx9");
    let mut noisy = finding("BAS-CLEAN-001", Severity::High, Kind::Defect);
    noisy.title = marker("title");
    noisy.snippet = marker("snippet");
    noisy.description = marker("description");
    noisy.remediation = marker("remediation");
    noisy.location.file = PathBuf::from(marker("file"));
    noisy.references = vec![marker("reference")];
    noisy.secondary_rule_ids = vec![marker("secondary")];

    let mut r = report(
        CveStatus::Unreachable {
            reason: marker("cve_reason"),
        },
        vec![
            Skip::unpinned(
                marker("skip_path"),
                marker("skip_detail"),
                &marker("constraint"),
            ),
            Skip::generated(marker("gen_path"), marker("gen_detail")),
            Skip::excluded(marker("ex_path"), &marker("pattern")),
        ],
        vec![noisy.clone(), noisy],
    );
    r.root = marker("root");

    let summary = ScanSummary::build(&r, &meta());
    let body = summary.to_json().unwrap();
    let text = String::from_utf8(body.clone()).unwrap();
    assert!(
        !text.contains("LEAKMARK"),
        "a marker reached the body: {text}"
    );
    assert!(text.contains("BAS-CLEAN-001"));
    validate_bytes(&body).unwrap();

    // The key set is exactly the schema's, at every level.
    let schema = schema_json();
    let keys = |value: &Value| -> BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    };
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(keys(&json), keys(&schema["properties"]));
    assert_eq!(
        keys(&json["coverage"]),
        keys(&schema["properties"]["coverage"]["properties"])
    );
    assert_eq!(
        keys(&json["findings"][0]),
        keys(&schema["properties"]["findings"]["items"]["properties"])
    );
    assert_eq!(json["findings"][0]["count"], 2);
}

/// A rule id of exactly 128 characters, unique for each `n`.
fn long_id(n: usize) -> String {
    format!("R{n:0>127}")
}

#[test]
fn oversized_findings_are_truncated_to_the_highest_priority_groups() {
    let mut findings = Vec::new();
    for n in 0..20 {
        findings.push(finding(
            &long_id(1000 + n),
            Severity::Critical,
            Kind::Defect,
        ));
    }
    for n in 0..580 {
        findings.push(finding(&long_id(n), Severity::Low, Kind::Observation));
    }
    let r = report(CveStatus::Checked { dependencies: 1 }, vec![], findings);
    let summary = ScanSummary::build(&r, &meta());
    let body = summary.to_json().unwrap();

    assert!(body.len() < MAX_BODY_BYTES);
    assert!(body.len() <= TARGET_BODY_BYTES);
    validate_bytes(&body).unwrap();

    let json: Value = serde_json::from_slice(&body).unwrap();
    let groups = json["findings"].as_array().unwrap();
    assert!(groups.len() <= 500);
    assert_eq!(json["scan_status"], "partial");
    assert!(summary.dropped_groups() > 0);
    assert_eq!(groups.len() + summary.dropped_groups(), 600);

    // Every critical group survives and leads.
    assert!(groups[..20].iter().all(|g| g["severity"] == "critical"));
    // The low groups kept are exactly the alphabetically first ones.
    let kept_low: Vec<&str> = groups[20..]
        .iter()
        .map(|g| g["rule_id"].as_str().unwrap())
        .collect();
    let expected: Vec<String> = (0..kept_low.len()).map(long_id).collect();
    assert_eq!(
        kept_low,
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
}

#[test]
fn many_short_groups_that_fit_stay_complete() {
    let findings: Vec<Finding> = (0..400)
        .map(|n| finding(&format!("R{n:03}"), Severity::Low, Kind::Defect))
        .collect();
    let r = report(CveStatus::Checked { dependencies: 1 }, vec![], findings);
    let summary = ScanSummary::build(&r, &meta());
    let body = summary.to_json().unwrap();
    assert!(body.len() <= TARGET_BODY_BYTES);
    validate_bytes(&body).unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["findings"].as_array().unwrap().len(), 400);
    assert_eq!(json["scan_status"], "complete");
    assert_eq!(summary.dropped_groups(), 0);
}

#[test]
fn five_hundred_short_groups_never_exceed_either_limit() {
    // Even the shortest possible group entry is large enough that 500 of them
    // overrun the size target, so the size guard, not the 500 cap, decides.
    let findings: Vec<Finding> = (0..500)
        .map(|n| finding(&format!("R{n:03}"), Severity::Low, Kind::Defect))
        .collect();
    let r = report(CveStatus::Checked { dependencies: 1 }, vec![], findings);
    let summary = ScanSummary::build(&r, &meta());
    let body = summary.to_json().unwrap();
    assert!(body.len() <= TARGET_BODY_BYTES);
    validate_bytes(&body).unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let kept = json["findings"].as_array().unwrap().len();
    assert!(kept <= 500);
    assert_eq!(kept + summary.dropped_groups(), 500);
    assert_eq!(
        json["scan_status"],
        if summary.dropped_groups() > 0 {
            "partial"
        } else {
            "complete"
        }
    );
}

#[test]
fn truncation_is_deterministic() {
    let findings: Vec<Finding> = (0..600)
        .map(|n| finding(&long_id(n), Severity::Medium, Kind::Defect))
        .collect();
    let r = report(CveStatus::NoManifest, vec![], findings);
    let fixed = meta();
    let first = ScanSummary::build(&r, &fixed);
    let second = ScanSummary::build(&r, &fixed);
    assert_eq!(first.to_json().unwrap(), second.to_json().unwrap());
    assert_eq!(first.dropped_groups(), second.dropped_groups());
}

/// Every `id:` in a shipped rule file, found by parsing the YAML.
fn shipped_rule_ids() -> Vec<String> {
    let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    let mut ids = Vec::new();
    for entry in fs::read_dir(rules_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "yml") {
            continue;
        }
        let document: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let Some(rules) = document
            .get("rules")
            .and_then(serde_yaml_ng::Value::as_sequence)
        else {
            continue;
        };
        for rule in rules {
            ids.push(rule.get("id").unwrap().as_str().unwrap().to_owned());
        }
    }
    ids
}

#[test]
fn shipped_rule_ids_pass_the_sanitiser_unchanged() {
    let ids = shipped_rule_ids();
    assert!(
        ids.len() > 10,
        "expected the shipped rules, found {}",
        ids.len()
    );
    for id in ids {
        assert_eq!(sanitise_rule_id(&id), id);
    }
}
