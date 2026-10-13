//! The skill case suite: records what the scanner does with synthetic malicious
//! and benign agent skills under `tests/skill_cases`. It is separate from
//! the release gate (`corpus_gate.rs`) on purpose: it records many known
//! misses and false positives and must not count against that gate's caps.
//!
//! Labels in `cases.toml` say what the content really is. `outcome_now` says
//! what the scanner currently does. The test fails when behaviour gets worse
//! than `outcome_now`, prints a notice when it gets better, and fails when a
//! case directory and a manifest entry do not match. See
//! `tests/skill_cases/README.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bastyn_core::{Finding, ScanOptions, scan};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(default, rename = "case")]
    cases: Vec<Case>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Label {
    Malicious,
    Benign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Outcome {
    Detected,
    Missed,
    Flagged,
    Clean,
}

/// One skill directory: its true label and the scanner's recorded behaviour.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    dir: String,
    label: Label,
    class: String,
    outcome_now: Outcome,
    rules: Vec<String>,
    why: String,
    /// A benign case whose observation is expected output, not a false positive.
    #[serde(default)]
    expected_observation: bool,
    /// The id of the matched case with the opposite label (see the README).
    #[serde(default)]
    pair: Option<String>,
}

impl Case {
    /// Whether `outcome` is the correct behaviour for this case's label.
    fn is_correct(&self, outcome: Outcome) -> bool {
        match self.label {
            Label::Malicious => outcome == Outcome::Detected,
            Label::Benign => outcome == Outcome::Clean || self.expected_observation,
        }
    }
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/skill_cases")
}

/// The case directory (`<label>/<id>`) a finding's path falls under.
fn case_dir_of(finding: &Finding) -> Option<String> {
    let parts: Vec<String> = finding
        .location
        .file
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    (parts.len() > 2).then(|| format!("{}/{}", parts[0], parts[1]))
}

/// The outcome the label's vocabulary uses for "any finding here" or "none".
fn actual_outcome(label: Label, hit: bool) -> Outcome {
    match (label, hit) {
        (Label::Malicious, true) => Outcome::Detected,
        (Label::Malicious, false) => Outcome::Missed,
        (Label::Benign, true) => Outcome::Flagged,
        (Label::Benign, false) => Outcome::Clean,
    }
}

/// Case directories actually on disk, as `<label>/<id>`, sorted.
fn dirs_on_disk(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut found = BTreeSet::new();
    for label in ["malicious", "benign"] {
        let entries = std::fs::read_dir(root.join(label))
            .map_err(|e| format!("cannot read {label}/: {e}"))?;
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                found.insert(format!("{label}/{}", entry.file_name().to_string_lossy()));
            }
        }
    }
    Ok(found)
}

/// Structural checks on the manifest itself. Returns the failures.
fn check_manifest(cases: &[Case], on_disk: &BTreeSet<String>) -> Vec<String> {
    let mut failures = Vec::new();
    let mut listed = BTreeSet::new();
    for case in cases {
        if !listed.insert(case.dir.clone()) {
            failures.push(format!("{}: directory listed twice", case.id));
        }
        if !on_disk.contains(&case.dir) {
            failures.push(format!(
                "{}: directory {} does not exist",
                case.id, case.dir
            ));
        }
        let expected_parent = match case.label {
            Label::Malicious => "malicious/",
            Label::Benign => "benign/",
        };
        if !case.dir.starts_with(expected_parent) {
            failures.push(format!("{}: label does not match {}", case.id, case.dir));
        }
        let outcome_fits = match case.label {
            Label::Malicious => matches!(case.outcome_now, Outcome::Detected | Outcome::Missed),
            Label::Benign => matches!(case.outcome_now, Outcome::Clean | Outcome::Flagged),
        };
        if !outcome_fits {
            failures.push(format!("{}: outcome_now does not fit the label", case.id));
        }
        if case.why.trim().is_empty() || case.class.trim().is_empty() {
            failures.push(format!("{}: class and why must not be empty", case.id));
        }
    }
    let by_id: BTreeMap<&str, &Case> = cases.iter().map(|c| (c.id.as_str(), c)).collect();
    if by_id.len() != cases.len() {
        failures.push("case ids are not unique".to_string());
    }
    for case in cases {
        match (&case.pair, case.label) {
            (None, Label::Malicious) => failures.push(format!("{}: no pair", case.id)),
            (None, Label::Benign) => {}
            (Some(other), label) => match by_id.get(other.as_str()) {
                None => failures.push(format!("{}: pair {other} does not exist", case.id)),
                Some(twin) if twin.label == label => {
                    failures.push(format!("{}: pair {other} has the same label", case.id));
                }
                Some(twin) if twin.pair.as_deref() != Some(case.id.as_str()) => {
                    failures.push(format!("{}: pair {other} is not symmetric", case.id));
                }
                Some(_) => {}
            },
        }
    }
    for dir in on_disk.difference(&listed) {
        failures.push(format!("{dir}: directory has no [[case]] entry"));
    }
    failures
}

#[derive(Default)]
struct Tally {
    detected: usize,
    missed: usize,
    clean: usize,
    flagged: usize,
}

impl Tally {
    fn add(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Detected => self.detected += 1,
            Outcome::Missed => self.missed += 1,
            Outcome::Clean => self.clean += 1,
            Outcome::Flagged => self.flagged += 1,
        }
    }
}

fn print_row(name: &str, t: &Tally) {
    println!(
        "  {name:<24} malicious: {:>2} detected / {:>2} missed   benign: {:>2} clean / {:>2} flagged",
        t.detected, t.missed, t.clean, t.flagged
    );
}

/// One row per malicious/benign pair: both outcomes, and whether the scanner
/// separates them (flags the malicious case and stays silent on its twin).
fn print_pairs(cases: &[Case], actuals: &BTreeMap<&str, Outcome>) {
    println!("\npairs (malicious case, benign twin)");
    let (mut separated, mut total) = (0, 0);
    for case in cases.iter().filter(|c| c.label == Label::Malicious) {
        let Some(twin) = case.pair.as_deref() else {
            continue;
        };
        let (Some(&mal), Some(&ben)) = (actuals.get(case.id.as_str()), actuals.get(twin)) else {
            continue;
        };
        let apart = mal == Outcome::Detected && ben == Outcome::Clean;
        total += 1;
        separated += usize::from(apart);
        let verdict = if apart { "separated" } else { "not separated" };
        println!(
            "  {:<4} {:<9} | {:<4} {:<8} | {verdict}",
            case.id,
            format!("{mal:?}").to_lowercase(),
            twin,
            format!("{ben:?}").to_lowercase()
        );
    }
    println!("pairs separated: {separated} of {total}");
}

#[test]
fn skill_cases() -> Result<(), String> {
    let root = root();
    let text = std::fs::read_to_string(root.join("cases.toml"))
        .map_err(|e| format!("cannot read cases.toml: {e}"))?;
    let manifest: Manifest =
        toml::from_str(&text).map_err(|e| format!("cases.toml does not parse: {e}"))?;
    let mut failures = check_manifest(&manifest.cases, &dirs_on_disk(&root)?);

    let options = ScanOptions {
        offline: true,
        include_observations: true,
        ..ScanOptions::default()
    };
    let report = scan(&root, &options).map_err(|e| format!("scan failed: {e}"))?;
    let mut by_dir: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for finding in &report.findings {
        if let Some(dir) = case_dir_of(finding) {
            by_dir
                .entry(dir)
                .or_default()
                .insert(finding.rule_id.clone());
        }
    }

    let mut classes: BTreeMap<&str, Tally> = BTreeMap::new();
    let mut overall = Tally::default();
    let mut improved = Vec::new();
    let mut actuals: BTreeMap<&str, Outcome> = BTreeMap::new();
    for case in &manifest.cases {
        let rules = by_dir.get(&case.dir).cloned().unwrap_or_default();
        let actual = actual_outcome(case.label, !rules.is_empty());
        classes.entry(&case.class).or_default().add(actual);
        overall.add(actual);
        actuals.insert(&case.id, actual);

        let lost: Vec<&String> = case.rules.iter().filter(|r| !rules.contains(*r)).collect();
        if case.is_correct(case.outcome_now) && !case.is_correct(actual) {
            failures.push(format!(
                "{}: regressed from {:?} to {actual:?}",
                case.id, case.outcome_now
            ));
        } else if !lost.is_empty() {
            failures.push(format!("{}: no longer produces {lost:?}", case.id));
        } else if !case.is_correct(case.outcome_now) && case.is_correct(actual) {
            improved.push(format!("{}: {:?} -> {actual:?}", case.id, case.outcome_now));
        } else if rules.iter().any(|r| !case.rules.contains(r)) || actual != case.outcome_now {
            improved.push(format!("{}: rules now {rules:?}", case.id));
        }
    }

    println!("skill case suite (synthetic cases, not real-world rates)");
    for (class, tally) in &classes {
        print_row(class, tally);
    }
    print_row("OVERALL", &overall);
    print_pairs(&manifest.cases, &actuals);
    if !improved.is_empty() {
        println!("\nupdate cases.toml: behaviour changed for the better or sideways:");
        for line in &improved {
            println!("  {line}");
        }
    }
    assert!(
        failures.is_empty(),
        "skill case suite failures:\n  {}",
        failures.join("\n  ")
    );
    Ok(())
}
