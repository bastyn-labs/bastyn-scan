//! End-to-end tests for `bastyn scan`, driving the real binary.
//!
//! These assert the CLI's contracts rather than the wording of its output:
//! exit codes, the shape of the machine formats, and the two behaviours that
//! keep the tool honest — that a context-dependent observation never fails a
//! build, and that an unchecked CVE section never reads as clean.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::fs;
use std::path::Path;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

/// Python that trips `BAS-LLM10-001`: `eval` on a model reply.
const VULNERABLE: &str = r#"
import openai


def advise(question):
    reply = openai.chat.completions.create(messages=[{"role": "user", "content": question}])
    return eval(reply.choices[0].message.content)
"#;

/// Python that a naive rule would flag and a precise one must not.
const NEAR_MISSES: &str = r#"
import os


def arithmetic():
    return eval("2 + 2")


APPROX_TOKENS = 12000
API_KEY_NAME = "OPENAI_API_KEY"
CLIENT_KEY = os.environ["OPENAI_API_KEY"]
"#;

fn tree(entries: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (name, contents) in entries {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
    }
    dir
}

fn bastyn(cwd: &Path) -> Command {
    let mut command = Command::cargo_bin("bastyn").unwrap();
    command.current_dir(cwd);
    // Keep assertions independent of the terminal the suite happens to run in.
    command.env("NO_COLOR", "1");
    // No test run may send a scan summary anywhere.
    command.env("DO_NOT_TRACK", "1");
    command
}

fn stdout_of(mut command: Command) -> String {
    let output = command.output().unwrap();
    String::from_utf8(output.stdout).unwrap()
}

/// `bastyn scan --offline --format json`, plus whatever else is passed.
fn json_scan(dir: &Path, extra: &[&str]) -> serde_json::Value {
    let stdout = stdout_of({
        let mut c = bastyn(dir);
        c.args(["scan", "--offline", "--format", "json"]);
        c.args(extra);
        c
    });
    serde_json::from_str(&stdout)
        .map_err(|error| format!("{error}, in:\n{stdout}"))
        .unwrap()
}

/// A scan with no flags carries every framework, in one array.
///
/// The default used to carry none, and a reader had to know a flag existed to
/// see any regulatory area at all — and then a second flag to see the other
/// framework, whichever one they had not asked for looking like an area with
/// nothing in it.
#[test]
fn the_default_carries_every_framework_in_the_json() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    for extra in [vec![], vec!["--group-by", "layer"]] {
        let report = json_scan(dir.path(), &extra);
        let walks = report["crosswalks"].as_array().unwrap();

        let ids: Vec<&str> = walks
            .iter()
            .map(|walk| walk["framework"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            ["eu-ai-act", "nist-ai-rmf", "nist-genai"],
            "{extra:?} must carry all three, in a fixed order"
        );

        for walk in walks {
            assert!(
                walk["disclaimer"]
                    .as_str()
                    .unwrap()
                    .contains("not a compliance assessment"),
                "each entry carries its own caveat"
            );
        }
    }
}

/// Naming a framework narrows the JSON to that one.
///
/// `--group-by` chooses which framework the terminal expands, and a machine
/// consumer gets the same answer: the reader asked about one document, so the
/// other two are not in the output they are about to process.
#[test]
fn group_by_a_framework_puts_the_crosswalk_in_the_json() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    for (flag, id, area) in [
        ("eu-ai-act", "eu-ai-act", "Art. 15"),
        ("nist-ai-rmf", "nist-ai-rmf", "MEASURE 2.7"),
        ("nist-genai", "nist-genai", "Information Security"),
    ] {
        let report = json_scan(dir.path(), &["--group-by", flag]);
        let walks = report["crosswalks"].as_array().unwrap();
        assert_eq!(walks.len(), 1, "{flag} asked for one framework");
        let walk = &walks[0];

        assert_eq!(walk["framework"], id, "{flag}");
        assert!(
            walk["disclaimer"]
                .as_str()
                .unwrap()
                .contains("not a compliance assessment"),
            "{flag} must carry its own caveat"
        );
        assert_ne!(walk["citation"].as_str().unwrap(), "");
        assert!(walk["source_url"].as_str().unwrap().starts_with("https://"));

        let groups = walk["groups"].as_array().unwrap();
        assert!(
            groups.iter().any(|group| group["id"] == area),
            "{flag} should have grouped the eval finding under {area}: {walk}"
        );

        // Every index addresses the report's own findings array.
        let findings = report["findings"].as_array().unwrap();
        for group in groups {
            for index in group["findings"].as_array().unwrap() {
                let index = usize::try_from(index.as_u64().unwrap()).unwrap();
                assert!(findings.get(index).is_some(), "{flag}: dangling index");
            }
        }
    }
}

/// Every key the JSON published before is still there, unrenamed, alongside
/// the crosswalks — whether or not a framework was named.
#[test]
fn the_crosswalk_is_additive_to_the_published_json_keys() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let default = json_scan(dir.path(), &[]);
    let grouped = json_scan(dir.path(), &["--group-by", "eu-ai-act"]);

    for key in ["bastyn_version", "root", "summary", "cve", "findings"] {
        assert_eq!(default[key], grouped[key], "{key} changed");
    }
    assert!(default.get("crosswalks").is_some());
    assert!(grouped.get("crosswalks").is_some());
    assert!(
        default.get("crosswalk").is_none() && grouped.get("crosswalk").is_none(),
        "the singular key is gone; the array replaced it"
    );
}

/// `coverage` is additive too: the published keys are unchanged beside it,
/// and all four of its own keys are present even when empty.
#[test]
fn coverage_is_additive_and_always_has_its_four_keys() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let report = json_scan(dir.path(), &[]);

    let coverage = report["coverage"].as_object().unwrap();
    for key in [
        "mcp_manifests",
        "skill_files",
        "instruction_files",
        "skipped",
    ] {
        assert_eq!(coverage[key], serde_json::json!([]), "{key}");
    }
}

#[test]
fn coverage_names_the_mcp_instruction_and_skill_files_that_were_read() {
    let dir = tree(&[
        (".mcp.json", r#"{"mcpServers":{}}"#),
        ("AGENTS.md", "# Agents\nBe careful.\n"),
        (
            "skills/foo/SKILL.md",
            "---\nname: foo\ndescription: does foo\n---\nBody.\n",
        ),
    ]);

    let report = json_scan(dir.path(), &[]);

    assert_eq!(
        report["coverage"],
        serde_json::json!({
            "mcp_manifests": [".mcp.json"],
            "skill_files": ["skills/foo/SKILL.md"],
            "instruction_files": ["AGENTS.md"],
            "skipped": [],
        })
    );
}

/// The terminal says what the grouping is not, in full, before it groups
/// anything — in both forms.
#[test]
fn the_terminal_crosswalk_states_its_limits() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    for extra in [vec![], vec!["--group-by", "eu-ai-act"]] {
        let stdout = stdout_of({
            let mut c = bastyn(dir.path());
            c.args(["scan", "--offline"]);
            c.args(&extra);
            c
        });

        let flat = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains(&flatten(bastyn_core::compliance::CROSSWALK_INTRO)),
            "{extra:?}: {stdout}"
        );
        assert!(
            flat.contains(&flatten(bastyn_core::compliance::TERMINAL_CAVEAT)),
            "{extra:?}: {stdout}"
        );
        assert!(
            flat.contains("Finding nothing does not mean an obligation is met."),
            "an empty table must not read as a clean bill of health: {stdout}"
        );
        assert!(flat.contains("2 December 2027"), "{stdout}");
        assert!(flat.contains("high-risk"), "{stdout}");

        // A verdict, in any spelling, must not reach the terminal at all.
        for word in bastyn_core::compliance::FORBIDDEN_CLAIMS {
            assert!(
                !stdout.to_lowercase().contains(word),
                "{word:?} reached the terminal: {stdout}"
            );
        }

        // The weaker words are scoped to the crosswalk: "Coverage gaps" is a
        // legitimate heading elsewhere in the report, and `gap` is on that
        // list. Transcribed article headings are exempt — NIST AI 100-1's
        // MAP 3.5 says "defined, assessed, and documented", and rewriting a
        // citation to satisfy a word list would be the worse failure.
        let section = without_transcriptions(&flatten(&crosswalk_section(&stdout)));
        for word in bastyn_core::compliance::FORBIDDEN_CHARACTERISATIONS {
            assert!(
                !section.to_lowercase().contains(word),
                "{word:?} reached the crosswalk's own prose: {section}"
            );
        }
    }
}

/// `text` with every run of whitespace collapsed, so an assertion about
/// wording is not also an assertion about where the lines were wrapped.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `text` with every transcribed article heading removed, including the
/// word-boundary prefixes the compact form cuts them to.
///
/// What is left is the prose Bastyn wrote itself, which is what
/// `FORBIDDEN_CHARACTERISATIONS` is about.
fn without_transcriptions(text: &str) -> String {
    let mut text = text.to_owned();
    for framework in bastyn_core::Framework::ALL {
        for control in framework.controls() {
            let words: Vec<&str> = control.title.split_whitespace().collect();
            for take in (1..=words.len()).rev() {
                text = text.replace(&words[..take].join(" "), " ");
            }
        }
    }
    text
}

/// A scan with no flags names all three frameworks, and says what the section
/// is not exactly once.
///
/// Once, not three times: a caveat repeated before every block is a caveat a
/// reader learns to skip past.
#[test]
fn the_default_terminal_report_names_every_framework_and_caveats_it_once() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline"]);
        c
    });
    let flat = stdout.split_whitespace().collect::<Vec<_>>().join(" ");

    for name in ["EU AI Act", "NIST AI RMF 1.0", "NIST Generative AI Profile"] {
        assert!(flat.contains(name), "{name} is missing from:\n{stdout}");
    }
    assert_eq!(
        flat.matches("Not a compliance assessment.").count(),
        1,
        "one caveat for the section, not one per framework:\n{stdout}"
    );
    assert!(
        flat.contains("Voluntary guidance, not a regulation"),
        "the NIST documents' standing must survive the summary:\n{stdout}"
    );
    // The document identifier, not the full title: it is the half a reader can
    // look up, and it is the half that fits on the heading line. The complete
    // citation is still in `--format json`.
    for framework in bastyn_core::Framework::ALL {
        assert!(
            flat.contains(framework.document_id()),
            "{} must name the document its identifiers come from:\n{stdout}",
            framework.name()
        );
    }
    let report = json_scan(dir.path(), &[]);
    for (walk, framework) in report["crosswalks"]
        .as_array()
        .unwrap()
        .iter()
        .zip(bastyn_core::Framework::ALL)
    {
        assert_eq!(
            walk["citation"].as_str(),
            Some(framework.citation()),
            "the machine format keeps the complete reference"
        );
    }
}

/// No framework heading in the crosswalk table wraps onto a second line.
///
/// It used to: the full document title pushed five of the six heading lines in
/// a three-framework table into a hanging continuation, and a reader met two
/// lines of citation before the first count.
#[test]
fn a_framework_heading_fits_on_one_line() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    for extra in [vec![], vec!["--group-by", "nist-genai"]] {
        let stdout = stdout_of({
            let mut c = bastyn(dir.path());
            c.args(["scan", "--offline"]);
            c.args(&extra);
            c
        });
        let lines: Vec<&str> = stdout.lines().collect();

        for framework in bastyn_core::Framework::ALL {
            let Some(at) = lines
                .iter()
                .position(|line| line.starts_with(framework.name()))
            else {
                continue;
            };
            assert!(
                lines[at].contains(framework.document_id()),
                "{extra:?}: the whole heading must fit on its line: {:?}",
                lines[at]
            );
            let next = lines.get(at + 1).copied().unwrap_or_default();
            let indent = next.len() - next.trim_start().len();
            assert!(
                indent <= 2,
                "{extra:?}: {:?} wrapped into {next:?}",
                lines[at]
            );
        }
    }
}

/// The default's crosswalk section does not grow with the findings.
///
/// Asserted structurally rather than by counting lines: the summary lists
/// areas and counts, and never a per-finding line, so its size is a property
/// of how many areas a framework has and not of what the scan found. The
/// detailed form is where the findings are listed, and this checks that it
/// takes the flag to get there.
#[test]
fn the_default_crosswalk_section_lists_no_individual_finding() {
    let dir = tree(&[
        ("agents.py", VULNERABLE),
        ("more.py", VULNERABLE),
        ("again.py", VULNERABLE),
    ]);

    let default = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline"]);
        c
    });
    let section = crosswalk_section(&default);
    assert!(
        !section.contains("BAS-"),
        "the summary must not list findings:\n{section}"
    );
    assert!(
        section.contains("3 defects"),
        "it must still carry the counts:\n{section}"
    );

    // The same repository under --group-by does list them, which is what the
    // flag is for.
    let expanded = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--group-by", "eu-ai-act"]);
        c
    });
    let expanded = crosswalk_section(&expanded);
    assert_eq!(
        expanded.matches("BAS-LLM10-001").count(),
        3,
        "--group-by lists every finding under its area:\n{expanded}"
    );
}

/// Everything the terminal prints from the crosswalk heading up to the closing
/// summary.
fn crosswalk_section(stdout: &str) -> String {
    let start = stdout
        .find("Compliance crosswalk")
        .unwrap_or_else(|| unreachable!("no crosswalk section in:\n{stdout}"));
    let end = stdout[start..]
        .find("Scan complete:")
        .unwrap_or_else(|| unreachable!("no summary line in:\n{stdout}"));
    stdout[start..start + end].to_owned()
}

/// `--group-by` expands one framework and leaves the other two out.
#[test]
fn group_by_expands_one_framework_and_only_that_one() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--group-by", "eu-ai-act"]);
        c
    });
    let section = crosswalk_section(&stdout);

    assert!(section.contains("EU AI Act"), "{section}");
    assert!(
        section.contains("BAS-LLM10-001"),
        "the detailed form lists the findings under each area:\n{section}"
    );
    assert!(
        section.contains("Accuracy, robustness and cybersecurity"),
        "and quotes the article heading whole:\n{section}"
    );
    for other in ["NIST AI RMF 1.0", "NIST Generative AI Profile"] {
        assert!(
            !section.contains(other),
            "{other} must not appear when one framework was named:\n{section}"
        );
    }
}

/// `--no-color`, and a non-tty, emit no ANSI byte with the default summary
/// present.
#[test]
fn the_default_crosswalk_emits_no_escape_byte() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    for extra in [
        vec!["--no-color"],
        vec![],
        vec!["--no-color", "--group-by", "nist-genai"],
    ] {
        let stdout = stdout_of({
            let mut c = bastyn(dir.path());
            c.args(["scan", "--offline"]);
            c.args(&extra);
            c
        });
        assert!(
            !stdout.contains('\u{1b}'),
            "{extra:?} emitted an escape byte:\n{stdout}"
        );
    }
}

/// SARIF gets every crosswalk as a taxonomy, and `tags` stays category ids.
#[test]
fn group_by_puts_the_crosswalk_in_sarif_taxonomies_not_tags() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args([
            "scan",
            "--offline",
            "--format",
            "sarif",
            "--group-by",
            "eu-ai-act",
        ]);
        c
    });
    let sarif: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let run = &sarif["runs"][0];

    let taxonomies = run["taxonomies"].as_array().unwrap();
    assert_eq!(taxonomies.len(), 1, "one framework was named");
    let taxonomy = &taxonomies[0];
    assert_eq!(taxonomy["name"], "EU AI Act");
    assert!(
        taxonomy["fullDescription"]["text"]
            .as_str()
            .unwrap()
            .contains("not a compliance assessment")
    );

    for rule in run["tool"]["driver"]["rules"].as_array().unwrap() {
        for tag in rule["properties"]["tags"].as_array().unwrap() {
            let tag = tag.as_str().unwrap();
            assert!(
                tag.starts_with("LLM") || tag.starts_with("ZT"),
                "a framework name reached SARIF tags: {tag}"
            );
        }
        for relationship in rule["relationships"].as_array().unwrap() {
            assert_eq!(relationship["kinds"][0], "relevant");
        }
    }
}

/// Default SARIF carries all three taxonomies, each relationship resolving to
/// the taxonomy its area came from.
///
/// The guid is what §3.52.3 resolves a descriptor reference by, so a
/// relationship that named the wrong component would file a finding under a
/// framework that never mentioned it. Tags stay the category ids throughout:
/// `tags` is what GitHub and GitLab index a rule by, and a framework name
/// there would make their UI read a finding as a regulatory violation.
#[test]
fn default_sarif_carries_every_taxonomy_and_still_only_category_tags() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--format", "sarif"]);
        c
    });
    let sarif: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let run = &sarif["runs"][0];

    let taxonomies = run["taxonomies"].as_array().unwrap();
    let names: Vec<&str> = taxonomies
        .iter()
        .map(|taxonomy| taxonomy["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["EU AI Act", "NIST AI RMF 1.0", "NIST Generative AI Profile"],
        "{stdout}"
    );

    let taxa_of = |guid: &str| -> Vec<String> {
        taxonomies
            .iter()
            .find(|taxonomy| taxonomy["guid"].as_str() == Some(guid))
            .map(|taxonomy| {
                taxonomy["taxa"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|taxon| taxon["id"].as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    };

    let mut related = 0;
    for rule in run["tool"]["driver"]["rules"].as_array().unwrap() {
        for tag in rule["properties"]["tags"].as_array().unwrap() {
            let tag = tag.as_str().unwrap();
            assert!(
                tag.starts_with("LLM") || tag.starts_with("ZT"),
                "a framework name reached SARIF tags: {tag}"
            );
        }
        for relationship in rule["relationships"].as_array().unwrap() {
            related += 1;
            assert_eq!(relationship["kinds"][0], "relevant");
            let target = &relationship["target"];
            let guid = target["toolComponent"]["guid"].as_str().unwrap();
            let id = target["id"].as_str().unwrap().to_owned();
            assert!(
                taxa_of(guid).contains(&id),
                "{id} is not a taxon of the taxonomy it points at: {stdout}"
            );
        }
    }
    assert!(related >= 3, "every framework must be reached: {stdout}");
}

/// Grouping is a view, not a filter: it never changes what the scan found or
/// whether the build fails — and neither does the default now carrying three
/// crosswalks it did not carry before.
#[test]
fn group_by_changes_no_finding_and_no_exit_code() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let default = json_scan(dir.path(), &[]);
    let grouped = json_scan(dir.path(), &["--group-by", "nist-genai"]);
    assert_eq!(default["findings"], grouped["findings"]);
    assert_eq!(default["summary"], grouped["summary"]);

    for extra in [vec![], vec!["--group-by", "nist-genai"]] {
        let mut command = bastyn(dir.path());
        command.args(["scan", "--offline"]);
        command.args(&extra);
        command.assert().failure();
    }

    // The line a reader trusts for "what did this scan find" is unchanged by
    // the section printed above it.
    let default_text = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline"]);
        c
    });
    let grouped_text = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--group-by", "eu-ai-act"]);
        c
    });
    let summary_line = |text: &str| -> String {
        text.lines()
            .rev()
            .find(|line| line.starts_with("Scan complete:"))
            .unwrap()
            .to_owned()
    };
    assert_eq!(summary_line(&default_text), summary_line(&grouped_text));
}

/// An unknown framework is rejected rather than silently ignored: a CI job
/// that asked for a grouping and got none would read the empty result as
/// "nothing to report".
#[test]
fn an_unknown_grouping_is_an_error() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    bastyn(dir.path())
        .args(["scan", "--offline", "--group-by", "iso-42001"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("eu-ai-act"));
}

#[test]
fn a_clean_tree_exits_zero() {
    let dir = tree(&[("safe.py", NEAR_MISSES)]);

    bastyn(dir.path())
        .args(["scan", "--offline"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No defects found"));
}

#[test]
fn near_misses_are_not_reported() {
    let dir = tree(&[("safe.py", NEAR_MISSES)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--format", "json"]);
        c
    });
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(
        report["summary"]["defects"], 0,
        "eval on a literal, approx_tokens, and os.environ must not be flagged: {stdout}"
    );
}

#[test]
fn eval_on_a_model_reply_is_a_critical_defect() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--format", "json"]);
        c
    });
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();

    assert_eq!(findings.len(), 1, "expected exactly one finding: {stdout}");
    assert_eq!(findings[0]["rule_id"], "BAS-LLM10-001");
    assert_eq!(findings[0]["severity"], "critical");
    assert_eq!(findings[0]["kind"], "defect");
}

#[test]
fn findings_exit_one_and_the_threshold_is_honoured() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    bastyn(dir.path())
        .args(["scan", "--offline", "--quiet"])
        .assert()
        .code(1);

    // The same critical finding, with failing switched off entirely.
    bastyn(dir.path())
        .args(["scan", "--offline", "--quiet", "--fail-on", "none"])
        .assert()
        .code(0);
}

/// The RESULT line and the exit code are the same fact.
///
/// A printed status that can disagree with `$?` is worse than no printed
/// status: a reader who sees FAILED and a CI step that sees 0 will each act on
/// what they were told, and only one of them is right.
#[test]
fn the_result_line_agrees_with_the_exit_code() {
    let failing = tree(&[("agents.py", VULNERABLE)]);
    let passing = tree(&[("safe.py", NEAR_MISSES)]);

    for (dir, extra, code, word, other) in [
        (
            failing.path(),
            vec![],
            1,
            "RESULT: FAILED",
            "RESULT: PASSED",
        ),
        (
            failing.path(),
            vec!["--fail-on", "none"],
            0,
            "RESULT: PASSED",
            "RESULT: FAILED",
        ),
        (
            passing.path(),
            vec![],
            0,
            "RESULT: PASSED",
            "RESULT: FAILED",
        ),
        (
            passing.path(),
            vec!["--fail-on", "low"],
            0,
            "RESULT: PASSED",
            "RESULT: FAILED",
        ),
    ] {
        let mut command = bastyn(dir);
        command.args(["scan", "--offline"]);
        command.args(&extra);
        let output = command.output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert_eq!(
            output.status.code(),
            Some(code),
            "{extra:?} over {dir:?} should exit {code}:\n{stdout}"
        );
        assert!(stdout.contains(word), "{extra:?}: {stdout}");
        assert!(!stdout.contains(other), "{extra:?}: {stdout}");
        assert!(
            stdout.contains(&format!("Exit status: {code}")),
            "the printed status must be the real one:\n{stdout}"
        );
    }
}

/// `--quiet` prints the summary, which is no longer the last line.
///
/// It used to be implemented as "the last line of the report", which was
/// correct only for as long as nothing was printed below the summary. Under
/// this layout that would hand a caller `Exit status: 1` and nothing else.
#[test]
fn quiet_prints_the_summary_and_not_the_exit_status_line() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let quiet = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--quiet"]);
        c
    });

    assert_eq!(
        quiet.lines().count(),
        1,
        "--quiet is one line, not a report:\n{quiet}"
    );
    let line = quiet.lines().next().unwrap();
    assert!(line.starts_with("Scan complete:"), "{line:?}");
    assert!(!quiet.contains("Exit status:"), "{quiet}");

    // And it is the same line the full report carries.
    let full = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline"]);
        c
    });
    assert!(full.contains(line), "{full}");
    assert_ne!(
        full.lines().next_back(),
        Some(line),
        "the summary is no longer last, which is the whole reason this broke"
    );
}

/// A report going anywhere but a terminal draws with ASCII.
///
/// A tick, a hollow circle, a box-drawing rule and a dagger all mangle
/// somewhere: an older Windows console, a CI log viewer that stores bytes, a
/// pasted snippet that lost its encoding.
#[test]
fn a_report_that_is_not_going_to_a_terminal_has_no_unicode_in_it() {
    let dir = tree(&[
        ("agents.py", VULNERABLE),
        ("requirements.txt", "flask>=2.0\n"),
    ]);

    for extra in [
        vec![],
        vec!["--show-observations"],
        vec!["--group-by", "eu-ai-act"],
    ] {
        // `bastyn` already sets NO_COLOR, and `assert_cmd` captures stdout, so
        // both halves of the fallback's trigger are exercised here.
        let stdout = stdout_of({
            let mut c = bastyn(dir.path());
            c.args(["scan", "--offline"]);
            c.args(&extra);
            c
        });

        assert!(
            stdout.is_ascii(),
            "{extra:?} emitted non-ASCII: {:?}",
            stdout.chars().filter(|c| !c.is_ascii()).collect::<String>()
        );
        assert!(stdout.contains("[ok] Discovered source tree"), "{stdout}");
        assert!(stdout.contains("[--] OSV vulnerability lookup"), "{stdout}");
    }
}

/// Observations are counted whether or not they are listed, and the report
/// says which of those two it is doing.
///
/// The old report printed "No observations." directly above a summary line
/// counting three of them.
#[test]
fn the_report_never_denies_the_observations_its_own_summary_counts() {
    let dir = tree(&[(
        "config.py",
        "OPENAI_API_KEY = \"sk-proj-7f3a9c1e5d8b2a6f4c0e9d7b3a5f8c1e\"\n\
         PASSWORD = \"hunter2placeholder\"\n",
    )]);

    let hidden = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--fail-on", "none"]);
        c
    });
    let counted = observation_count(&hidden);

    if counted > 0 {
        assert!(
            hidden.contains(&format!("{counted} observation")) && hidden.contains("hidden"),
            "the report must say how many it is withholding:\n{hidden}"
        );
        assert!(
            hidden.contains("--show-observations"),
            "and which flag shows them:\n{hidden}"
        );
        assert!(
            !hidden.contains("No observations."),
            "it must not deny what its own summary counts:\n{hidden}"
        );

        let shown = stdout_of({
            let mut c = bastyn(dir.path());
            c.args([
                "scan",
                "--offline",
                "--fail-on",
                "none",
                "--show-observations",
            ]);
            c
        });
        assert!(shown.contains("OBSERVATIONS"), "{shown}");
        assert!(!shown.contains("hidden"), "{shown}");
        assert_eq!(observation_count(&shown), counted);
    }

    // A tree with nothing context-dependent in it says so plainly.
    let clean = tree(&[("safe.py", NEAR_MISSES)]);
    let text = stdout_of({
        let mut c = bastyn(clean.path());
        c.args(["scan", "--offline"]);
        c
    });
    assert!(text.contains("No observations."), "{text}");
    assert!(!text.contains("hidden"), "{text}");
}

/// The observation count the closing summary states.
fn observation_count(stdout: &str) -> usize {
    stdout
        .lines()
        .find(|line| line.starts_with("Scan complete:"))
        .and_then(|line| {
            line.split(", ")
                .find(|part| part.contains("observation"))
                .and_then(|part| part.split_whitespace().next())
                .and_then(|count| count.parse().ok())
        })
        .unwrap_or_else(|| unreachable!("no summary line in:\n{stdout}"))
}

/// The flag is `--show-observations`, and the old spelling is gone.
#[test]
fn the_observation_flag_is_spelled_one_way() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    bastyn(dir.path())
        .args([
            "scan",
            "--offline",
            "--show-observations",
            "--fail-on",
            "none",
        ])
        .assert()
        .code(0);

    bastyn(dir.path())
        .args(["scan", "--offline", "--include-observations"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--show-observations"));
}

/// Every reason a path can leave the scan reaches the reader, stated once per
/// reason rather than once per entry.
///
/// No single repository produces all of them, so this builds one that does.
#[test]
fn every_coverage_gap_category_reaches_the_terminal() {
    let dir = tree(&[
        ("agents.py", VULNERABLE),
        ("broken.py", "def (((( not python\n"),
        ("vendor/lib.py", "x = 1\n"),
        ("requirements.txt", "flask>=2.0\nrequests==2.31.0\n"),
        (".bastynignore", "*.log\n"),
        ("web/bundle.js", &"var a=1;".repeat(20_000)),
    ]);
    // Not valid UTF-8, so it is unreadable rather than unparseable.
    fs::write(dir.path().join("binary.py"), [0x00_u8, 0xff, 0xfe, 0x01]).unwrap();

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--exclude", "vendor/", "--hidden"]);
        c
    });

    for expected in [
        "excluded by a pattern given on the command line",
        ".bastynignore file was honoured",
        "bytes say it is generated",
        "could not be read, or is not valid UTF-8",
        "could not be parsed",
        "unpinned version and could not be matched to CVEs",
    ] {
        assert!(
            stdout.contains(expected),
            "{expected:?} is missing from:\n{stdout}"
        );
    }

    // The reason belongs to the group, not to each line under it.
    assert_eq!(
        stdout.matches("could not be matched to CVEs").count(),
        1,
        "{stdout}"
    );
    assert!(stdout.contains("Coverage gaps"), "{stdout}");
}

/// No line of the report runs off an eighty-column terminal, over a tree with
/// long paths and the rules whose remediation is longest.
#[test]
fn nothing_the_binary_prints_runs_past_eighty_columns() {
    let dir = tree(&[
        (
            "services/ingestion/pipelines/enrichment/handlers/generated/deeply/nested/model_output_handler_implementation.py",
            VULNERABLE,
        ),
        ("requirements.txt", "flask>=2.0\n"),
    ]);

    for extra in [
        vec![],
        vec!["--show-observations"],
        vec!["--group-by", "nist-genai"],
    ] {
        let stdout = stdout_of({
            let mut c = bastyn(dir.path());
            c.args(["scan", "--offline"]);
            c.args(&extra);
            c
        });
        for line in stdout.lines() {
            assert!(
                line.chars().count() <= 80,
                "{extra:?} printed {} characters: {line:?}",
                line.chars().count()
            );
        }
    }
}

#[test]
fn an_unreadable_root_is_an_execution_error_not_a_finding() {
    let dir = TempDir::new().unwrap();

    bastyn(dir.path())
        .args(["scan", "does-not-exist"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("could not scan"));
}

#[test]
fn invalid_usage_is_also_an_execution_error() {
    let dir = TempDir::new().unwrap();

    bastyn(dir.path())
        .args(["scan", "--nope"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn mcp_misconfiguration_is_found_in_json_yaml_and_toml() {
    let cases = [
        (
            "mcp.json",
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","server","/"]}}}"#,
        ),
        (
            "mcp.yaml",
            "mcpServers:\n  fs:\n    command: npx\n    args: [\"-y\", \"server\", \"/\"]\n",
        ),
        (
            "mcp.toml",
            "[mcpServers.fs]\ncommand = \"npx\"\nargs = [\"-y\", \"server\", \"/\"]\n",
        ),
    ];

    for (name, contents) in cases {
        let dir = tree(&[(name, contents)]);
        let stdout = stdout_of({
            let mut c = bastyn(dir.path());
            c.args(["scan", "--offline", "--format", "json"]);
            c
        });
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        // The point of this test is format parity, not a finding count: the
        // same config expressed three ways must yield the same rules. Asserting
        // on the set of rule ids rather than a total means adding a rule that
        // legitimately fires here does not look like a parity failure.
        let mut rules: Vec<&str> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["rule_id"].as_str().unwrap())
            .collect();
        rules.sort_unstable();

        assert_eq!(
            rules,
            ["BAS-MCP-001", "BAS-MCP-005"],
            "{name} should yield the same rules as the other formats: {stdout}"
        );
    }
}

#[test]
fn observations_are_hidden_by_default_and_never_fail_the_build() {
    // No observation rules ship yet, so this asserts the contract structurally:
    // the summary counts observations separately from defects, and the default
    // findings list carries only defects.
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--format", "json"]);
        c
    });
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(report["summary"]["observations"].is_number());
    for finding in report["findings"].as_array().unwrap() {
        assert_eq!(
            finding["kind"], "defect",
            "observations must not appear without --show-observations"
        );
    }
}

#[test]
fn an_unchecked_cve_section_says_so() {
    let dir = tree(&[("requirements.txt", "requests==2.19.1\n")]);

    bastyn(dir.path())
        .args(["scan", "--offline"])
        .assert()
        .stdout(predicate::str::contains("Coverage gaps"))
        .stdout(predicate::str::contains(
            "CVEs were not checked because the scan ran in offline mode.",
        ));
}

#[test]
fn an_unpinned_dependency_is_reported_as_unchecked_not_guessed() {
    let dir = tree(&[("requirements.txt", "flask>=2.0\n")]);

    bastyn(dir.path())
        .args(["scan", "--offline"])
        .assert()
        .stdout(predicate::str::contains(
            "1 dependency has an unpinned version and could not be matched to CVEs:",
        ))
        .stdout(predicate::str::contains("requirements.txt:1"))
        .stdout(predicate::str::contains("flask"));
}

#[test]
fn sarif_output_is_valid_and_rule_indices_resolve() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--format", "sarif"]);
        c
    });
    let sarif: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    for result in run["results"].as_array().unwrap() {
        let index = usize::try_from(result["ruleIndex"].as_u64().unwrap()).unwrap();
        assert_eq!(
            rules[index]["id"], result["ruleId"],
            "ruleIndex must point at the matching rule"
        );
    }
}

#[test]
fn text_output_carries_no_escape_bytes_with_no_color() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--no-color"]);
        c
    });

    assert!(
        !stdout.contains('\u{1b}'),
        "found an ANSI escape: {stdout:?}"
    );
}

#[test]
fn gitignored_and_hidden_files_are_skipped_unless_asked_for() {
    let dir = tree(&[
        ("safe.py", NEAR_MISSES),
        ("ignored/agents.py", VULNERABLE),
        (".gitignore", "ignored/\n"),
    ]);

    bastyn(dir.path())
        .args(["scan", "--offline", "--quiet"])
        .assert()
        .code(0);

    bastyn(dir.path())
        .args(["scan", "--offline", "--quiet", "--no-ignore"])
        .assert()
        .code(1);
}

/// The flag that matters most when the repository is not yours: you cannot
/// add a `.bastynignore` to somebody else's checkout, and `--exclude` is what
/// is left.
#[test]
fn exclude_drops_matching_paths_and_reports_every_one() {
    let dir = tree(&[
        ("agents.py", VULNERABLE),
        ("thirdparty/agents.py", VULNERABLE),
    ]);

    let report: serde_json::Value = serde_json::from_str(&stdout_of({
        let mut c = bastyn(dir.path());
        c.args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--exclude",
            "thirdparty/",
        ]);
        c
    }))
    .unwrap();

    let files: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["location"]["file"].as_str().unwrap())
        .collect();
    assert!(
        files.iter().all(|file| *file == "agents.py"),
        "the excluded copy must not be reported as a finding: {files:?}"
    );

    let skipped: Vec<&str> = report["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect();
    assert!(
        skipped
            .iter()
            .any(|entry| entry.starts_with("thirdparty/ \u{2014} excluded by pattern")),
        "an exclusion the report does not mention is a hiding place: {skipped:?}"
    );
}

#[test]
fn exclude_is_repeatable() {
    let dir = tree(&[
        ("keep.py", NEAR_MISSES),
        ("one/agents.py", VULNERABLE),
        ("two/agents.py", VULNERABLE),
    ]);

    bastyn(dir.path())
        .args([
            "scan",
            "--offline",
            "--quiet",
            "--exclude",
            "one/",
            "--exclude",
            "two/",
        ])
        .assert()
        .code(0);

    bastyn(dir.path())
        .args(["scan", "--offline", "--quiet", "--exclude", "one/"])
        .assert()
        .code(1);
}

/// A pattern that does not compile excludes nothing, so carrying on would
/// scan more than the user asked for and say nothing about it.
#[test]
fn a_malformed_exclude_pattern_fails_the_command() {
    let dir = tree(&[("agents.py", VULNERABLE)]);

    bastyn(dir.path())
        .args(["scan", "--offline", "--exclude", "dist/{unclosed"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("exclude pattern"));
}

/// "Do not commit this" and "not worth scanning" are different statements,
/// which is why `.bastynignore` earns a file of its own rather than leaning
/// on `.gitignore`.
#[test]
fn a_bastynignore_is_honoured_and_named_in_the_report() {
    let dir = tree(&[
        ("keep.py", NEAR_MISSES),
        ("vendored/agents.py", VULNERABLE),
        (".bastynignore", "vendored/\n"),
    ]);

    bastyn(dir.path())
        .args(["scan", "--offline", "--quiet"])
        .assert()
        .code(0);

    let report: serde_json::Value = serde_json::from_str(&stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline", "--format", "json"]);
        c
    }))
    .unwrap();

    let skipped: Vec<&str> = report["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect();
    assert!(
        skipped
            .iter()
            .any(|entry| entry.starts_with(".bastynignore \u{2014}")),
        "the report must say a .bastynignore reduced its coverage: {skipped:?}"
    );

    // And `--no-ignore` reaches it again, so nothing can hide behind the file
    // permanently.
    bastyn(dir.path())
        .args(["scan", "--offline", "--quiet", "--no-ignore"])
        .assert()
        .code(1);
}

#[test]
fn repeated_scans_produce_byte_identical_output() {
    // The SCOPE requires that an agent can re-run a scan to verify its own
    // fix. Any iteration-order dependence in the pipeline breaks that, and it
    // shows up as flaky output rather than a failure.
    let dir = tree(&[
        ("agents.py", VULNERABLE),
        ("safe.py", NEAR_MISSES),
        (
            "mcp.json",
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","s","/"]}}}"#,
        ),
        ("requirements.txt", "requests==2.19.1\nflask>=2.0\n"),
    ]);

    // Both formats: the text report groups findings into sections, which is
    // another place an unordered container could leak iteration order into
    // what a reader sees.
    for format in ["json", "text"] {
        let run = || {
            stdout_of({
                let mut c = bastyn(dir.path());
                c.args(["scan", "--offline", "--format", format]);
                c
            })
        };

        let first = run();
        for attempt in 1..4 {
            assert_eq!(
                first,
                run(),
                "{format} output differed on run {}",
                attempt + 1
            );
        }
    }
}

#[test]
fn the_text_report_groups_defects_by_threat_layer() {
    // A hardcoded key (ZT1, a missing defense) and eval on a model reply
    // (LLM10, cross-layer). The point of the grouping is that these do not
    // read as two equal items in one list.
    let dir = tree(&[
        ("agents.py", VULNERABLE),
        (
            "config.py",
            "OPENAI_API_KEY = \"sk-proj-7f3a9c1e5d8b2a6f4c0e9d7b3a5f8c1e\"\n",
        ),
    ]);

    let stdout = stdout_of({
        let mut c = bastyn(dir.path());
        c.args(["scan", "--offline"]);
        c
    });

    let cross = stdout.find("CROSS-LAYER");
    let defenses = stdout.find("MISSING DEFENSES");
    assert!(
        cross.is_some() && defenses.is_some(),
        "expected layer headings in:\n{stdout}"
    );
    assert!(
        cross < defenses,
        "threats must be listed before the defenses they defeat:\n{stdout}"
    );
    assert!(
        stdout.find("BAS-LLM10-001") < defenses,
        "BAS-LLM10-001 is a threat, not a missing defense:\n{stdout}"
    );
}

#[test]
fn help_and_version_are_available() {
    let dir = TempDir::new().unwrap();

    bastyn(dir.path())
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan"));

    bastyn(dir.path())
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}
