//! Unit tests for the `exclude_if:` clause: a negative exclusion that drops
//! an otherwise-matching candidate when a Tier-2 structural predicate proves
//! the captured value is safe, rather than requiring proof of where it came
//! from the way `flow:` does.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;

use super::{RuleError, RuleSet, scan_source};

/// A dict of literal commands, looked up by a key checked against the dict
/// itself, is a closed value: the graph can prove it regardless of where the
/// key came from.
#[test]
fn exclude_if_closed_value_drops_a_dict_membership_checked_command() {
    let yaml = r"
rules:
  - id: TEST-EXCLUDE-CLOSED
    title: test
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - subprocess.run($ARG, shell=True)
    exclude_if:
      variable: ARG
      kind: closed_value
    description: test
    remediation: test
";
    let rules = RuleSet::from_yaml(yaml).unwrap();
    let source = "\
COMMANDS = {\"restart\": \"systemctl restart worker\"}


def run(component):
    if component not in COMMANDS:
        return \"unknown\"
    command = COMMANDS[component]
    subprocess.run(command, shell=True)
";
    let findings = scan_source(&rules, Path::new("t.py"), source);
    assert!(findings.is_empty(), "{findings:#?}");
}

/// The other direction: a value the graph cannot prove closed still reports,
/// so the exclusion does not cost recall on a genuinely open value.
#[test]
fn exclude_if_closed_value_still_fires_on_a_genuinely_open_value() {
    let yaml = r"
rules:
  - id: TEST-EXCLUDE-CLOSED-2
    title: test
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - subprocess.run($ARG, shell=True)
    exclude_if:
      variable: ARG
      kind: closed_value
    description: test
    remediation: test
";
    let rules = RuleSet::from_yaml(yaml).unwrap();
    let source = "\
def run(user_command):
    subprocess.run(user_command, shell=True)
";
    let findings = scan_source(&rules, Path::new("t.py"), source);
    assert_eq!(findings.len(), 1, "{findings:#?}");
}

/// An `exclude_if:` gate on a metavariable the matching pattern never bound
/// has no evidence to exclude with, and fails open -- the finding stays --
/// the opposite direction from `tests_flow.rs`'s
/// `a_flow_gate_on_an_unbound_metavariable_fails_closed`, where a `flow:`
/// gate on an unbound metavariable drops the finding instead.
#[test]
fn an_exclude_if_gate_on_an_unbound_metavariable_fails_open() {
    let yaml = r"
rules:
  - id: TEST-EXCLUDE-UNBOUND
    title: test
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - subprocess.run($ARG, shell=True)
    exclude_if:
      variable: NEVER_BOUND
      kind: closed_value
    description: test
    remediation: test
";
    let rules = RuleSet::from_yaml(yaml).unwrap();
    let source = "\
COMMANDS = {\"restart\": \"systemctl restart worker\"}


def run(component):
    if component not in COMMANDS:
        return \"unknown\"
    command = COMMANDS[component]
    subprocess.run(command, shell=True)
";
    let findings = scan_source(&rules, Path::new("t.py"), source);
    assert_eq!(findings.len(), 1, "{findings:#?}");
}

/// The graph is Python-only. An `exclude_if:` rule in a language it cannot
/// analyse is a load error, not a rule that quietly never excludes.
#[test]
fn exclude_if_rejects_a_non_python_language() {
    let yaml = r"
rules:
  - id: TEST-EXCLUDE-LANG
    title: test
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: javascript
    any:
      - eval($ARG)
    exclude_if:
      variable: ARG
      kind: closed_value
    description: test
    remediation: test
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(error, RuleError::ExcludeIfUnsupportedLanguage { .. }),
        "{error:?}"
    );
}

/// An empty `kind: []` list would compile into an exclusion that never
/// excludes anything -- no kind is ever "in" an empty set -- with nothing in
/// the report to say so. A load error catches it instead, the same contract
/// `flow.source: []` already keeps via `EmptyFlowSources`.
#[test]
fn exclude_if_rejects_an_empty_kind_list() {
    let yaml = r"
rules:
  - id: TEST-EXCLUDE-EMPTY-KIND
    title: test
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    exclude_if:
      variable: ARG
      kind: []
    description: test
    remediation: test
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(error, RuleError::EmptyExcludeIfKinds { .. }),
        "{error:?}"
    );
}

/// A command made only of `sys.executable` and literal text is closed; one
/// that also interpolates a function parameter is not.
#[test]
fn exclude_if_closed_value_drops_a_command_of_sys_executable_and_literals() {
    let yaml = r"
rules:
  - id: TEST-EXCLUDE-CLOSED-EXE
    title: test
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - os.system($ARG)
    exclude_if:
      variable: ARG
      kind: closed_value
    description: test
    remediation: test
";
    let rules = RuleSet::from_yaml(yaml).unwrap();
    let source = "\
import os
import sys


def install_fixed():
    os.system(f\"{sys.executable} -m pip install requests -q\")


def install_named(package):
    os.system(f\"{sys.executable} -m pip install {package}\")
";
    let findings = scan_source(&rules, Path::new("t.py"), source);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].location.line, 10);
}
