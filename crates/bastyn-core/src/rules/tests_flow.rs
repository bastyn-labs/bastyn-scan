//! Unit tests for the `flow:` clause: a rule that fires on where a value came
//! from rather than on what it was called.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;

use super::{RuleError, RuleSet, scan_source};

/// The `flow:`-gated form of `BAS-LLM10-001`: no name gate anywhere in it.
const FLOW_RULE_YAML: &str = r"
rules:
  - id: BAS-FLOW-001
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
      - exec($ARG)
    flow:
      variable: ARG
      source: model_output
      unguarded: true
    description: Model output reaches eval().
    remediation: Do not execute model output.
";

fn flow_ruleset() -> RuleSet {
    RuleSet::from_yaml(FLOW_RULE_YAML).unwrap()
}

fn fires(ruleset: &RuleSet, source: &str) -> bool {
    scan_source(ruleset, Path::new("app/handler.py"), source)
        .iter()
        .any(|finding| finding.rule_id.starts_with("BAS-FLOW"))
}

/// The measurement this whole tier exists to move: the variable is named
/// something no keyword list contains, and the rule fires anyway.
#[test]
fn a_flow_gated_rule_fires_regardless_of_the_variable_name() {
    let ruleset = flow_ruleset();
    for name in ["response", "runbookText", "suggestion", "x", "config_path"] {
        let source = format!(
            "def handle(ticket):\n    \
             {name} = client.chat.completions.create(prompt=ticket).choices[0].message.content\n    \
             eval({name})\n"
        );
        assert!(fires(&ruleset, &source), "did not fire for `{name}`");
    }
}

/// And the other direction: a gate-shaped name over a value that did not come
/// from a model stays silent, which the name gate could never do.
#[test]
fn a_flow_gated_rule_stays_silent_on_a_value_from_elsewhere() {
    let ruleset = flow_ruleset();
    for name in ["response", "completion", "output"] {
        let source =
            format!("def handle(path):\n    {name} = json.load(open(path))\n    eval({name})\n");
        assert!(!fires(&ruleset, &source), "fired for `{name}`");
    }
}

#[test]
fn a_flow_gated_rule_stays_silent_on_a_literal() {
    assert!(!fires(
        &flow_ruleset(),
        "def handle():\n    eval(\"1 + 1\")\n"
    ));
}

/// A value whose origin the graph cannot prove is not a value the rule may
/// claim. Silence, not a guess.
#[test]
fn a_flow_gated_rule_stays_silent_when_the_origin_is_unprovable() {
    assert!(!fires(
        &flow_ruleset(),
        "def handle():\n    eval(mystery)\n"
    ));
}

/// `unguarded: true` means what it says: a model reply that has been checked
/// against a fixed set before reaching the sink is not reported.
#[test]
fn an_unguarded_flow_rule_skips_a_guarded_sink() {
    let source = "\
ALLOWED = (\"a\", \"b\")


def handle(ticket):
    plan = client.chat.completions.create(prompt=ticket).choices[0].message.content
    if plan not in ALLOWED:
        raise ValueError(plan)
    eval(plan)
";
    assert!(!fires(&flow_ruleset(), source));
}

/// Task 4's payoff, reachable from a rule: the sink is one call away.
#[test]
fn a_sink_flow_rule_reports_a_call_to_a_local_wrapper() {
    let yaml = r"
rules:
  - id: BAS-FLOW-002
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: ARG
      source: model_output
      sink: code_execution
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "\
def run_snippet(code):
    exec(code)


def handle(ticket):
    plan = client.chat.completions.create(prompt=ticket).choices[0].message.content
    run_snippet(plan)
";
    let findings = scan_source(&ruleset, Path::new("app/handler.py"), source);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].location.line, 7);
}

/// A wrapper call carrying something the graph cannot attribute to a model is
/// not reported, so the extra reach does not cost precision.
#[test]
fn a_sink_flow_rule_ignores_a_wrapper_call_with_an_unproven_argument() {
    let yaml = r"
rules:
  - id: BAS-FLOW-002
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: model_output
      sink: code_execution
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "\
def run_snippet(code):
    exec(code)


def handle(path):
    run_snippet(open(path).read())
";
    assert_eq!(
        scan_source(&ruleset, Path::new("app/handler.py"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

/// Migration has to be possible one rule at a time, so the two gates must be
/// able to sit on the same rule. Both apply.
#[test]
fn flow_and_metavariable_matches_both_apply() {
    let yaml = r#"
rules:
  - id: BAS-FLOW-003
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    metavariable_matches:
      ARG: "(?i)plan"
    flow:
      source: model_output
    description: Model output reaches eval().
    remediation: Do not execute model output.
"#;
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let model = "plan = client.chat.completions.create(prompt=t).choices[0].message.content\n";

    // Both gates satisfied.
    assert!(fires(
        &ruleset,
        &format!("def handle(t):\n    {model}    eval(plan)\n")
    ));
    // Flow satisfied, name gate not.
    assert!(!fires(
        &ruleset,
        &format!(
            "def handle(t):\n    {}    eval(other)\n",
            model.replace("plan", "other")
        )
    ));
    // Name gate satisfied, flow not.
    assert!(!fires(
        &ruleset,
        "def handle(p):\n    plan = json.load(open(p))\n    eval(plan)\n"
    ));
}

/// A `flow:` gate on a metavariable the matching pattern never bound has no
/// evidence, and fails closed -- the same direction `metavariable_matches`
/// takes, and for the same reason.
#[test]
fn a_flow_gate_on_an_unbound_metavariable_fails_closed() {
    let yaml = r"
rules:
  - id: BAS-FLOW-004
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: NEVER_BOUND
      source: model_output
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "def handle(t):\n    \
                  plan = client.chat.completions.create(prompt=t).choices[0].message.content\n    \
                  eval(plan)\n";
    assert_eq!(
        scan_source(&ruleset, Path::new("app/handler.py"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

/// The graph is Python-only. A `flow:` rule in a language it cannot analyse is
/// a load error, not a rule that quietly never matches.
#[test]
fn a_flow_rule_in_an_unsupported_language_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-FLOW-005
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: typescript
    any:
      - eval($ARG)
    flow:
      source: model_output
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(error, RuleError::FlowUnsupportedLanguage { .. }),
        "{error:?}"
    );
}

#[test]
fn a_flow_clause_accepts_a_list_of_sources() {
    let yaml = r"
rules:
  - id: BAS-FLOW-006
    title: Untrusted content executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: [model_output, file_read]
    description: Untrusted content reaches eval().
    remediation: Do not execute untrusted content.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    assert!(fires(
        &ruleset,
        "def handle(p):\n    rows = json.load(open(p))\n    eval(rows)\n"
    ));
    assert!(!fires(
        &ruleset,
        "def handle(p):\n    rows = requests.get(p)\n    eval(rows)\n"
    ));
}

#[test]
fn a_flow_clause_with_an_empty_source_list_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-FLOW-007
    title: Untrusted content executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: []
    description: Untrusted content reaches eval().
    remediation: Do not execute untrusted content.
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(error, RuleError::EmptyFlowSources { .. }),
        "{error:?}"
    );
}

/// A `flow:` clause that omits `source:` entirely does not gate on
/// provenance at all -- `BAS-LLM10-004`'s own new shape. Everything else in
/// [`crate::flow`]'s composition (closed values, guards, builtin shadowing)
/// still applies; only the "where did this come from" question is gone.
const UNCONDITIONAL_FLOW_RULE: &str = r"
rules:
  - id: BAS-FLOW-030
    title: eval() or exec() run on a non-literal expression
    kind: defect
    severity: high
    confidence: medium
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: ARG
      unguarded: true
      builtin_callee: true
    description: eval() runs a non-literal argument.
    remediation: Do not.
";

/// The measurement this clause exists to fix: a value traced to a
/// catalogued source and a value with no known origin at all must be
/// treated identically -- both `Proven` -- since there is no source list
/// left to tell them apart.
#[test]
fn a_sourceless_flow_clause_proves_a_traced_value() {
    let ruleset = RuleSet::from_yaml(UNCONDITIONAL_FLOW_RULE).unwrap();
    let source = "def handle(ticket):\n    plan = client.chat.completions.create(prompt=ticket).choices[0].message.content\n    eval(plan)\n";
    let findings = scan_source(&ruleset, Path::new("app/handler.py"), source);
    let finding = only(&findings);
    assert_eq!(finding.kind, crate::finding::Kind::Defect);
}

#[test]
fn a_sourceless_flow_clause_proves_an_untraceable_value_too() {
    let ruleset = RuleSet::from_yaml(UNCONDITIONAL_FLOW_RULE).unwrap();
    // `mystery` is an untraced function parameter -- no assignment, no call,
    // nothing the flow graph can classify. With a `source:` list this would
    // be `Unproven` or `Drop`; with none, it is `Proven`, exactly like the
    // traced value above.
    let findings = scan_source(
        &ruleset,
        Path::new("app/handler.py"),
        "def handle(mystery):\n    eval(mystery)\n",
    );
    let finding = only(&findings);
    assert_eq!(finding.kind, crate::finding::Kind::Defect);
}

/// `unguarded: true` still means what it says with no `source:`: a value
/// already checked against a fixed set before reaching the sink is still not
/// reported.
#[test]
fn a_sourceless_unguarded_flow_clause_still_drops_a_guarded_value() {
    let ruleset = RuleSet::from_yaml(UNCONDITIONAL_FLOW_RULE).unwrap();
    let source = "\
ALLOWED = (\"a\", \"b\")


def handle(value):
    if value not in ALLOWED:
        raise ValueError(value)
    eval(value)
";
    assert!(!fires(&ruleset, source));
}

/// `builtin_callee: true` still means what it says with no `source:`: a call
/// through a name this file rebinds itself is not the builtin, and is still
/// not reported.
#[test]
fn a_sourceless_flow_clause_still_drops_a_call_through_a_shadowed_builtin() {
    let ruleset = RuleSet::from_yaml(UNCONDITIONAL_FLOW_RULE).unwrap();
    let source =
        "def eval(value):\n    return value\n\n\ndef handle(mystery):\n    return eval(mystery)\n";
    assert!(!fires(&ruleset, source));
}

/// `is_closed` still runs before the sourceless shortcut: a value built only
/// from literals this file fixes is dropped the same as it would be with a
/// `source:` list, not proven just because there is no provenance question
/// left to ask. Only indirectly covered elsewhere by the
/// `eval_guarded_by_local_check.py` corpus fixture; this pins it directly at
/// the engine level.
#[test]
fn a_sourceless_flow_clause_still_drops_a_closed_value() {
    let ruleset = RuleSet::from_yaml(UNCONDITIONAL_FLOW_RULE).unwrap();
    assert!(!fires(
        &ruleset,
        "def handle():\n    x = \"a\" + \"b\"\n    eval(x)\n"
    ));
}

/// `unproven:` only means something when there is a `source:` list for a
/// value's origin to fail against -- with none, every non-closed, non-guarded
/// value is already `Proven`, so the combination is a meaningless
/// configuration, rejected at load time.
#[test]
fn unproven_without_source_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-FLOW-031
    title: eval() or exec() run on a non-literal expression
    kind: defect
    severity: high
    confidence: medium
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: ARG
      unguarded: true
      unproven:
        kind: observation
    description: eval() runs a non-literal argument.
    remediation: Do not.
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(error, RuleError::UnprovenWithoutSource { .. }),
        "{error:?}"
    );
}

/// `flow.sink` with no `flow.source` would let the wrapper-sink pass report
/// every call to a local wrapper whose argument is merely not closed and not
/// guarded -- a materially broader, currently untested reach no shipped rule
/// asks for. Rejected at load time rather than shipped silently.
#[test]
fn sink_without_source_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-FLOW-032
    title: eval() or exec() run on a non-literal expression
    kind: defect
    severity: high
    confidence: medium
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: ARG
      sink: code_execution
    description: eval() runs a non-literal argument.
    remediation: Do not.
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(error, RuleError::FlowSinkWithoutSource { .. }),
        "{error:?}"
    );
}

#[test]
fn an_unknown_flow_field_is_a_load_error() {
    let yaml = r"
rules:
  - id: BAS-FLOW-008
    title: Untrusted content executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: model_output
      sanitiser: html_escape
    description: Untrusted content reaches eval().
    remediation: Do not execute untrusted content.
";
    assert!(matches!(
        RuleSet::from_yaml(yaml).unwrap_err(),
        RuleError::Yaml(_)
    ));
}

/// The cost guard in front of the wrapper walk must never hide a real
/// wrapper, whatever the file looks like around it. These are the shapes a
/// plain substring test, or a `name(` test, would get wrong.
#[test]
fn the_wrapper_cost_guard_does_not_hide_a_wrapper() {
    let yaml = r"
rules:
  - id: BAS-FLOW-009
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: model_output
      sink: code_execution
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let call = "plan = client.chat.completions.create(prompt=t).choices[0].message.content\n    run_snippet(plan)\n";

    // Whitespace between the callee and its arguments.
    let spaced = format!("def run_snippet(code):\n    exec (code)\n\n\ndef handle(t):\n    {call}");
    assert!(fires(&ruleset, &spaced), "missed a spaced `exec (code)`");

    // The file's other mention of the name is inside a longer word.
    let shadowed = format!(
        "def execute_all(rows):\n    return rows\n\n\ndef run_snippet(code):\n    exec(code)\n\n\ndef handle(t):\n    {call}"
    );
    assert!(
        fires(&ruleset, &shadowed),
        "missed a wrapper next to `execute_all`"
    );
}

/// A `flow:` rule with an unproven path, parameterised by its extra flow
/// keys and its declared kind.
fn unproven_rule(kind: &str, extra_flow: &str) -> String {
    format!(
        r"
rules:
  - id: BAS-FLOW-020
    title: Model output run as a shell command
    kind: {kind}
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - os.system($ARG)
    flow:
      variable: ARG
      source: model_output
      unguarded: true
{extra_flow}
    description: A value reaches os.system().
    remediation: Do not.
"
    )
}

const UNPROVEN_WITH_REQUIRES: &str = "      unproven:
        kind: observation
        requires:
          ARG: \"(?i)(response|reply)\"";

fn only(findings: &[crate::finding::Finding]) -> &crate::finding::Finding {
    assert_eq!(findings.len(), 1, "{findings:#?}");
    &findings[0]
}

#[test]
fn a_proven_source_keeps_the_declared_kind() {
    let rules = RuleSet::from_yaml(&unproven_rule("defect", UNPROVEN_WITH_REQUIRES)).unwrap();
    let source = "def run(client):\n    command = client.chat.completions.create(prompt='x').choices[0].message.content\n    os.system(command)\n";
    let findings = scan_source(&rules, Path::new("app/run.py"), source);
    let finding = only(&findings);
    assert_eq!(finding.kind, crate::finding::Kind::Defect);
    assert_eq!(finding.confidence, crate::finding::Confidence::High);
    assert!(!finding.description.contains("could not be traced"));
}

#[test]
fn an_untraceable_value_with_a_matching_name_is_an_observation() {
    let rules = RuleSet::from_yaml(&unproven_rule("defect", UNPROVEN_WITH_REQUIRES)).unwrap();
    let findings = scan_source(
        &rules,
        Path::new("app/run.py"),
        "def run(response):\n    os.system(response)\n",
    );
    let finding = only(&findings);
    assert_eq!(finding.kind, crate::finding::Kind::Observation);
    assert_eq!(finding.confidence, crate::finding::Confidence::Low);
    assert!(finding.description.ends_with(
        "The origin of this value could not be traced within this file, so this is reported as an observation rather than a defect."
    ), "{}", finding.description);
}

#[test]
fn an_untraceable_value_whose_name_fails_requires_is_dropped() {
    let rules = RuleSet::from_yaml(&unproven_rule("defect", UNPROVEN_WITH_REQUIRES)).unwrap();
    assert_eq!(
        scan_source(
            &rules,
            Path::new("app/run.py"),
            "def run(command):\n    os.system(command)\n"
        ),
        Vec::<crate::finding::Finding>::new()
    );
}

#[test]
fn a_value_from_a_different_known_source_is_dropped_not_observed() {
    let rules = RuleSet::from_yaml(&unproven_rule("defect", UNPROVEN_WITH_REQUIRES)).unwrap();
    let source = "def run(path):\n    response = json.load(open(path))\n    os.system(response)\n";
    assert_eq!(
        scan_source(&rules, Path::new("app/run.py"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

#[test]
fn a_closed_value_is_dropped_even_with_an_unproven_path() {
    let rules = RuleSet::from_yaml(&unproven_rule("defect", UNPROVEN_WITH_REQUIRES)).unwrap();
    assert_eq!(
        scan_source(
            &rules,
            Path::new("app/run.py"),
            "response = \"printf hello\"\nos.system(response)\n"
        ),
        Vec::<crate::finding::Finding>::new()
    );
}

#[test]
fn a_guarded_value_is_dropped_even_with_an_unproven_path() {
    let rules = RuleSet::from_yaml(&unproven_rule("defect", UNPROVEN_WITH_REQUIRES)).unwrap();
    let source = "def run(response):\n    if response not in (\"ls\", \"pwd\"):\n        raise ValueError(response)\n    os.system(response)\n";
    assert_eq!(
        scan_source(&rules, Path::new("app/run.py"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

#[test]
fn an_unproven_path_without_requires_reports_any_untraceable_value() {
    let rules = RuleSet::from_yaml(&unproven_rule(
        "defect",
        "      unproven:\n        kind: observation",
    ))
    .unwrap();
    let findings = scan_source(
        &rules,
        Path::new("app/run.py"),
        "def run(anything):\n    os.system(anything)\n",
    );
    assert_eq!(only(&findings).kind, crate::finding::Kind::Observation);
}

#[test]
fn unproven_on_an_observation_rule_reports_an_untraceable_value() {
    let rules = RuleSet::from_yaml(&unproven_rule("observation", UNPROVEN_WITH_REQUIRES)).unwrap();
    let findings = scan_source(
        &rules,
        Path::new("app/run.py"),
        "def run(response):\n    os.system(response)\n",
    );
    assert_eq!(only(&findings).kind, crate::finding::Kind::Observation);
}

#[test]
fn unproven_kind_other_than_observation_fails_to_load() {
    let err = RuleSet::from_yaml(&unproven_rule(
        "defect",
        "      unproven:\n        kind: defect",
    ))
    .unwrap_err();
    assert!(matches!(err, RuleError::Yaml(_)), "{err}");
}

#[test]
fn requires_naming_an_unbound_metavariable_fails_to_load() {
    let err = RuleSet::from_yaml(&unproven_rule(
        "defect",
        "      unproven:\n        kind: observation\n        requires:\n          NOPE: \"x\"",
    ))
    .unwrap_err();
    assert!(
        matches!(err, RuleError::UnboundMetavariable { ref var, .. } if var == "NOPE"),
        "{err}"
    );
}

#[test]
fn an_invalid_requires_regex_fails_to_load() {
    let err = RuleSet::from_yaml(&unproven_rule(
        "defect",
        "      unproven:\n        kind: observation\n        requires:\n          ARG: \"(\"",
    ))
    .unwrap_err();
    assert!(
        matches!(err, RuleError::InvalidUnprovenRegex { .. }),
        "{err}"
    );
}

#[test]
fn an_unproven_observation_in_a_test_path_is_still_an_observation() {
    let rules = RuleSet::from_yaml(&unproven_rule("defect", UNPROVEN_WITH_REQUIRES)).unwrap();
    let findings = scan_source(
        &rules,
        Path::new("tests/test_run.py"),
        "def run(response):\n    os.system(response)\n",
    );
    assert_eq!(only(&findings).kind, crate::finding::Kind::Observation);
}

const BUILTIN_RULE: &str = r"
rules:
  - id: BAS-FLOW-021
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: ARG
      source: model_output
      builtin_callee: true
    description: Model output reaches eval().
    remediation: Do not.
";

#[test]
fn builtin_callee_drops_a_call_to_a_shadowed_eval() {
    let rules = RuleSet::from_yaml(BUILTIN_RULE).unwrap();
    let source = "def eval(value):\n    return value\n\ndef run(client):\n    text = client.responses.create(model='m', input='x').output_text\n    return eval(text)\n";
    assert_eq!(
        scan_source(&rules, Path::new("app/run.py"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

#[test]
fn builtin_callee_keeps_a_call_to_the_real_eval() {
    let rules = RuleSet::from_yaml(BUILTIN_RULE).unwrap();
    let source = "def run(client):\n    text = client.responses.create(model='m', input='x').output_text\n    return eval(text)\n";
    assert_eq!(
        scan_source(&rules, Path::new("app/run.py"), source).len(),
        1
    );
}

const BUILTIN_SINK_RULE: &str = r"
rules:
  - id: BAS-FLOW-023
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: ARG
      source: model_output
      sink: code_execution
      builtin_callee: true
    description: Model output reaches eval().
    remediation: Do not.
";

/// The wrapper pass used to ignore `builtin_callee` entirely: it asked only
/// whether a local function's body called something named `eval`, never
/// whether that name still meant the real builtin by the time it ran. A file
/// that shadows `eval` with its own identity function and then wraps *that*
/// must not report a call through the wrapper, the same way a direct call to
/// the shadowed name already does not.
#[test]
fn builtin_callee_drops_a_wrapper_call_through_a_shadowed_eval() {
    let rules = RuleSet::from_yaml(BUILTIN_SINK_RULE).unwrap();
    let source = "\
def eval(v):
    return v


def run(code):
    return eval(code)


def handle(client):
    model_text = client.responses.create(model='m', input='x').output_text
    run(model_text)
";
    assert_eq!(
        scan_source(&rules, Path::new("app/run.py"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

/// The companion case: with no local `def eval`, the wrapper's `eval` really
/// is the builtin, and the call through the wrapper is still reported.
#[test]
fn builtin_callee_keeps_a_wrapper_call_through_the_real_eval() {
    let rules = RuleSet::from_yaml(BUILTIN_SINK_RULE).unwrap();
    let source = "\
def run(code):
    return eval(code)


def handle(client):
    model_text = client.responses.create(model='m', input='x').output_text
    run(model_text)
";
    let findings = scan_source(&rules, Path::new("app/run.py"), source);
    assert_eq!(findings.len(), 1, "{findings:#?}");
}

#[test]
fn the_wrapper_pass_reports_an_unproven_argument_only_without_requires() {
    let with_requires = r"
rules:
  - id: BAS-FLOW-022
    title: t
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - exec($ARG)
    flow:
      variable: ARG
      source: model_output
      sink: code_execution
      unproven:
        kind: observation
        requires:
          ARG: response
    description: d
    remediation: r
";
    let source =
        "def runner(code):\n    exec(code)\n\ndef handle(response):\n    runner(response)\n";
    let rules = RuleSet::from_yaml(with_requires).unwrap();
    let findings = scan_source(&rules, Path::new("app/run.py"), source);
    assert!(
        findings.iter().all(|f| f.location.line != 5),
        "no wrapper-call finding expected with requires: {findings:#?}"
    );

    let without = with_requires.replace("        requires:\n          ARG: response\n", "");
    let rules = RuleSet::from_yaml(&without).unwrap();
    let findings = scan_source(&rules, Path::new("app/run.py"), source);
    let wrapper = findings
        .iter()
        .find(|f| f.location.line == 5)
        .expect("a wrapper-call observation");
    assert_eq!(wrapper.kind, crate::finding::Kind::Observation);
}

/// `request.json` is an attribute read, not a call, so the graph cannot
/// classify it as request data. With a user-input-shaped name it must still
/// surface as an observation rather than vanish.
#[test]
fn a_system_prompt_from_an_unclassified_request_attribute_is_an_observation() {
    let rules = RuleSet::embedded().unwrap();
    let source = "def handle(request):\n    user_query = request.json[\"q\"]\n    system_prompt = f\"Context: {user_query}\"\n";
    let findings = scan_source(&rules, Path::new("app/handler.py"), source);
    let zt4 = findings
        .iter()
        .find(|f| f.rule_id == "BAS-ZT4-001")
        .expect("an observation");
    assert_eq!(zt4.kind, crate::finding::Kind::Observation);
}

/// `BAS-ZT4-001` has `unguarded: true`, so a value already checked against a
/// fixed set before reaching the interpolation is not reported at all -- the
/// same guard every other flow-gated rule already honours.
#[test]
fn bas_zt4_001_skips_a_value_already_limited_by_a_fixed_set_check() {
    let rules = RuleSet::embedded().unwrap();
    let source = "def handle(request):\n    user_input = request.get_json()[\"q\"]\n    if user_input not in (\"a\", \"b\"):\n        return None\n    system_prompt = f\"Context: {user_input}\"\n";
    let findings = scan_source(&rules, Path::new("app/handler.py"), source);
    assert!(
        findings.iter().all(|f| f.rule_id != "BAS-ZT4-001"),
        "a guarded value must not be reported: {findings:#?}"
    );
}

/// `flow.passthrough_downgrade` reports a bare pass-through of a
/// non-entry-point function's own parameter as an observation, not a
/// defect, when nothing in the file wires it to a recognized entry point.
#[test]
fn passthrough_downgrade_reports_a_bare_parameter_helper_as_an_observation() {
    let rules = RuleSet::embedded().unwrap();
    let source = "\
import subprocess


def run_shell_cmd(cmd):
    return subprocess.run(cmd, shell=True)
";
    let findings = scan_source(&rules, Path::new("app/helpers.py"), source);
    let finding = findings
        .iter()
        .find(|f| f.rule_id == "BAS-LLM10-009")
        .expect("a BAS-LLM10-009 finding");
    assert_eq!(finding.kind, crate::finding::Kind::Observation);
}

/// The companion case: the same bare-parameter shape inside a function
/// decorated `@mcp.tool()` -- a recognized entry point -- must stay a
/// defect, since this file itself hands that parameter an agent-chosen
/// value.
#[test]
fn passthrough_downgrade_does_not_apply_inside_an_entry_point() {
    let rules = RuleSet::embedded().unwrap();
    let source = "\
import subprocess


@mcp.tool()
def run_shell_cmd(cmd):
    return subprocess.run(cmd, shell=True)
";
    let findings = scan_source(&rules, Path::new("app/helpers.py"), source);
    let finding = findings
        .iter()
        .find(|f| f.rule_id == "BAS-LLM10-009")
        .expect("a BAS-LLM10-009 finding");
    assert_eq!(finding.kind, crate::finding::Kind::Defect);
}
