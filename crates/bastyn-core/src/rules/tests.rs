//! Unit tests for rule loading and scanning.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;

use super::*;
use crate::finding::{Kind, Severity};

/// The example rule from the spec: `eval`/`exec` on something that looks
/// like a model response, with a `none` guard on eval-of-a-literal.
const LLM10_RULE_YAML: &str = r#"
rules:
  - id: BAS-LLM10-001
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10, ZT4]
    language: python
    any:
      - eval($ARG)
      - exec($ARG)
    none:
      - eval("$LITERAL")
    metavariable_matches:
      ARG: "(?i)(response|reply|completion|message|content|choices|output|generated)"
    description: Running model output as code gives an attacker who controls the prompt full code execution.
    remediation: Parse the model output as structured data and validate it against a schema. Never pass it to eval or exec.
"#;

fn llm10_ruleset() -> RuleSet {
    RuleSet::from_yaml(LLM10_RULE_YAML).unwrap()
}

#[test]
fn eval_on_llm_response_is_flagged() {
    let ruleset = llm10_ruleset();
    let source = "eval(reply.choices[0].message.content)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM10-001");
    assert_eq!(findings[0].location.line, 1);
    assert_eq!(
        findings[0].snippet,
        "eval(reply.choices[0].message.content)"
    );
}

#[test]
fn eval_on_a_literal_is_not_flagged() {
    let ruleset = llm10_ruleset();
    let source = "eval(\"2 + 2\")\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// `BAS-LLM10-003`, kept in sync by hand with `rules/bastyn.yml` -- see
/// `tests_frameworks.rs`'s module docs for why a dedicated fragment beats
/// loading the real file. Measured 2026-08-28 against 65 real third-party
/// repositories: every one of this rule's 5 corpus findings was a false
/// positive of one of the two shapes the `none:`/`metavariable_not_matches:`
/// entries below exclude. Extended 2026-08-31 to exclude an arbitrary-count
/// plain-literal concatenation (previously capped at 2-5 adjacent literals)
/// via a `metavariable_not_matches` regex anchored end-to-end, rather than
/// enumerated `none:` shapes -- see `rules/bastyn.yml`'s comment above the
/// rule for the full writeup, including the two alternatives (an ast-grep
/// `$$$` ellipsis `none:`, a `flow:` migration) tried and rejected.
const LLM10_003_RULE_YAML: &str = r#"
rules:
  - id: BAS-LLM10-003
    title: Model output concatenated into a SQL query
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - $CUR.execute($ARG)
    none:
      - $CUR.execute("""$LIT""")
      - $CUR.execute('''$LIT''')
      - $CUR.execute($FN("$LIT"))
      - $CUR.execute($FN('$LIT'))
      - $CUR.execute($FN("""$LIT"""))
      - $CUR.execute($FN('''$LIT'''))
    metavariable_matches:
      CUR: "(?i)(cursor|cur|db|conn|connection)"
      ARG: "(?i)(response|reply|completion|message|content|choices|output|generated)"
    metavariable_not_matches:
      ARG: '^\s*(select|insert|update)\(|^\s*(("([^"\\]|\\.)*")|(''([^''\\]|\\.)*''))(\s*(("([^"\\]|\\.)*")|(''([^''\\]|\\.)*'')))*\s*$'
    description: A database cursor executes a query built from model output.
    remediation: Never interpolate model output into a SQL string.
"#;

fn llm10_003_ruleset() -> RuleSet {
    RuleSet::from_yaml(LLM10_003_RULE_YAML).unwrap()
}

/// The true positive this rule exists for: the model's own reply spliced
/// into an f-string that becomes the query text. Must survive every
/// exclusion added below -- an f-string is structurally distinct from a
/// bare string literal (it carries interpolation children), so `"$LIT"`
/// must not accidentally swallow it.
#[test]
fn bas_llm10_003_flags_an_fstring_built_from_model_output() {
    let ruleset = llm10_003_ruleset();
    let source = "cursor.execute(f\"INSERT INTO t (a) VALUES ('{model_reply}')\")\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM10-003");
}

#[test]
fn bas_llm10_003_still_flags_a_format_call() {
    let ruleset = llm10_003_ruleset();
    let source = "cursor.execute(\"INSERT INTO t (a) VALUES ('{}')\".format(response))\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn bas_llm10_003_still_flags_percent_interpolation() {
    let ruleset = llm10_003_ruleset();
    let source = "cursor.execute(\"INSERT INTO t (a) VALUES ('%s')\" % response)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn bas_llm10_003_still_flags_plus_concatenation() {
    let ruleset = llm10_003_ruleset();
    let source = "cursor.execute(\"INSERT INTO t (a) VALUES ('\" + response + \"')\")\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

/// False-positive shape 1a: a single-quoted-style plain literal, a corpus
/// shape (a `CREATE TABLE` DDL string whose column names happen to contain
/// `output`).
#[test]
fn bas_llm10_003_ignores_a_triple_quoted_ddl_literal() {
    let ruleset = llm10_003_ruleset();
    let source = "conn.execute(\"\"\"\nCREATE TABLE audit (output_redacted TEXT)\n\"\"\")\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// False-positive shape 1b: the same literal DDL wrapped in one call, a
/// corpus shape from a database-init module (`SQLAlchemy`'s
/// `text("""...""")`).
#[test]
fn bas_llm10_003_ignores_a_call_wrapped_ddl_literal() {
    let ruleset = llm10_003_ruleset();
    let source = "conn.execute(text(\"\"\"\nCREATE TABLE tasks (error_message TEXT)\n\"\"\"))\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// False-positive shape 1c: Python's implicit adjacent-string-literal
/// concatenation (`"a" "b"`, no operator between them), a corpus shape
/// from an HTTP route module -- four literal pieces split across lines for
/// readability, not interpolation.
#[test]
fn bas_llm10_003_ignores_adjacent_literal_concatenation() {
    let ruleset = llm10_003_ruleset();
    let source = "db.execute(\n    \"SELECT c.*, \"\n    \"(SELECT content FROM messages) \"\n    \"AS first_query \"\n    \"FROM chats\"\n)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// A bare double-quoted literal with no concatenation at all -- the
/// simplest shape `metavariable_not_matches`'s literal-concatenation regex
/// has to cover now that the dedicated `none: - $CUR.execute("$LIT")` entry
/// is gone, folded into that regex's "one or more" case.
#[test]
fn bas_llm10_003_ignores_a_bare_double_quoted_literal() {
    let ruleset = llm10_003_ruleset();
    let source = "cursor.execute(\"SELECT completion_tokens FROM t\")\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// The real false positive this exclusion was rewritten for: a query split
/// across more literal segments than the rule's old `none:` enumeration
/// covered (previously capped at 5), one of which -- `completion_tokens`, a
/// real `LiteLLM_SpendLogs` column -- contains an ARG trigger word for a
/// reason that has nothing to do with model output.
#[test]
fn bas_llm10_003_ignores_arbitrarily_many_adjacent_literals() {
    let ruleset = llm10_003_ruleset();
    let source = "cur.execute(\n    \"SELECT model, \"\n    \"prompt_tokens, \"\n    \"completion_tokens, \"\n    \"startTime, \"\n    \"endTime \"\n    \"FROM LiteLLM_SpendLogs\"\n)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// The same shape, single-quoted -- a quote style the old enumerated
/// `none:` entries never covered for the multi-literal case at all.
#[test]
fn bas_llm10_003_ignores_adjacent_single_quoted_literals() {
    let ruleset = llm10_003_ruleset();
    let source = "cur.execute(\n    'SELECT model, '\n    'prompt_tokens, '\n    'completion_tokens, '\n    'FROM LiteLLM_SpendLogs'\n)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// The exact reported shape: adjacent segments that mix quote styles (the
/// last one switches to single quotes to hold a double-quoted identifier
/// without escaping it). Each segment is independently either style, not
/// all-double or all-single.
#[test]
fn bas_llm10_003_ignores_adjacent_literals_with_mixed_quote_styles() {
    let ruleset = llm10_003_ruleset();
    let source = "cur.execute(\n    \"SELECT model, \"\n    \"prompt_tokens, \"\n    \"completion_tokens, \"\n    \"startTime, \"\n    \"endTime \"\n    'FROM \"LiteLLM_SpendLogs\"'\n)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// The literal-concatenation regex is anchored end-to-end so it cannot
/// swallow a real vulnerability: `%`-interpolation starts with a quoted
/// literal but does not consist *only* of quoted literals.
#[test]
fn bas_llm10_003_still_flags_percent_interpolation_after_many_literals_fix() {
    let ruleset = llm10_003_ruleset();
    let source = "cursor.execute(\"INSERT INTO t (a) VALUES ('%s')\" % response)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

/// False-positive shape 2: a `SQLAlchemy` query-builder expression, a corpus
/// shape from a Postgres store module -- `update()` builds a parameterized
/// query object, so a `message`-named value passed to `.values()` becomes a
/// bound parameter, never query text.
#[test]
fn bas_llm10_003_ignores_a_sqlalchemy_update_builder() {
    let ruleset = llm10_003_ruleset();
    let source = "conn.execute(update(t).where(t.c.k == 1).values(last_error=str(message)))\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// The query-builder exclusion is anchored to the start of `$ARG`'s text so
/// it cannot misfire on an identifier that merely starts with a builder
/// name, e.g. a function called `select_response_row` rather than `SQLAlchemy`'s
/// `select(...)`.
#[test]
fn bas_llm10_003_does_not_over_exclude_a_select_prefixed_identifier() {
    let ruleset = llm10_003_ruleset();
    let source = "cursor.execute(select_response_row)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(
        findings.len(),
        1,
        "a bare identifier that merely starts with a builder name must still be flagged: {findings:?}"
    );
}

#[test]
fn defect_rule_on_context_dependent_category_is_rejected_at_load() {
    let yaml = r"
rules:
  - id: BAS-BAD-001
    title: Missing rate limit
    kind: defect
    severity: medium
    confidence: medium
    categories: [LLM06]
    language: python
    any:
      - foo($X)
    description: test
    remediation: test
";

    let error = RuleSet::from_yaml(yaml).unwrap_err();

    assert!(
        matches!(error, RuleError::ContextDependentDefect { .. }),
        "got {error:?}"
    );
}

#[test]
fn malformed_yaml_is_an_error() {
    let yaml = "rules:\n  - id: BAS-1\n    any: [unterminated\n";

    let error = RuleSet::from_yaml(yaml).unwrap_err();

    assert!(matches!(error, RuleError::Yaml(_)), "got {error:?}");
}

#[test]
fn unknown_yaml_field_is_an_error() {
    let yaml = r"
rules:
  - id: BAS-1
    title: t
    kind: defect
    severity: low
    confidence: low
    categories: [LLM10]
    language: python
    any:
      - foo($X)
    description: test
    remediation: test
    this_field_does_not_exist: true
";

    let error = RuleSet::from_yaml(yaml).unwrap_err();

    assert!(matches!(error, RuleError::Yaml(_)), "got {error:?}");
}

#[test]
fn unparseable_python_does_not_panic() {
    let ruleset = llm10_ruleset();
    let source = "def(:::: not python at all @#$%^&*(\0\0\0";

    let findings = scan_source(&ruleset, Path::new("broken.py"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn two_rules_at_the_same_location_dedupe_to_one_finding() {
    let yaml = r"
rules:
  - id: BAS-A
    title: rule a
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    description: a
    remediation: a
  - id: BAS-B
    title: rule b
    kind: defect
    severity: critical
    confidence: high
    categories: [ZT4]
    language: python
    any:
      - eval($ARG)
    description: b
    remediation: b
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "eval(x)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    // Critical outranks high, so BAS-B is primary and BAS-A is secondary.
    assert_eq!(findings[0].rule_id, "BAS-B");
    assert_eq!(findings[0].secondary_rule_ids, vec!["BAS-A".to_string()]);
}

#[test]
fn any_list_requires_at_least_one_pattern() {
    let yaml = r"
rules:
  - id: BAS-EMPTY
    title: t
    kind: defect
    severity: low
    confidence: low
    categories: [LLM10]
    language: python
    any: []
    description: test
    remediation: test
";

    let error = RuleSet::from_yaml(yaml).unwrap_err();

    assert!(matches!(error, RuleError::EmptyAny { .. }), "got {error:?}");
}

#[test]
fn embedded_ruleset_loads_and_is_non_empty() {
    let ruleset = RuleSet::embedded().unwrap();

    // Future-proof against the full rule corpus replacing this file's
    // single seed rule: only assert that loading succeeds and is non-empty.
    assert!(!ruleset.is_empty());
}

#[test]
fn embedded_ruleset_includes_the_mcp_transport_rules() {
    let ruleset = RuleSet::embedded().unwrap();

    let py = "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP(\"n\", host=\"0.0.0.0\")\nmcp.run(transport=\"streamable-http\")\n";
    let findings = scan_source(&ruleset, Path::new("server.py"), py);
    assert!(
        findings.iter().any(|f| f.rule_id == "BAS-ZT3-001"),
        "findings: {findings:?}"
    );

    for call in [
        "FastMCP(\"n\", host=\"0.0.0.0\", port=1)",
        "FastMCP(host=\"0.0.0.0\", port=1)",
        "FastMCP(\"n\", port=1, host='0.0.0.0')",
        "FastMCP(host=\"0.0.0.0\")",
        "uvicorn.run(app, host=\"0.0.0.0\", port=1)",
    ] {
        let src = format!("{call}\nrun(transport=\"sse\")\n");
        let findings = scan_source(&ruleset, Path::new("server.py"), &src);
        assert!(
            findings.iter().any(|f| f.rule_id == "BAS-ZT3-001"),
            "{call}: {findings:?}"
        );
    }
    let loopback = "FastMCP(\"n\", host=\"127.0.0.1\")\nrun(transport=\"sse\")\n";
    let findings = scan_source(&ruleset, Path::new("server.py"), loopback);
    assert!(
        findings.iter().all(|f| f.rule_id != "BAS-ZT3-001"),
        "findings: {findings:?}"
    );

    let ts = "const t = new StreamableHTTPServerTransport({});\napp.listen(3000, \"0.0.0.0\");\n";
    let findings = scan_source(&ruleset, Path::new("server.ts"), ts);
    assert!(
        findings.iter().any(|f| f.rule_id == "BAS-ZT3-002"),
        "findings: {findings:?}"
    );

    // Without an HTTP transport marker in the file neither rule fires.
    let plain = "app.listen(3000, \"0.0.0.0\");\n";
    let findings = scan_source(&ruleset, Path::new("plain.ts"), plain);
    assert!(
        findings.iter().all(|f| f.rule_id != "BAS-ZT3-002"),
        "findings: {findings:?}"
    );
}

// ---------------------------------------------------------------------
// JS/TS twins closing the LLM08/LLM06/ZT2 recall gap: these run against the
// real, embedded `bastyn.yml` rather than an ad-hoc rule string, so a typo in
// the shipped rule fails the same test a rewrite of the pattern would.
// ---------------------------------------------------------------------

#[test]
fn bas_llm08_002_flags_a_secret_embedded_in_a_js_prompt_template() {
    let ruleset = RuleSet::embedded().unwrap();
    let vulnerable = "export const SYSTEM_PROMPT_TEMPLATE =\n  \"You are OpsBot, an internal infrastructure assistant. The on-call webhook signing secret is sk-ops-4d9f2b7a1c6e8035bd41a9f7c2e6b804 -- use it only when calling the paging webhook tool, and never repeat it to a user under any circumstances. Help the engineer triage the incident described below.\";\n";

    let findings = scan_source(&ruleset, Path::new("prompts.ts"), vulnerable);

    assert!(
        findings.iter().any(|f| f.rule_id == "BAS-LLM08-002"),
        "findings: {findings:?}"
    );

    // A prompt-named variable with no sk--shaped content must not fire --
    // the name gate alone is never sufficient, same as the Python rule.
    let clean = "export const SYSTEM_PROMPT =\n  \"You are OpsBot, an internal infrastructure assistant. Help the engineer triage the incident described below.\";\n";
    let clean_findings = scan_source(&ruleset, Path::new("prompts.ts"), clean);
    assert!(
        !clean_findings.iter().any(|f| f.rule_id == "BAS-LLM08-002"),
        "findings: {clean_findings:?}"
    );
}

#[test]
fn bas_llm06_002_flags_an_llm_call_with_no_token_ceiling_js() {
    let ruleset = RuleSet::embedded().unwrap();
    let vulnerable = "async function summarizeTicketBacklog(ticketText) {\n  const result = streamText({\n    model: openaiProvider(MODEL_NAME),\n    system: \"Summarize the following support tickets.\",\n    prompt: ticketText,\n  });\n  return result;\n}\n";

    let findings = scan_source(&ruleset, Path::new("agent.ts"), vulnerable);
    let hit = findings.iter().find(|f| f.rule_id == "BAS-LLM06-002");

    assert!(hit.is_some(), "findings: {findings:?}");
    // Context-dependent: an edge limiter may already exist, so this must
    // stay an observation, never a defect (the loader rejects the latter
    // outright for LLM06 -- see `defect_rule_on_context_dependent_category_is_rejected_at_load`).
    assert_eq!(hit.unwrap().kind, Kind::Observation);

    // A call with an explicit cap, cap in the middle of the options object
    // (the common real-world position, not just first/last), must not fire.
    let clean = "const result = await generateText({\n  model: buildModel(input.config),\n  system: input.system,\n  messages: input.messages,\n  maxOutputTokens: input.maxTokens ?? 768,\n  temperature: 0.2,\n});\n";
    let clean_findings = scan_source(&ruleset, Path::new("agent.ts"), clean);
    assert!(
        !clean_findings.iter().any(|f| f.rule_id == "BAS-LLM06-002"),
        "findings: {clean_findings:?}"
    );
}

#[test]
fn bas_zt2_002_flags_a_positional_wildcard_tool_grant_js() {
    let ruleset = RuleSet::embedded().unwrap();
    let vulnerable = "export function buildOpsbotAgent() {\n  return selectToolsForAgent(ALL_TOOLS, \"*\");\n}\n";

    let findings = scan_source(&ruleset, Path::new("agent.ts"), vulnerable);

    assert!(
        findings.iter().any(|f| f.rule_id == "BAS-ZT2-002"),
        "findings: {findings:?}"
    );

    // An explicit, scoped tool list -- not a wildcard -- must not fire.
    let clean = "export function buildOpsbotAgent() {\n  return selectToolsForAgent(ALL_TOOLS, [\"getServerStatus\"]);\n}\n";
    let clean_findings = scan_source(&ruleset, Path::new("agent.ts"), clean);
    assert!(
        !clean_findings.iter().any(|f| f.rule_id == "BAS-ZT2-002"),
        "findings: {clean_findings:?}"
    );

    // Regression: a Supabase/PostgREST `.from(table).select("*")` chain
    // where the table name happens to contain "tool" or "agent" as a
    // substring (measured on 65 real repositories: 7 false positives, 0
    // true, all this exact shape). FN must not capture the whole chain's
    // text -- the fix anchors the gate to a single bare identifier.
    let chain = "async function getById(id) {\n  const { data, error } = await getSupabase()\n    .from('user_mcp_connector_tools')\n    .select('*')\n    .eq('id', id)\n    .single();\n  return data;\n}\n";
    let chain_findings = scan_source(&ruleset, Path::new("agent.ts"), chain);
    assert!(
        !chain_findings.iter().any(|f| f.rule_id == "BAS-ZT2-002"),
        "findings: {chain_findings:?}"
    );
}

// ---------------------------------------------------------------------
// Multi-language dispatch.
// ---------------------------------------------------------------------

/// A ruleset with one Python rule and one JavaScript rule, both anchored on
/// `eval($ARG)` with no metavariable gate, so the only thing that can decide
/// which one (if either) fires is the file extension `scan_source` dispatches
/// on.
fn cross_language_eval_ruleset() -> RuleSet {
    let yaml = r"
rules:
  - id: BAS-PY-EVAL
    title: py
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    description: test
    remediation: test
  - id: BAS-JS-EVAL
    title: js
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: javascript
    any:
      - eval($ARG)
    description: test
    remediation: test
";
    RuleSet::from_yaml(yaml).unwrap()
}

#[test]
fn a_javascript_rule_never_runs_against_a_python_file() {
    let ruleset = cross_language_eval_ruleset();
    let source = "eval(x)\n";

    let findings = scan_source(&ruleset, Path::new("bot.py"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-PY-EVAL");
}

#[test]
fn a_python_rule_never_runs_against_a_javascript_file() {
    let ruleset = cross_language_eval_ruleset();
    let source = "eval(x)\n";

    let findings = scan_source(&ruleset, Path::new("bot.js"), source);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-JS-EVAL");
}

/// `.mjs`/`.cjs`/`.jsx` all route to the same `javascript` rule bucket as
/// `.js` -- there is no separate grammar for any of them (JSX parses under
/// the plain JavaScript grammar; see `engine`'s module docs).
#[test]
fn mjs_cjs_and_jsx_all_dispatch_to_javascript_rules() {
    let ruleset = cross_language_eval_ruleset();
    let source = "eval(x)\n";

    for ext in ["mjs", "cjs", "jsx"] {
        let path = format!("bot.{ext}");
        let findings = scan_source(&ruleset, Path::new(&path), source);
        assert_eq!(findings.len(), 1, "extension {ext}: findings: {findings:?}");
        assert_eq!(findings[0].rule_id, "BAS-JS-EVAL", "extension {ext}");
    }
}

/// A file whose extension the engine has no grammar for is skipped cleanly,
/// not parsed as some other language -- even when the content would trip a
/// loaded rule if it were.
#[test]
fn unrecognised_extension_produces_no_findings() {
    let ruleset = cross_language_eval_ruleset();
    let source = "eval(x)\n";

    let findings = scan_source(&ruleset, Path::new("bot.rb"), source);

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// A `language: typescript` rule is compiled against both the TypeScript and
/// Tsx grammars (see `engine`'s module docs), so it fires on `.tsx` files
/// too without a rule author having to declare it twice.
#[test]
fn a_typescript_rule_also_fires_on_tsx_files() {
    let yaml = r"
rules:
  - id: BAS-TS-EVAL
    title: ts
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: typescript
    any:
      - eval($ARG)
    description: test
    remediation: test
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "eval(x);\n";

    let dot_ts = scan_source(&ruleset, Path::new("bot.ts"), source);
    let dot_tsx = scan_source(&ruleset, Path::new("bot.tsx"), source);

    assert_eq!(dot_ts.len(), 1, "findings: {dot_ts:?}");
    assert_eq!(dot_ts[0].rule_id, "BAS-TS-EVAL");
    assert_eq!(dot_tsx.len(), 1, "findings: {dot_tsx:?}");
    assert_eq!(dot_tsx[0].rule_id, "BAS-TS-EVAL");
}

/// JavaScript is a syntactic subset of TypeScript, so a `language:
/// javascript` rule describes code that is equally valid in a `.ts` or
/// `.tsx` file. Routing it only to the JavaScript bucket would mean a
/// TypeScript file is silently scanned by fewer rules than the identical
/// JavaScript file -- a coverage hole with no error and no warning, which is
/// the exact failure mode this module's per-grammar dispatch exists to make
/// impossible.
#[test]
fn a_javascript_rule_also_fires_on_typescript_and_tsx_files() {
    let yaml = r"
rules:
  - id: BAS-JS-EVAL
    title: js
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: javascript
    any:
      - eval($ARG)
    description: test
    remediation: test
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "eval(x);\n";

    for file in ["bot.js", "bot.jsx", "bot.ts", "bot.mts", "bot.tsx"] {
        let findings = scan_source(&ruleset, Path::new(file), source);
        assert_eq!(findings.len(), 1, "{file} findings: {findings:?}");
        assert_eq!(findings[0].rule_id, "BAS-JS-EVAL", "{file}");
    }
}

/// The converse of [`a_javascript_rule_also_fires_on_typescript_and_tsx_files`]:
/// the subset relationship only runs one way. TypeScript syntax is not valid
/// JavaScript, so a `language: typescript` rule must never be routed to the
/// JavaScript bucket, where its patterns were never compiled.
#[test]
fn a_typescript_rule_does_not_fire_on_javascript_files() {
    let yaml = r"
rules:
  - id: BAS-TS-ONLY
    title: ts
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: typescript
    any:
      - eval($ARG)
    description: test
    remediation: test
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();

    let dot_js = scan_source(&ruleset, Path::new("bot.js"), "eval(x);\n");

    assert!(dot_js.is_empty(), "findings: {dot_js:?}");
}

/// A pattern that cannot parse as a single node under the grammar its rule
/// targets fails at load time, naming both the rule id and the grammar --
/// not silently loaded as a matcher that can never match anything.
#[test]
fn an_unparseable_pattern_fails_to_load_naming_the_language() {
    let yaml = r"
rules:
  - id: BAS-BAD-PATTERN
    title: t
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: javascript
    any:
      - foo(); bar();
    description: test
    remediation: test
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();

    assert!(
        matches!(error, RuleError::InvalidPattern { .. }),
        "got {error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("BAS-BAD-PATTERN"), "message: {message}");
    assert!(message.contains("javascript"), "message: {message}");
}

/// The same unparseable-pattern failure for a `language: typescript` rule
/// names whichever of the two grammars (`typescript`/`tsx`) it was compiling
/// against when the pattern failed -- here, `typescript`, since that compile
/// runs first.
#[test]
fn typescript_rule_pattern_error_names_the_first_grammar_it_fails_against() {
    let yaml = r"
rules:
  - id: BAS-BAD-TS-PATTERN
    title: t
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: typescript
    any:
      - foo(); bar();
    description: test
    remediation: test
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();

    assert!(
        matches!(error, RuleError::InvalidPattern { .. }),
        "got {error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("BAS-BAD-TS-PATTERN"), "message: {message}");
    assert!(message.contains("typescript"), "message: {message}");
}

/// JS/TS string-literal patterns are quote-sensitive (unlike Python's, which
/// treat quote style as insignificant to a `Pattern` match) -- a rule
/// anchored only on a double-quoted literal misses the identical value
/// written with single quotes. This is why every string-anchored rule in
/// `bastyn.yml` for JS/TS lists both quote styles; this test pins down the
/// underlying behavior so that reasoning does not silently bit-rot.
#[test]
fn javascript_string_pattern_does_not_match_the_other_quote_style() {
    let yaml = r#"
rules:
  - id: BAS-DQ-ONLY
    title: t
    kind: defect
    severity: high
    confidence: high
    categories: [ZT1]
    language: javascript
    any:
      - "\"$SECRET\""
    metavariable_matches:
      SECRET: "^sk-[A-Za-z0-9_-]{16,}$"
    description: test
    remediation: test
"#;
    let ruleset = RuleSet::from_yaml(yaml).unwrap();

    let double_quoted = scan_source(
        &ruleset,
        Path::new("a.js"),
        "const k = \"sk-abcdefgh12345678\";\n",
    );
    let single_quoted = scan_source(
        &ruleset,
        Path::new("a.js"),
        "const k = 'sk-abcdefgh12345678';\n",
    );

    assert_eq!(double_quoted.len(), 1, "findings: {double_quoted:?}");
    assert!(
        single_quoted.is_empty(),
        "expected the single-quoted literal to be missed by a double-quote-only \
         pattern, findings: {single_quoted:?}"
    );
}

// ---------------------------------------------------------------------
// Test-path policy.
// ---------------------------------------------------------------------

/// A credential rule with `id`, anchored on the string literal's own shape
/// the way `BAS-ZT1-002` is. `policy` is the `in_test_paths:` line, or empty
/// to leave the field off and get the default.
fn credential_rule(id: &str, policy: &str) -> String {
    format!(
        r#"
  - id: {id}
    title: hardcoded credential
    kind: defect
    severity: critical
    confidence: high
    categories: [ZT1]
    language: python
{policy}    any:
      - '"$VALUE"'
    metavariable_matches:
      VALUE: 'password'
    description: test
    remediation: test
"#
    )
}

fn credential_ruleset(policy: &str) -> RuleSet {
    RuleSet::from_yaml(&format!("rules:{}", credential_rule("BAS-CRED", policy))).unwrap()
}

const A_DSN: &str = "DSN = \"postgresql://user:password@localhost/db\"\n";

/// The measured false-positive fix: a placeholder DSN in a test fixture is
/// still reported, but as an observation, so it is out of the default report
/// and never fails a build.
#[test]
fn a_match_in_a_test_path_is_downgraded_to_an_observation() {
    let ruleset = credential_ruleset("");

    let findings = scan_source(&ruleset, Path::new("tests/unit/test_db.py"), A_DSN);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].kind, Kind::Observation);
    // Severity is untouched: if the credential turns out to be real it is
    // still critical, and a reader who asked for observations must see that.
    assert_eq!(findings[0].severity, Severity::Critical);
}

/// The same literal in shipped code is untouched. Without this the downgrade
/// would be a blanket severity cut rather than a path policy.
#[test]
fn a_match_outside_a_test_path_stays_a_defect() {
    let ruleset = credential_ruleset("");

    let findings = scan_source(&ruleset, Path::new("app/config.py"), A_DSN);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].kind, Kind::Defect);
}

/// A rule whose finding is worth reading even in a fixture -- a live provider
/// API key is leaked wherever it sits -- opts out.
#[test]
fn a_rule_can_opt_out_of_the_test_path_downgrade() {
    let ruleset = credential_ruleset("    in_test_paths: report\n");

    let findings = scan_source(&ruleset, Path::new("tests/unit/test_db.py"), A_DSN);

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].kind, Kind::Defect);
}

/// Two rules matching one location merge into one finding, and the surviving
/// primary must be the defect: a downgrade applied to one rule must never
/// swallow another rule's real defect at the same place.
#[test]
fn a_defect_outranks_a_downgraded_observation_at_the_same_location() {
    let yaml = format!(
        "rules:{}{}",
        credential_rule("BAS-DOWNGRADED", ""),
        credential_rule("BAS-REPORTED", "    in_test_paths: report\n"),
    );
    let ruleset = RuleSet::from_yaml(&yaml).unwrap();

    let findings = scan_source(
        &ruleset,
        Path::new("tests/unit/test_db.py"),
        "\"postgresql://user:password@localhost/db\"\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-REPORTED");
    assert_eq!(findings[0].kind, Kind::Defect);
    assert_eq!(
        findings[0].secondary_rule_ids,
        vec!["BAS-DOWNGRADED".to_owned()]
    );
}

/// An unrecognised policy is a load error, not a silent fallback to the
/// default -- a typo must not quietly turn reporting back on.
#[test]
fn an_unknown_test_path_policy_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-TYPO
    title: t
    kind: defect
    severity: high
    confidence: high
    categories: [ZT1]
    language: python
    in_test_paths: ignore
    any:
      - foo($X)
    description: test
    remediation: test
";

    let error = RuleSet::from_yaml(yaml).unwrap_err();

    assert!(matches!(error, RuleError::Yaml(_)), "got {error:?}");
}

// ---------------------------------------------------------------------
// `metavariable_not_matches` -- the inverse of `metavariable_matches`.
//
// `metavariable_matches` alone cannot express "this looks like a credential
// but is a known placeholder" (BAS-ZT1-002/003's precision bug, measured
// 2026-08-28: every real false positive was a placeholder DSN or a
// clearly-fake key). The `regex` crate this engine uses has no lookaround
// and no backreferences, so a single regex cannot both require the
// credential shape and reject specific placeholder words -- the exclusion
// needs its own gate.
// ---------------------------------------------------------------------

/// A credential rule like [`credential_rule`], but with an added
/// `metavariable_not_matches` on the same captured variable.
fn credential_rule_with_exclusion(id: &str, exclude: &str) -> String {
    format!(
        r#"
  - id: {id}
    title: hardcoded credential
    kind: defect
    severity: critical
    confidence: high
    categories: [ZT1]
    language: python
    any:
      - '"$VALUE"'
    metavariable_matches:
      VALUE: 'password'
    metavariable_not_matches:
      VALUE: '{exclude}'
    description: test
    remediation: test
"#
    )
}

/// A captured variable whose text matches `metavariable_not_matches` is
/// disqualified even though it satisfies `metavariable_matches` -- the
/// placeholder-DSN case: `localhost` in the value excludes it.
#[test]
fn metavariable_not_matches_excludes_a_matching_capture() {
    let ruleset = RuleSet::from_yaml(&format!(
        "rules:{}",
        credential_rule_with_exclusion("BAS-EXCL", "(?i)localhost")
    ))
    .unwrap();

    let placeholder = scan_source(
        &ruleset,
        Path::new("app/config.py"),
        "DSN = \"postgresql://user:password@localhost/db\"\n",
    );
    assert!(
        placeholder.is_empty(),
        "expected the localhost DSN to be excluded, findings: {placeholder:?}"
    );
}

/// The same rule still fires on a value that does not match the exclusion --
/// proof this is a narrow exception, not a blanket weakening of the rule.
#[test]
fn metavariable_not_matches_leaves_a_non_matching_capture_alone() {
    let ruleset = RuleSet::from_yaml(&format!(
        "rules:{}",
        credential_rule_with_exclusion("BAS-EXCL", "(?i)localhost")
    ))
    .unwrap();

    let real = scan_source(
        &ruleset,
        Path::new("app/config.py"),
        "DSN = \"postgresql://user:password@prod-db.internal/db\"\n",
    );
    assert_eq!(real.len(), 1, "findings: {real:?}");
}

/// A `metavariable_not_matches` entry for a variable a given `any` pattern
/// never captures is not an exclusion at all -- "no evidence" means nothing
/// to exclude, the mirror image of `metavariable_matches`'s fail-closed
/// behavior. This matters because a rule's `any` list can mix patterns that
/// bind a variable with patterns that do not (BAS-LLM10-006's bare
/// `execSync($ARG)` never binds a receiver), and adding an exclusion on the
/// receiver must not silently kill matches that have no receiver to judge.
#[test]
fn metavariable_not_matches_on_an_uncaptured_variable_excludes_nothing() {
    let yaml = r#"
rules:
  - id: BAS-EXCL-UNCAPTURED
    title: t
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: javascript
    any:
      - run($ARG)
    metavariable_not_matches:
      RECEIVER: "(?i)^(pattern|regexp)$"
    description: test
    remediation: test
"#;
    let ruleset = RuleSet::from_yaml(yaml).unwrap();

    let findings = scan_source(&ruleset, Path::new("a.js"), "run(reply);\n");

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

/// An invalid `metavariable_not_matches` regex fails to load, the same as an
/// invalid `metavariable_matches` regex does.
#[test]
fn an_invalid_metavariable_not_matches_regex_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-BAD-EXCL
    title: t
    kind: defect
    severity: high
    confidence: high
    categories: [ZT1]
    language: python
    any:
      - foo($X)
    metavariable_not_matches:
      X: '('
    description: test
    remediation: test
";

    let error = RuleSet::from_yaml(yaml).unwrap_err();

    assert!(
        matches!(error, RuleError::InvalidNotRegex { .. }),
        "got {error:?}"
    );
}

/// A rule pairing a source-shaped `any` capture with a `none_in_file` pattern
/// for the message role it is sent under: `none` only sees the matched node
/// and `inside` only its ancestors, so neither can see the sibling statement
/// that sends the same value in the user role.
const USER_ROLE_RULE_PY: &str = r#"
rules:
  - id: BAS-NIF-001
    title: t
    kind: observation
    severity: high
    confidence: high
    categories: [LLM01]
    language: python
    any:
      - $SYS = f"$$$A{$VAR}$$$B"
    none_in_file:
      - '{"role": "user", "content": $SYS}'
    description: d
    remediation: r
"#;

/// A prompt assembled with an f-string and then sent as a `role: "user"`
/// message anywhere in the file is dropped, even though the `any` pattern
/// alone would have matched the assignment.
#[test]
fn none_in_file_drops_a_prompt_sent_in_the_user_role() {
    let rules = RuleSet::from_yaml(USER_ROLE_RULE_PY).unwrap();
    let source = "def chat(client, query):\n    prompt = f\"Summarize: {query}\"\n    return client.x(messages=[{\"role\": \"user\", \"content\": prompt}])\n";
    assert_eq!(
        scan_source(&rules, Path::new("app.py"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

/// The same shape sent as a `role: "system"` message instead has nothing to
/// exclude it, and is still reported.
#[test]
fn none_in_file_keeps_a_prompt_sent_in_the_system_role() {
    let rules = RuleSet::from_yaml(USER_ROLE_RULE_PY).unwrap();
    let source = "def chat(client, query):\n    prompt = f\"Follow: {query}\"\n    return client.x(messages=[{\"role\": \"system\", \"content\": prompt}])\n";
    assert_eq!(scan_source(&rules, Path::new("app.py"), source).len(), 1);
}

/// A `role: "user"` message that sends a *different* variable does not
/// exclude the candidate: the exclusion pattern must bind `$SYS` to the same
/// text the candidate bound, not merely find a user-role message somewhere.
#[test]
fn none_in_file_requires_the_same_bound_text() {
    let rules = RuleSet::from_yaml(USER_ROLE_RULE_PY).unwrap();
    let source = "def chat(client, query, other):\n    prompt = f\"Follow: {query}\"\n    return client.x(messages=[{\"role\": \"user\", \"content\": other}])\n";
    assert_eq!(scan_source(&rules, Path::new("app.py"), source).len(), 1);
}

/// Matching is on text, not on binding: a same-named variable sent in the
/// user role anywhere in the file suppresses the candidate. Accepted, and
/// pinned here so a change to it is deliberate.
#[test]
fn none_in_file_matches_on_text_across_functions() {
    let rules = RuleSet::from_yaml(USER_ROLE_RULE_PY).unwrap();
    let source = "def a(query):\n    prompt = f\"Follow: {query}\"\n    return prompt\n\ndef b(client, prompt):\n    return client.x(messages=[{\"role\": \"user\", \"content\": prompt}])\n";
    assert_eq!(
        scan_source(&rules, Path::new("app.py"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

/// The same exclusion works against a TypeScript/JavaScript grammar, not
/// just Python.
#[test]
fn none_in_file_works_for_typescript() {
    let yaml = r#"
rules:
  - id: BAS-NIF-002
    title: t
    kind: observation
    severity: high
    confidence: high
    categories: [LLM01]
    language: javascript
    any:
      - "const $SYS = `$$$A${$VAR}$$$B`"
    none_in_file:
      - '{role: "user", content: $SYS}'
    description: d
    remediation: r
"#;
    let rules = RuleSet::from_yaml(yaml).unwrap();
    let source = "export function m(query: string) {\n  const prompt = `S: ${query}`;\n  return [{role: \"system\", content: \"x\"}, {role: \"user\", content: prompt}];\n}\n";
    assert_eq!(
        scan_source(&rules, Path::new("app.ts"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

/// A `none_in_file` pattern naming a metavariable no `any` pattern binds
/// fails to load, the same as `flow.unproven.requires` does.
#[test]
fn none_in_file_naming_an_unbound_metavariable_fails_to_load() {
    let yaml = USER_ROLE_RULE_PY.replace("$SYS}'", "$OTHER}'");
    let err = RuleSet::from_yaml(&yaml).unwrap_err();
    assert!(
        matches!(err, RuleError::UnboundMetavariable { ref var, .. } if var == "OTHER"),
        "{err}"
    );
}

/// `flow.sink` and `none_in_file` on the same rule fails to load: the
/// wrapper-sink pass that `flow.sink` turns on builds its findings straight
/// from `wrapper_sink_calls`, never through `CompiledRule::excluded_by_file`,
/// so a `none_in_file` exclusion on such a rule would be silently skipped for
/// every finding the wrapper pass reports.
#[test]
fn flow_sink_combined_with_none_in_file_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-NIF-003
    title: t
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
    none_in_file:
      - exec($ARG)
    description: d
    remediation: r
";
    let err = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(err, RuleError::FlowSinkWithNoneInFile { ref id } if id == "BAS-NIF-003"),
        "{err}"
    );
}

/// A rule that reports a bind-all address only in a file that also builds the
/// HTTP transport; `requires_in_file` has no metavariables, like the anonymous
/// `none_in_file` patterns.
const REQUIRES_RULE_TS: &str = r#"
rules:
  - id: BAS-RIF-001
    title: t
    kind: observation
    severity: low
    confidence: high
    categories: [ZT3]
    language: javascript
    any:
      - '$APP.listen($PORT, "0.0.0.0")'
    requires_in_file:
      - 'new StreamableHTTPServerTransport($$$)'
    description: d
    remediation: r
"#;

#[test]
fn requires_in_file_keeps_a_match_when_the_required_pattern_is_present() {
    let rules = RuleSet::from_yaml(REQUIRES_RULE_TS).unwrap();
    let source =
        "const t = new StreamableHTTPServerTransport({});\napp.listen(3000, \"0.0.0.0\");\n";
    assert_eq!(scan_source(&rules, Path::new("s.ts"), source).len(), 1);
}

#[test]
fn requires_in_file_drops_a_match_when_the_required_pattern_is_absent() {
    let rules = RuleSet::from_yaml(REQUIRES_RULE_TS).unwrap();
    let source = "app.listen(3000, \"0.0.0.0\");\n";
    assert_eq!(
        scan_source(&rules, Path::new("s.ts"), source),
        Vec::<crate::finding::Finding>::new()
    );
}

#[test]
fn requires_in_file_accepts_any_one_of_several_patterns() {
    let yaml = REQUIRES_RULE_TS.replace(
        "      - 'new StreamableHTTPServerTransport($$$)'",
        "      - 'new StreamableHTTPServerTransport($$$)'\n      - 'new SSEServerTransport($$$)'",
    );
    let rules = RuleSet::from_yaml(&yaml).unwrap();
    let source = "const t = new SSEServerTransport(\"/m\", res);\napp.listen(3000, \"0.0.0.0\");\n";
    assert_eq!(scan_source(&rules, Path::new("s.ts"), source).len(), 1);
}

#[test]
fn requires_in_file_combines_with_none_in_file() {
    let yaml = REQUIRES_RULE_TS.replace(
        "    description: d",
        "    none_in_file:\n      - 'requireBearerAuth($$$)'\n    description: d",
    );
    let rules = RuleSet::from_yaml(&yaml).unwrap();
    let guarded = "const t = new StreamableHTTPServerTransport({});\nrequireBearerAuth({});\napp.listen(3000, \"0.0.0.0\");\n";
    assert_eq!(
        scan_source(&rules, Path::new("s.ts"), guarded),
        Vec::<crate::finding::Finding>::new()
    );
}

#[test]
fn requires_in_file_works_for_python() {
    let yaml = r#"
rules:
  - id: BAS-RIF-002
    title: t
    kind: observation
    severity: low
    confidence: high
    categories: [ZT3]
    language: python
    any:
      - 'uvicorn.run($APP, host="0.0.0.0")'
    requires_in_file:
      - '$_.streamable_http_app()'
    description: d
    remediation: r
"#;
    let rules = RuleSet::from_yaml(yaml).unwrap();
    let hit = "app = mcp.streamable_http_app()\nuvicorn.run(app, host=\"0.0.0.0\")\n";
    assert_eq!(scan_source(&rules, Path::new("s.py"), hit).len(), 1);
    let miss = "uvicorn.run(app, host=\"0.0.0.0\")\n";
    assert_eq!(scan_source(&rules, Path::new("s.py"), miss).len(), 0);
}

#[test]
fn requires_in_file_naming_an_unbound_metavariable_fails_to_load() {
    let yaml = REQUIRES_RULE_TS.replace("new StreamableHTTPServerTransport($$$)", "new T($OTHER)");
    let err = RuleSet::from_yaml(&yaml).unwrap_err();
    assert!(
        matches!(err, RuleError::UnboundMetavariable { ref var, ref field, .. } if var == "OTHER" && field == "requires_in_file"),
        "{err}"
    );
}

#[test]
fn flow_sink_combined_with_requires_in_file_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-RIF-003
    title: t
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
    requires_in_file:
      - 'import os'
    description: d
    remediation: r
";
    let err = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(err, RuleError::FlowSinkWithRequiresInFile { ref id } if id == "BAS-RIF-003"),
        "{err}"
    );
}
