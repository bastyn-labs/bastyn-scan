//! Measures how much of each `metavariable_matches` naming gate's precision
//! is bought at the cost of recall against realistically-named code.
//!
//! `bastyn.yml` buys a lot of its precision with a regex gate on a captured
//! variable's *name* -- `eval($ARG)` only fires when `$ARG`'s text looks like
//! `response`/`reply`/`completion`/... A gate like that is exactly as good as
//! its assumption that real code names things that way, and that assumption
//! was never measured, only asserted. A calibration run over 65 real
//! third-party AI repositories (2026-08-28) already showed the
//! consequence for two rules by contrast: BAS-LLM10-005 went from "never
//! fired" to firing repeatedly the moment its `ARG` gate was dropped, while
//! BAS-LLM10-007's gate stayed because dropping it would have traded 0
//! findings for 7 false positives on `${table}`-shaped interpolations. This
//! file turns that kind of one-off measurement into a permanent, per-rule
//! number, for every naming gate in the file, so the next such decision has
//! evidence instead of a hunch.
//!
//! # What counts as a "naming gate"
//!
//! Not every `metavariable_matches` entry gates a *name*. `BAS-ZT1-001`'s
//! `SECRET` regex (`^sk-[A-Za-z0-9_-]{16,}$`) and `BAS-ZT1-002`'s `VALUE`
//! regex test the *shape of a string's own content* -- a real API key still
//! looks like `sk-...` no matter what variable holds it, so renaming the
//! variable cannot defeat that gate and there is nothing to measure. The
//! gates this file exercises are the ones where the regex is tested against
//! the text of an *identifier* -- a variable, parameter, receiver, or
//! function/binding name -- because that is exactly the kind of gate a
//! developer's naming choice can accidentally walk around. `BAS-LLM08-001`'s
//! `VAR` gate (an identifier) is covered; its `CONTENT` gate (a secret's own
//! shape) is not, for the same reason.
//!
//! # Where the realistic names came from
//!
//! Per the task brief, the "real-world synonym" word lists below were
//! harvested by grepping the calibration corpus (65 real third-party AI
//! repositories, kept in a separate private repository and never committed
//! here) for the actual variable names
//! real code binds to a model reply and to an `eval`/`exec` argument --
//! things like `content`, `text`, `statement`, `code`, `expression`,
//! `resolved`. Nothing from that corpus is reproduced verbatim here: every
//! sample below is a synthetic snippet this file authored, using only the
//! *names* (paraphrased where a corpus name was itself gate-shaped, e.g.
//! `page_content` still contains `content`) against a vulnerability shape
//! this file also authored. That is what makes committing this file safe,
//! and is why the corpus itself is not committed here at all.
//!
//! # Method
//!
//! For each `(rule, gated variable)` pair, one source template holds every
//! *other* part of the match fixed (including any other gated variable, held
//! at a value that satisfies its own gate) and substitutes one name at a time
//! for the variable under test, drawn from three groups:
//!
//! - `in_gate`: words the regex explicitly lists. Every one must fire against
//!   the real, shipped rule -- if it does not, the regex itself is broken,
//!   not just narrow.
//! - `synonyms`: realistic names for the same value that the regex does not
//!   list. What fraction of these the shipped rule still catches is the
//!   headline brittleness number: **real-world survival rate**.
//! - `unrelated`: a value that genuinely is not the thing the rule is about.
//!   For a naming gate that is a name for something else (a config path, a
//!   table name, a retry count), because the name is what the gate reads.
//!   None of these should fire against the shipped rule; if one does, the
//!   "genuinely unrelated" classification was wrong, or the regex is looser
//!   than intended -- either way this test catches it, because `Target`'s
//!   templates and `scan_source` run the *actual* compiled rule, not a
//!   re-implementation of it.
//!
//! # Rules that gate on provenance
//!
//! A rule that has migrated to a `flow:` clause is measured the same way, but
//! two things about its fixture have to change, and both changes make the
//! measurement stricter rather than kinder.
//!
//! **Its template has to contain the whole vulnerability.** `BAS-LLM10-001`'s
//! template was `eval(__ARG__)` -- one line, with no model call anywhere in
//! the file. That is not "model output executed as code" written with a
//! different variable name; it is a snippet in which the *name is the only
//! evidence there is*, which is precisely the assumption the file exists to
//! test. Any rule that fires on it fires by guessing. So the template for a
//! provenance-gated rule binds the name from a model call and then uses it,
//! and the name still varies exactly as before:
//!
//! ```python
//! def handle(ticket):
//!     __ARG__ = client.chat.completions.create(prompt=ticket).choices[0].message.content
//!     eval(__ARG__)
//! ```
//!
//! **Its `unrelated` control has to vary the value, not the name.** Under a
//! provenance gate the name decides nothing, so `eval(config_path)` proves
//! nothing about precision: it would pass whatever the rule did. The control
//! that means something is the mirror image -- hold the name at the most
//! gate-shaped words this file has (`response`, `completion`, `output`) and
//! make the *value* innocent, here a `json.load` of a file. A rule that fires
//! on those is guessing from the name, and this file fails. That is a
//! materially harder bar than the naming-gate control it replaces, where
//! `eval(config_path)` staying silent was true by construction.
//!
//! Both changes are recorded here rather than left implicit because they move
//! a published number: the overall survival rate below is not comparable
//! across them for the migrated row. `BAS-LLM10-001` scored 0% on the old
//! template both before and after its migration -- the old fixture cannot
//! distinguish the two rules at all, which is the point.
//!
//! `BAS-LLM10-002`, `BAS-LLM10-003`'s `ARG` gate, and `BAS-ZT4-001`'s `VAR`
//! gate have since migrated the same way: their templates bind the name from
//! a catalogued source and their `unrelated` control varies the value, not
//! the name, exactly as described above. A migrated rule reports its
//! traceable value as `kind: defect` but an untraceable one -- whatever the
//! `unproven` path's own name check still lets through -- as `kind:
//! observation`, so `Target`'s `kind` field records which kind a row's
//! template is built to prove and [`run_group`] only counts a sample as
//! fired when both the rule id and that kind match; an unproven-path
//! observation can never stand in for a row that expects a defect.
//!
//! Each sample is run twice: once against `RuleSet::embedded()` (the shipped,
//! gated rule -- what the three bullet points above measure), and once
//! against a *widened* variant compiled from the same `any`/`none`/`inside`
//! patterns with only that variable's gate removed -- its
//! `metavariable_matches` entry, or its `flow:` clause (built by editing
//! `bastyn.yml`'s own parsed YAML in memory, so it
//! can never drift from the rule it is testing -- see
//! [`widened_ruleset_without`]). The widened run answers a different
//! question than the three headline numbers: not "does the shipped rule
//! catch this", but "if this gate were dropped the way BAS-LLM10-005's was,
//! would the rule still be precise". A rule with a high real-world miss rate
//! *and* zero widened false-fires on `unrelated` is a safe widening
//! candidate; a rule that fires on `unrelated` once widened is not -- that is
//! the BAS-LLM10-007 case, reproduced here as a number instead of a story.
//!
//! # What this file intentionally does not do
//!
//! It does not touch `rules/bastyn.yml` or `src/rules/`. It measures; fixing
//! a specific gate is a separate decision with its own precision trade-off,
//! made against the 65-repository corpus and recorded in `bastyn.yml` beside
//! the rule (see BAS-LLM10-007's comment for a widening that was measured and
//! refused, and BAS-LLM10-001's for a migration that was measured and taken).

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
#![expect(
    clippy::panic,
    reason = "a failed lookup against bastyn.yml's own rule list is a broken \
              test fixture, not a code path a scanner needs to survive"
)]

use std::path::PathBuf;

use bastyn_core::Kind;
use bastyn_core::rules::{RuleSet, scan_source};
use serde_yaml_ng::Value;

const RULES_YAML: &str = include_str!("../rules/bastyn.yml");

// ---------------------------------------------------------------------
// Word lists. See this module's docs for where the `synonyms` groups came
// from. Every list is checked against the rule's own regex at run time (a
// misclassified word shows up as an unexpected fire, not a silent miss), but
// each was also hand-verified against the regexes in `bastyn.yml` as of this
// writing so the tables below are not just "hope the assertion catches it".
// ---------------------------------------------------------------------

/// `BAS-LLM10-001`/`-002`/`-003`/`-006`/`-007`'s `ARG` gate:
/// `(?i)(response|reply|completion|message|content|choices|output|generated)`.
const ARG_IN_GATE: &[&str] = &[
    "response",
    "reply",
    "completion",
    "message",
    "content",
    "choices",
    "output",
    "generated",
];
/// Names real Python code binds a model reply or an `eval`/`exec` argument
/// to, harvested from the calibration corpus (see e.g. the `statement`,
/// `code`, and `expression` shapes two of its repositories use), plus the
/// task brief's own examples.
const ARG_SYNONYMS_PY: &[&str] = &[
    "suggestion",
    "answer",
    "result",
    "text",
    "resolved",
    "expression",
    "statement",
    "code",
    "raw",
    "payload",
];
/// The same idea in the TypeScript/JavaScript corpus's naming convention --
/// `runbookText`, `suggestion`, `assistantNote` are the exact names the task
/// brief cites as defeating this gate.
const ARG_SYNONYMS_JS: &[&str] = &[
    "suggestion",
    "assistantNote",
    "resolved",
    "expression",
    "calculation",
    "llmOut",
    "rawText",
    "payload",
    "result",
    "resultText",
];

/// `BAS-LLM10-003`'s `CUR` gate: `(?i)(cursor|cur|db|conn|connection)`.
const CUR_IN_GATE: &[&str] = &["cursor", "db", "conn", "connection", "cur"];
/// Realistic names for a query executor that do not contain `cur`, `db`, or
/// `conn` as a substring -- `cur` in particular is short enough that most
/// "cursor-ish" words accidentally contain it (`occurred`, `current`), so
/// this list leans on ORM/session vocabulary instead.
const CUR_SYNONYMS: &[&str] = &[
    "session",
    "handle",
    "store",
    "sql",
    "repository",
    "engine",
    "sql_client",
];

/// `BAS-ZT4-001`/`-002`'s and `BAS-ZT4-003`'s `SYS` gate:
/// `(?i)(system|prompt|instruction|persona|template)`.
const SYS_IN_GATE_PY: &[&str] = &[
    "system_prompt",
    "prompt_template",
    "base_instructions",
    "agent_persona",
    "prompt_text",
];
const SYS_IN_GATE_JS: &[&str] = &[
    "systemPrompt",
    "promptTemplate",
    "baseInstructions",
    "agentPersona",
    "promptText",
];
/// Realistic names for "the fixed instruction text" that say nothing about
/// being a prompt.
const SYS_SYNONYMS: &[&str] = &[
    "preamble",
    "directive",
    "guidance",
    "agent_setup",
    "base_text",
    "header",
    "boilerplate",
    "charter",
];

/// `BAS-ZT4-001`'s and `BAS-ZT4-003`'s `VAR` gate:
/// `(?i)(user|request|query|input|raw|message)`.
const VAR_IN_GATE_PY: &[&str] = &[
    "user_input",
    "request_body",
    "raw_query",
    "chat_message",
    "input_text",
];
const VAR_IN_GATE_JS: &[&str] = &[
    "userInput",
    "requestBody",
    "rawQuery",
    "chatMessage",
    "inputText",
];
/// Realistic names for "the untrusted text being spliced in" that avoid every
/// word in the gate.
const VAR_SYNONYMS_PY: &[&str] = &[
    "task_text",
    "topic",
    "details",
    "context_text",
    "note",
    "subject",
    "brief",
];
const VAR_SYNONYMS_JS: &[&str] = &[
    "runbookText",
    "topic",
    "details",
    "contextText",
    "note",
    "subject",
    "brief",
];

/// `BAS-LLM06-001`'s `CLIENT` gate: `(?i)(client|llm|openai|gpt)`.
const CLIENT_IN_GATE: &[&str] = &[
    "client",
    "llm",
    "openai_client",
    "gpt4_client",
    "llm_wrapper",
];
/// Realistic names for an LLM SDK handle that name the *role* rather than
/// echoing "client"/"llm"/a vendor name.
const CLIENT_SYNONYMS: &[&str] = &[
    "chatbot",
    "assistant",
    "model",
    "bot",
    "agent",
    "provider",
    "api",
    "brain",
];

/// `BAS-LLM03-001`'s `FN` gate and `BAS-LLM03-002`'s `NAME` gate: both
/// `(?i)^(delete|drop|remove|transfer|withdraw|wire|drain|revoke|terminate|
/// shutdown|sell_all|liquidate|send_funds|execute_trade|purge|wipe)`,
/// anchored at the start of the identifier.
const FN_IN_GATE_PY: &[&str] = &[
    "delete_wallet",
    "drop_table",
    "transfer_funds",
    "withdraw_cash",
    "purge_records",
];
const FN_IN_GATE_JS: &[&str] = &[
    "deleteWallet",
    "dropTable",
    "transferFunds",
    "withdrawCash",
    "purgeRecords",
];
/// Genuinely destructive/irreversible actions named with a verb the regex
/// does not anchor on.
const FN_SYNONYMS_PY: &[&str] = &[
    "close_account",
    "cancel_subscription",
    "erase_data",
    "clear_wallet",
    "kill_process",
    "flush_cache",
    "unenroll_user",
    "reset_balance",
];
const FN_SYNONYMS_JS: &[&str] = &[
    "closeAccount",
    "cancelSubscription",
    "eraseData",
    "clearWallet",
    "killProcess",
    "flushCache",
    "unenrollUser",
    "resetBalance",
];
/// Ordinary, non-destructive tool names -- the precision control for the
/// function-name gate specifically, since a generic "unrelated" word like
/// `config_path` is not a plausible tool name at all.
const FN_UNRELATED_PY: &[&str] = &[
    "get_balance",
    "list_wallets",
    "search_users",
    "calculate_total",
    "format_report",
    "validate_input",
];
const FN_UNRELATED_JS: &[&str] = &[
    "getBalance",
    "listWallets",
    "searchUsers",
    "calculateTotal",
    "formatReport",
    "validateInput",
];

/// The shared "genuinely not model output" precision control for every
/// value-naming gate (`ARG`, `CUR`, `SYS`, `VAR`, `CLIENT`). Verified by hand
/// against every gate regex above (none contain `cur`, `db`, `conn`, `user`,
/// `client`, `llm`, `gpt`, or any `ARG`/`SYS` word as a substring); the test
/// itself re-verifies this at run time by asserting none of them fire.
const GENERIC_UNRELATED: &[&str] = &[
    "config_path",
    "table_name",
    "schema",
    "retry_count",
    "page_size",
    "batch_id",
    "file_path",
    "account_id",
    "cache_ttl",
    "region_code",
];

// ---------------------------------------------------------------------
// Targets: one per (rule, gated identifier).
// ---------------------------------------------------------------------

/// One gate to measure: a `metavariable_matches` naming gate, or the `flow:`
/// provenance gate on a rule that has migrated off one.
///
/// `template` holds every other part of the match fixed -- including any
/// *other* gated variable in the same rule, pinned to a value that already
/// satisfies its own gate -- so that varying `placeholder` isolates exactly
/// one gate's brittleness at a time. `placeholder` must appear in `template`
/// exactly `placeholder_occurrences` times; [`Target::render_from`] asserts
/// this so a copy-paste mistake in a template fails loudly instead of
/// silently testing the wrong thing.
struct Target {
    rule_id: &'static str,
    var: &'static str,
    /// The kind a sample's finding must have to count as the rule firing.
    /// A flow-gated row's template proves the value's source, so it expects
    /// the rule's declared kind; a row can never be satisfied by an
    /// unproven-path observation standing in for a defect.
    kind: Kind,
    /// File extension `scan_source` dispatches on -- decides which grammar
    /// bucket the rule is matched from (see `rules::engine`'s module docs).
    ext: &'static str,
    template: &'static str,
    placeholder: &'static str,
    /// How many times `placeholder` appears in `template`. One for a naming
    /// gate, whose template needs only the sink line; two for a provenance
    /// gate, whose template has to bind the name as well as use it.
    placeholder_occurrences: usize,
    in_gate: &'static [&'static str],
    synonyms: &'static [&'static str],
    unrelated: &'static [&'static str],
    /// Template for the `unrelated` group, when "a value this rule is
    /// genuinely not about" cannot be expressed by changing a name.
    ///
    /// `None` for every naming gate: there, an unrelated *name* is exactly
    /// what an unrelated value looks like, because the name is what the gate
    /// reads. A provenance gate needs the opposite control -- the name held
    /// at its most gate-shaped and the *value* made innocent -- because under
    /// such a gate the name decides nothing at all. See this module's docs.
    unrelated_template: Option<&'static str>,
}

impl Target {
    fn render(&self, name: &str) -> String {
        self.render_from(self.template, name)
    }

    /// The `unrelated` group's source, which is [`Self::template`] unless the
    /// target supplies its own.
    fn render_unrelated(&self, name: &str) -> String {
        self.render_from(self.unrelated_template.unwrap_or(self.template), name)
    }

    fn render_from(&self, template: &'static str, name: &str) -> String {
        assert_eq!(
            template.matches(self.placeholder).count(),
            self.placeholder_occurrences,
            "{}.{}: template must contain {} exactly {} time(s)",
            self.rule_id,
            self.var,
            self.placeholder,
            self.placeholder_occurrences
        );
        template.replace(self.placeholder, name)
    }
}

/// One `Target` struct literal per gated rule -- length here is a flat list
/// of fixtures, not control flow, so splitting it up would only add
/// indirection between a rule's id and its template.
#[expect(clippy::too_many_lines, reason = "a flat list of fixtures, not logic")]
fn targets() -> Vec<Target> {
    vec![
        Target {
            rule_id: "BAS-LLM10-001",
            var: "ARG",
            kind: Kind::Defect,
            ext: "py",
            // The whole vulnerability, not just its last line. This rule now
            // gates on `flow:` -- see the "Rules that gate on provenance"
            // section in this module's docs for why a bare `eval(name)` is
            // not a fixture for it, and what replaced it.
            template: "\
def handle(ticket):
    __ARG__ = client.chat.completions.create(prompt=ticket).choices[0].message.content
    eval(__ARG__)
",
            placeholder: "__ARG__",
            placeholder_occurrences: 2,
            in_gate: ARG_IN_GATE,
            synonyms: ARG_SYNONYMS_PY,
            // The precision control is the *value*, not the name: the most
            // gate-shaped names this file has, over a value read from a file
            // rather than produced by a model.
            unrelated: ARG_IN_GATE,
            unrelated_template: Some(
                "\
def handle(path):
    __ARG__ = json.load(open(path))
    eval(__ARG__)
",
            ),
        },
        Target {
            rule_id: "BAS-LLM10-002",
            var: "ARG",
            kind: Kind::Defect,
            ext: "py",
            // This rule now gates on `flow:` -- see the "Rules that gate on
            // provenance" section in this module's docs.
            template: "\
def handle(ticket):
    __ARG__ = client.chat.completions.create(prompt=ticket).choices[0].message.content
    os.system(__ARG__)
",
            placeholder: "__ARG__",
            placeholder_occurrences: 2,
            in_gate: ARG_IN_GATE,
            synonyms: ARG_SYNONYMS_PY,
            unrelated: ARG_IN_GATE,
            unrelated_template: Some(
                "\
def handle(path):
    __ARG__ = json.load(open(path))
    os.system(__ARG__)
",
            ),
        },
        Target {
            rule_id: "BAS-LLM10-003",
            var: "ARG",
            kind: Kind::Defect,
            ext: "py",
            // CUR pinned to "cursor", an in-gate value for CUR's own regex.
            // This rule now gates ARG on `flow:` too -- see the "Rules that
            // gate on provenance" section in this module's docs.
            template: "\
def handle(ticket):
    __ARG__ = client.chat.completions.create(prompt=ticket).choices[0].message.content
    cursor.execute(__ARG__)
",
            placeholder: "__ARG__",
            placeholder_occurrences: 2,
            in_gate: ARG_IN_GATE,
            synonyms: ARG_SYNONYMS_PY,
            unrelated: ARG_IN_GATE,
            unrelated_template: Some(
                "\
def handle(path):
    __ARG__ = json.load(open(path))
    cursor.execute(__ARG__)
",
            ),
        },
        Target {
            rule_id: "BAS-LLM10-003",
            var: "CUR",
            kind: Kind::Defect,
            ext: "py",
            // ARG pinned to "response", an in-gate value for ARG's own regex.
            template: "\
def handle(ticket):
    response = client.chat.completions.create(prompt=ticket).choices[0].message.content
    __CUR__.execute(response)
",
            placeholder: "__CUR__",
            placeholder_occurrences: 1,
            in_gate: CUR_IN_GATE,
            synonyms: CUR_SYNONYMS,
            unrelated: GENERIC_UNRELATED,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-ZT4-001",
            var: "SYS",
            kind: Kind::Observation,
            ext: "py",
            // VAR pinned to "user_input", an in-gate value for VAR's own regex.
            template: "\
def handle(request):
    user_input = request.get_json()[\"q\"]
    __SYS__ = f\"Context: {user_input}\"
",
            placeholder: "__SYS__",
            placeholder_occurrences: 1,
            in_gate: SYS_IN_GATE_PY,
            synonyms: SYS_SYNONYMS,
            unrelated: GENERIC_UNRELATED,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-ZT4-001",
            var: "VAR",
            kind: Kind::Observation,
            ext: "py",
            // SYS pinned to "system_prompt", an in-gate value for SYS's own
            // regex. This rule now gates VAR on `flow:` too -- see the
            // "Rules that gate on provenance" section in this module's docs.
            template: "\
def handle(request):
    __VAR__ = request.get_json()[\"q\"]
    system_prompt = f\"Context: {__VAR__}\"
",
            placeholder: "__VAR__",
            placeholder_occurrences: 2,
            in_gate: VAR_IN_GATE_PY,
            synonyms: VAR_SYNONYMS_PY,
            unrelated: VAR_IN_GATE_PY,
            unrelated_template: Some(
                "\
def handle():
    __VAR__ = \"a fixed note\"
    system_prompt = f\"Context: {__VAR__}\"
",
            ),
        },
        Target {
            rule_id: "BAS-LLM08-001",
            var: "VAR",
            kind: Kind::Defect,
            ext: "py",
            // CONTENT pinned to a valid sk-... shape, satisfying CONTENT's own
            // (value-shape, not naming) gate.
            template: "__VAR__ = \"Key hint: sk-ABCDEFGHIJKLMNOPQRSTUVWX\"\n",
            placeholder: "__VAR__",
            placeholder_occurrences: 1,
            in_gate: SYS_IN_GATE_PY,
            synonyms: SYS_SYNONYMS,
            unrelated: GENERIC_UNRELATED,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-LLM03-001",
            var: "FN",
            kind: Kind::Observation,
            ext: "py",
            template: "@tool\ndef __FN__(args):\n    do_something(args)\n",
            placeholder: "__FN__",
            placeholder_occurrences: 1,
            in_gate: FN_IN_GATE_PY,
            synonyms: FN_SYNONYMS_PY,
            unrelated: FN_UNRELATED_PY,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-LLM06-001",
            var: "CLIENT",
            kind: Kind::Observation,
            ext: "py",
            template: "__CLIENT__.chat.completions.create(messages=msgs)\n",
            placeholder: "__CLIENT__",
            placeholder_occurrences: 1,
            in_gate: CLIENT_IN_GATE,
            synonyms: CLIENT_SYNONYMS,
            unrelated: GENERIC_UNRELATED,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-LLM10-006",
            var: "ARG",
            kind: Kind::Observation,
            ext: "ts",
            template: "execSync(__ARG__);\n",
            placeholder: "__ARG__",
            placeholder_occurrences: 1,
            in_gate: ARG_IN_GATE,
            synonyms: ARG_SYNONYMS_JS,
            unrelated: GENERIC_UNRELATED,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-LLM10-007",
            var: "ARG",
            kind: Kind::Observation,
            ext: "ts",
            template: "db.query(`SELECT * FROM t WHERE id = ${__ARG__}`);\n",
            placeholder: "__ARG__",
            placeholder_occurrences: 1,
            in_gate: ARG_IN_GATE,
            synonyms: ARG_SYNONYMS_JS,
            unrelated: GENERIC_UNRELATED,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-ZT4-003",
            var: "SYS",
            kind: Kind::Observation,
            ext: "ts",
            // VAR pinned to "userInput", an in-gate value for VAR's own regex.
            template: "const __SYS__ = `Context: ${userInput}`;\n",
            placeholder: "__SYS__",
            placeholder_occurrences: 1,
            in_gate: SYS_IN_GATE_JS,
            synonyms: SYS_SYNONYMS,
            unrelated: GENERIC_UNRELATED,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-ZT4-003",
            var: "VAR",
            kind: Kind::Observation,
            ext: "ts",
            // SYS pinned to "systemPrompt", an in-gate value for SYS's own regex.
            template: "const systemPrompt = `Context: ${__VAR__}`;\n",
            placeholder: "__VAR__",
            placeholder_occurrences: 1,
            in_gate: VAR_IN_GATE_JS,
            synonyms: VAR_SYNONYMS_JS,
            unrelated: GENERIC_UNRELATED,
            unrelated_template: None,
        },
        Target {
            rule_id: "BAS-LLM03-002",
            var: "NAME",
            kind: Kind::Observation,
            ext: "ts",
            template: "const __NAME__ = tool({\n  description: \"does a thing\",\n  execute: async (params) => {\n    doSomething(params);\n  }\n});\n",
            placeholder: "__NAME__",
            placeholder_occurrences: 1,
            in_gate: FN_IN_GATE_JS,
            synonyms: FN_SYNONYMS_JS,
            unrelated: FN_UNRELATED_JS,
            unrelated_template: None,
        },
    ]
}

// ---------------------------------------------------------------------
// Running samples through the real engine.
// ---------------------------------------------------------------------

/// One name tried against one rule, and whether that rule fired.
struct Sample {
    name: &'static str,
    fired: bool,
}

/// Which of a target's two templates a group is rendered from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    /// `in_gate` and `synonyms`: the vulnerability, with the name varying.
    Vulnerable,
    /// `unrelated`: whatever this target uses as its precision control.
    Unrelated,
}

/// Renders and scans every name in `names` for `target` against `ruleset`,
/// running the exact same `scan_source` entry point the real scanner uses --
/// nothing in this file re-implements pattern matching or regex evaluation.
fn run_group(
    ruleset: &RuleSet,
    target: &Target,
    names: &[&'static str],
    group: Group,
) -> Vec<Sample> {
    names
        .iter()
        .map(|&name| {
            let source = match group {
                Group::Vulnerable => target.render(name),
                Group::Unrelated => target.render_unrelated(name),
            };
            let path = PathBuf::from(format!(
                "brittleness/{}_{}/{name}.{}",
                target.rule_id, target.var, target.ext
            ));
            let fired = scan_source(ruleset, &path, &source)
                .iter()
                .any(|f| f.rule_id == target.rule_id && f.kind == target.kind);
            Sample { name, fired }
        })
        .collect()
}

#[expect(
    clippy::cast_precision_loss,
    reason = "sample counts are a handful of hand-written names, far under f64's 52-bit mantissa"
)]
fn hit_rate(samples: &[Sample]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let hits = samples.iter().filter(|s| s.fired).count();
    hits as f64 / samples.len() as f64 * 100.0
}

fn misses(samples: &[Sample]) -> Vec<&'static str> {
    samples
        .iter()
        .filter(|s| !s.fired)
        .map(|s| s.name)
        .collect()
}

fn fires(samples: &[Sample]) -> Vec<&'static str> {
    samples.iter().filter(|s| s.fired).map(|s| s.name).collect()
}

// ---------------------------------------------------------------------
// The widened simulation: same rule, one `metavariable_matches` entry
// removed, built by editing `bastyn.yml`'s own parsed YAML rather than a
// hand-copied pattern list, so it cannot silently drift from the rule it is
// standing in for.
// ---------------------------------------------------------------------

/// Finds `id`'s rule definition inside the parsed `rules:` sequence from
/// `bastyn.yml`.
fn find_rule(rules: &[Value], id: &str) -> Value {
    rules
        .iter()
        .find(|rule| rule.get("id").and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("no rule with id {id} in bastyn.yml"))
        .clone()
}

/// Compiles a one-rule `RuleSet` identical to `rule_id`'s shipped definition
/// except that the gate on `var` is removed -- what the rule would look like
/// if that gate were widened away, everything else (the `any`/`none`/`inside`
/// patterns, any *other* gate) held exactly as shipped.
///
/// Both gate kinds are dropped: `var`'s `metavariable_matches` entry, and the
/// whole `flow:` clause. A rule has one or the other, never both once it has
/// migrated, so this removes exactly the gate the row is measuring and the
/// "widened" columns keep meaning what they say -- what this rule would do
/// with nothing but its structural patterns left.
fn widened_ruleset_without(rules: &[Value], rule_id: &str, var: &str) -> RuleSet {
    let mut rule = find_rule(rules, rule_id);
    if let Some(gates) = rule
        .as_mapping_mut()
        .and_then(|m| m.get_mut("metavariable_matches"))
        .and_then(Value::as_mapping_mut)
    {
        gates.remove(var);
    }
    if let Some(mapping) = rule.as_mapping_mut() {
        mapping.remove("flow");
    }

    let mut doc = serde_yaml_ng::Mapping::new();
    doc.insert(
        Value::String("rules".to_owned()),
        Value::Sequence(vec![rule]),
    );
    let yaml = serde_yaml_ng::to_string(&Value::Mapping(doc)).unwrap();
    RuleSet::from_yaml(&yaml)
        .unwrap_or_else(|e| panic!("widened {rule_id}.{var} failed to compile: {e}"))
}

// ---------------------------------------------------------------------
// Report + the ratchet.
// ---------------------------------------------------------------------

/// One target's full measurement: gated (shipped-rule) results for all three
/// groups, plus widened-rule results for `synonyms` and `unrelated` --
/// the numbers that decide whether dropping this gate would be safe.
struct Row {
    target: Target,
    in_gate: Vec<Sample>,
    synonyms: Vec<Sample>,
    unrelated: Vec<Sample>,
    widened_synonyms: Vec<Sample>,
    widened_unrelated: Vec<Sample>,
}

fn print_report(rows: &[Row]) {
    println!(
        "\n{:<16} {:<8} {:>9} {:>10} {:>10}   {:>17} {:>17}",
        "rule", "var", "in-gate", "survival", "unrel.", "widened-survival", "widened-unrel."
    );
    let mut order: Vec<&Row> = rows.iter().collect();
    // Worst real-world survival first -- the brittlest rules lead the report.
    order.sort_by(|a, b| {
        hit_rate(&a.synonyms)
            .partial_cmp(&hit_rate(&b.synonyms))
            .unwrap()
    });
    for row in order {
        println!(
            "{:<16} {:<8} {:>8.0}% {:>9.0}% {:>9.0}%   {:>16.0}% {:>16.0}%",
            row.target.rule_id,
            row.target.var,
            hit_rate(&row.in_gate),
            hit_rate(&row.synonyms),
            hit_rate(&row.unrelated),
            hit_rate(&row.widened_synonyms),
            hit_rate(&row.widened_unrelated),
        );
        let missed = misses(&row.synonyms);
        if !missed.is_empty() {
            println!("    missed synonyms: {}", missed.join(", "));
        }
        let widened_false_fires = fires(&row.widened_unrelated);
        if !widened_false_fires.is_empty() {
            println!(
                "    widening would false-fire on: {}",
                widened_false_fires.join(", ")
            );
        }
    }
}

/// Floor on the overall real-world survival rate (pooled synonym hits over
/// pooled synonym samples, across every gated rule). This is a brittleness
/// *measurement*, not a target this task is allowed to fix -- see this
/// file's module docs -- so the floor exists only to catch a *regression*:
/// someone tightening a gate, or adding a new one, in a way that makes real
/// naming survive even less often than it does today.
///
/// Measured 2026-08-28 against `bastyn.yml` as of this commit: 14 gated
/// targets, 119 synonym samples. Was **0 survive**; then `BAS-LLM03-001`/
/// `-002`'s `FN`/`NAME` gate was widened (closing the head-to-head
/// benchmark's tool-authorization gap -- see `bastyn.yml`'s comment on
/// `BAS-LLM03-001`) to cover state-changing verbs generally, not just
/// destructive ones, and the added `cancel` verb incidentally covers this
/// file's own `cancel_subscription`/`cancelSubscription` synonym samples: **2
/// survive, 1.7%**. This is exactly the rise the paragraph above describes,
/// not a regression -- the widening was deliberate and measured against 65
/// real repositories (see `bastyn.yml`), this sample happening to land inside
/// the new word list is incidental. The floor moves to the new measurement so
/// it still catches a real regression instead of silently sitting stale.
///
/// Then `BAS-LLM10-001` migrated from its `ARG` name gate to a `flow:`
/// provenance gate, and its row went from **0 of 10** synonyms surviving to
/// **10 of 10**, with its (now much stricter, see "Rules that gate on
/// provenance" above) `unrelated` control still at 0%: **12 survive, 10.1%**.
/// The rise is the whole point of that migration, and the row's widened
/// column says why it is not bought with precision -- dropping the `flow:`
/// clause would make the rule fire on all eight of the innocent
/// `json.load`-sourced samples it currently rejects.
///
/// The floor is pooled across 14 targets, so it moves in steps of roughly
/// eight points per migrated rule. Thirteen name gates are still unmigrated;
/// each one that moves should raise this again.
///
/// `BAS-LLM10-002`, `-003` and `BAS-ZT4-001` moved their value gates to
/// provenance; the name lists now only decide unproven-path observations.
/// Measured after that change: 14 gated targets, 119 synonym samples, 39
/// survive, **32.8%**. The floor moves to 32%, the printed rate rounded
/// down.
const MIN_OVERALL_SURVIVAL_PCT: f64 = 32.0;

#[test]
#[expect(
    clippy::cast_precision_loss,
    reason = "sample counts are a handful of hand-written names, far under f64's 52-bit mantissa"
)]
fn brittleness_gate() {
    let ruleset = RuleSet::embedded().unwrap();
    let rules_doc: Value = serde_yaml_ng::from_str(RULES_YAML).unwrap();
    let rules = rules_doc
        .get("rules")
        .and_then(Value::as_sequence)
        .unwrap()
        .clone();

    let rows: Vec<Row> = targets()
        .into_iter()
        .map(|target| {
            let in_gate = run_group(&ruleset, &target, target.in_gate, Group::Vulnerable);
            let synonyms = run_group(&ruleset, &target, target.synonyms, Group::Vulnerable);
            let unrelated = run_group(&ruleset, &target, target.unrelated, Group::Unrelated);

            let widened = widened_ruleset_without(&rules, target.rule_id, target.var);
            let widened_synonyms = run_group(&widened, &target, target.synonyms, Group::Vulnerable);
            let widened_unrelated =
                run_group(&widened, &target, target.unrelated, Group::Unrelated);

            Row {
                target,
                in_gate,
                synonyms,
                unrelated,
                widened_synonyms,
                widened_unrelated,
            }
        })
        .collect();

    print_report(&rows);

    let mut failures = Vec::new();
    for row in &rows {
        let in_gate_pct = hit_rate(&row.in_gate);
        if (in_gate_pct - 100.0).abs() > f64::EPSILON {
            failures.push(format!(
                "{}.{}: in-gate hit rate is {in_gate_pct:.0}%, expected 100% -- a name the \
                 regex itself lists must always fire; missed: {}",
                row.target.rule_id,
                row.target.var,
                misses(&row.in_gate).join(", ")
            ));
        }
        let unrelated_pct = hit_rate(&row.unrelated);
        if unrelated_pct > 0.0 {
            failures.push(format!(
                "{}.{}: unrelated false-fire rate is {unrelated_pct:.0}%, expected 0%; fired \
                 on: {}",
                row.target.rule_id,
                row.target.var,
                fires(&row.unrelated).join(", ")
            ));
        }
    }

    let total_synonym_samples: usize = rows.iter().map(|row| row.synonyms.len()).sum();
    let total_synonym_hits: usize = rows
        .iter()
        .map(|row| row.synonyms.iter().filter(|s| s.fired).count())
        .sum();
    let overall_survival = if total_synonym_samples == 0 {
        100.0
    } else {
        total_synonym_hits as f64 / total_synonym_samples as f64 * 100.0
    };
    println!(
        "\noverall real-world survival rate: {overall_survival:.1}% ({total_synonym_hits}/{total_synonym_samples})"
    );

    if overall_survival < MIN_OVERALL_SURVIVAL_PCT {
        failures.push(format!(
            "overall real-world survival rate regressed to {overall_survival:.1}%, floor is \
             {MIN_OVERALL_SURVIVAL_PCT}%"
        ));
    }

    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
