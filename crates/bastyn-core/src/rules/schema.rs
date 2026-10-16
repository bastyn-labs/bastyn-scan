//! The on-disk shape of a rule file, deserialised as written.
//!
//! `#[serde(deny_unknown_fields)]` throughout: a typo in a rule file is a load
//! error, not a silently ignored field.

use std::collections::HashMap;

use serde::Deserialize;

use crate::category::Category;
use crate::finding::{Confidence, Kind, Severity};
use crate::flow::{SinkKind, SourceKind};

/// The language a rule's patterns are written against.
///
/// The variant list is deliberately narrow so that a rule authored for a
/// language we cannot yet parse fails to load instead of silently never
/// matching.
///
/// There is no `Tsx` variant. `.tsx` files are still scanned -- see
/// [`super::engine`]'s module docs -- but a rule author writes `language:
/// typescript` once and the engine compiles it against both the TypeScript
/// and Tsx grammars internally, so the schema does not need a rule author to
/// pick between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RuleLanguage {
    /// Python source, matched via `tree-sitter-python`.
    Python,
    /// TypeScript source, matched via `tree-sitter-typescript`. Also
    /// compiled against the Tsx grammar to cover `.tsx` files.
    Typescript,
    /// JavaScript source, matched via `tree-sitter-javascript`. The same
    /// grammar parses JSX (`.jsx`), so there is no separate variant for it.
    ///
    /// Because JavaScript is a syntactic subset of TypeScript, a rule
    /// declaring this language is also compiled against the TypeScript and
    /// Tsx grammars, so it applies to `.ts` and `.tsx` files too. Declare
    /// [`Self::Typescript`] instead only when a pattern needs syntax
    /// JavaScript does not have.
    Javascript,
}

/// What a rule wants done with a match that lands in a test path.
///
/// The default is [`Self::Downgrade`], deliberately: it is the safe direction
/// for a scanner whose whole claim is precision, and a rule author who has a
/// reason to report through a fixture has to say so. See
/// [`crate::test_path`] for the measurement that motivated it and for what
/// counts as a test path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TestPathPolicy {
    /// Report the match as a [`Kind::Observation`] instead of whatever the
    /// rule's own `kind` says, so it stays out of the default report.
    #[default]
    Downgrade,
    /// Report the match unchanged. For the findings that are worth reading
    /// even in a fixture — a live provider key is leaked wherever it sits.
    Report,
}

/// The top-level shape of a rule YAML document: a list of rules.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleFile {
    /// The rules defined in this document.
    pub(crate) rules: Vec<RuleDef>,
}

/// One rule, exactly as written in YAML.
///
/// `Clone` is needed because a `language: typescript` rule is compiled twice
/// -- once against the TypeScript grammar, once against the Tsx grammar (see
/// [`super::engine`]'s module docs) -- and each compile consumes its own
/// `RuleDef`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleDef {
    /// Stable rule identifier, e.g. `"BAS-LLM10-001"`.
    pub(crate) id: String,
    /// One line, imperative, no hedging.
    pub(crate) title: String,
    /// Defect or observation.
    pub(crate) kind: Kind,
    /// Severity, if real.
    pub(crate) severity: Severity,
    /// How sure we are.
    pub(crate) confidence: Confidence,
    /// Framework categories this maps to. Must be non-empty.
    pub(crate) categories: Vec<Category>,
    /// The language the patterns below are written against.
    pub(crate) language: RuleLanguage,
    /// What to do with a match inside a test path. Defaults to
    /// [`TestPathPolicy::Downgrade`].
    #[serde(default)]
    pub(crate) in_test_paths: TestPathPolicy,
    /// Match if any of these patterns match. Must be non-empty.
    pub(crate) any: Vec<String>,
    /// Suppress a match if any of these match the same node.
    #[serde(default)]
    pub(crate) none: Vec<String>,
    /// Only match when nested inside one of these patterns.
    #[serde(default)]
    pub(crate) inside: Vec<String>,
    /// Drop a match when one of these patterns matches anywhere in the same
    /// file with every metavariable it shares bound to the same text.
    ///
    /// `none` only sees the matched node and `inside` only its ancestors;
    /// this reaches a sibling statement, such as the message that sends a
    /// prompt in the user role rather than the system role.
    #[serde(default)]
    pub(crate) none_in_file: Vec<String>,
    /// Keep a match only when one of these patterns matches anywhere in the
    /// same file, with every metavariable it shares with `any` bound to the
    /// same text.
    ///
    /// The positive twin of `none_in_file`: it anchors a rule to a file that
    /// shows the context the rule is about (for example, that an HTTP
    /// transport is built) before an otherwise ubiquitous call is reported.
    #[serde(default)]
    pub(crate) requires_in_file: Vec<String>,
    /// Captured metavariable name to the regex its text must match.
    #[serde(default)]
    pub(crate) metavariable_matches: HashMap<String, String>,
    /// Captured metavariable name to a regex its text must *not* match.
    ///
    /// The inverse of `metavariable_matches`, and a separate field rather
    /// than a negation syntax inside the same map: this engine's regex
    /// backend (the `regex` crate) has no lookaround and no backreferences,
    /// so a single regex cannot both require a shape (a credential-looking
    /// value) and reject specific content within it (a known placeholder
    /// word, or two captures being equal). A rule with no evidence for a
    /// variable here -- an `any` pattern that never binds it -- treats that
    /// as nothing to exclude, not as a failure; see
    /// [`super::engine::CompiledRule::metavariable_exclusions_clear`].
    #[serde(default)]
    pub(crate) metavariable_not_matches: HashMap<String, String>,
    /// Where a captured value must have come from, and whether a guard may
    /// already cover it.
    ///
    /// The provenance gate. `metavariable_matches` asks what a variable is
    /// *called*; this asks what produced its value, which is the question a
    /// rule about untrusted data actually needs answered. The two coexist so
    /// that rules can migrate from the first to the second one at a time
    /// rather than in a single sweep, and when both are present both apply.
    #[serde(default)]
    pub(crate) flow: Option<FlowDef>,
    /// Drop an otherwise-matching candidate when a targeted, Python-only
    /// structural predicate proves the captured value is safe.
    ///
    /// Distinct from `flow:`: `flow:` is a *positive* requirement ("this
    /// value must have come from an untrusted source"), which requires a
    /// `source:` kind. This is a *negative* exclusion for a rule that, by
    /// design, does not gate on provenance at all (`BAS-LLM10-009`,
    /// `BAS-LLM10-012` drop the source-name gate the way `BAS-LLM10-004`
    /// dropped it for eval/exec) but still recognises the handful of shapes
    /// that are provably safe regardless of where the value came from.
    #[serde(default)]
    pub(crate) exclude_if: Option<ExcludeIfDef>,
    /// What is wrong and why it matters. Two sentences at most.
    pub(crate) description: String,
    /// What to do about it. Actionable, specific to this code.
    pub(crate) remediation: String,
}

/// A rule's `flow:` clause, exactly as written in YAML.
///
/// Provenance-gated, the common case -- a value must trace to one of the
/// listed sources:
///
/// ```yaml
/// flow:
///   variable: ARG          # whose provenance to test; defaults to ARG
///   source: model_output   # one kind, or a list of them
///   unguarded: true        # and no guard may already dominate the sink
///   sink: code_execution   # also match calls to local wrappers of this sink
///   builtin_callee: true   # drop a call through a locally rebound name
///   unproven:               # report an untraceable value as an observation
///     kind: observation
///     requires:
///       ARG: "(?i)(response|reply)"
/// ```
///
/// Unconditional, when `source:` is left out entirely -- every non-closed,
/// non-guarded value is proven regardless of where it came from, the same
/// composition-is-the-defect philosophy `BAS-LLM10-009`/`-017`/`-018` already
/// use without going through `flow:` at all:
///
/// ```yaml
/// flow:
///   variable: ARG
///   unguarded: true        # a guard may still dominate the sink
///   builtin_callee: true   # a locally rebound name is still not the builtin
/// ```
///
/// `unproven:` only means something when there is a source requirement to
/// fail: with no `source:`, every value that is not closed or guarded is
/// already `Proven`, so pairing `unproven:` with an omitted `source:` is a
/// load error (see [`super::error::RuleError::UnprovenWithoutSource`]).
/// `sink:` is likewise rejected with no `source:` (see
/// [`super::error::RuleError::FlowSinkWithoutSource`]): the wrapper-sink
/// pass it enables would otherwise reach every wrapper call whose argument
/// is merely not closed and not guarded, a materially broader and currently
/// untested combination no shipped rule needs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent clause a rule opts into in YAML; a state machine would obscure which ones a rule set"
)]
pub(crate) struct FlowDef {
    /// The captured metavariable whose provenance is tested.
    ///
    /// Defaults to `ARG`, which is what every sink pattern in this corpus
    /// names its interesting capture. Naming it explicitly is still
    /// preferable in a rule whose patterns bind more than one.
    #[serde(default = "default_flow_variable")]
    pub(crate) variable: String,
    /// The source kinds the captured value must have come from. Written as a
    /// single kind or a list of them.
    ///
    /// Absent entirely, this clause does not gate on provenance at all: any
    /// value that is not closed over literals this file fixes and (with
    /// `unguarded: true`) not already dominated by a guard is proven,
    /// whatever produced it. See this struct's own docs for when to reach
    /// for this over a `source:` list.
    #[serde(default)]
    pub(crate) source: Option<SourceSpec>,
    /// Require that no guard dominates the sink.
    ///
    /// Off by default, because a rule that has not thought about guards
    /// should not silently start suppressing findings.
    #[serde(default)]
    pub(crate) unguarded: bool,
    /// Also report calls to a function *in the same file* that forwards the
    /// captured value into a sink of this kind.
    ///
    /// This is what lets `def run(x): exec(x)` called with a model reply be
    /// reported at the `run(...)` call site, which no `any:` pattern can
    /// describe. Bounded at one hop -- see [`crate::flow::graph`].
    #[serde(default)]
    pub(crate) sink: Option<SinkKind>,
    /// What to report when the value's origin cannot be traced at all.
    ///
    /// Absent, such a match is dropped. Present, it is reported as an
    /// observation instead of the rule's declared kind, provided every
    /// `requires` regex matches its capture. A value traced to a catalogued
    /// source the rule does not list is still dropped: it is known not to
    /// be what the rule is about.
    #[serde(default)]
    pub(crate) unproven: Option<UnprovenDef>,
    /// Also treat a value that carries caller input as proven, even when no
    /// listed `source:` produced it. Caller input is a function parameter
    /// (other than `self`/`cls` or a command-line parameter), HTTP request
    /// data, or the result of a catalogued model, tool or retrieval call; a
    /// value computed by calls over such input, with the input as an
    /// argument or receiver, carries it too (except through `ast.parse`).
    /// A value that carries neither a listed source nor caller input still
    /// takes the `unproven:` path. Requires `source:`.
    #[serde(default)]
    pub(crate) caller_input: bool,
    /// Drop a match whose callee is a bare name this file binds itself (a
    /// local `def eval`, an `import ... as eval`), so a rule about a Python
    /// builtin only ever reports the builtin.
    #[serde(default)]
    pub(crate) builtin_callee: bool,
    /// When true, a match whose captured value is a pure pass-through of a
    /// non-entry-point function's own parameter, unreachable in this file
    /// from any recognized entry point, is reported as `Kind::Observation`
    /// instead of the rule's declared kind -- `title` and `remediation`
    /// unchanged, only `kind`. See
    /// `crate::flow::graph::FlowGraph::is_passthrough_observation_eligible`.
    #[serde(default)]
    pub(crate) passthrough_downgrade: bool,
    /// When true, a match whose captured value carries caller input only
    /// through function parameters, inside a function that is neither a
    /// recognized entry point nor called from one in this file, is reported
    /// as `Kind::Observation` instead of the rule's declared kind. See
    /// `crate::flow::graph::FlowGraph::is_unreached_parameter_input`.
    #[serde(default)]
    pub(crate) unreached_parameter_downgrade: bool,
}

/// A `flow.unproven:` clause, exactly as written in YAML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnprovenDef {
    /// The kind an unproven match is reported as. Only `observation`.
    pub(crate) kind: UnprovenKind,
    /// Captured metavariable name to a regex its text must match, applied
    /// only on this path.
    #[serde(default)]
    pub(crate) requires: HashMap<String, String>,
}

/// The kinds an unproven match may be reported as.
///
/// One variant on purpose: a match whose origin is unknown is not evidence
/// of a defect, so `kind: defect` here fails to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UnprovenKind {
    /// Reported as [`Kind::Observation`].
    Observation,
}

/// One source kind or several, so a rule author writes `source: model_output`
/// when one will do and `source: [model_output, file_read]` when it will not.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum SourceSpec {
    /// A single kind.
    One(SourceKind),
    /// Several kinds; the value must have come from any one of them.
    Many(Vec<SourceKind>),
}

impl SourceSpec {
    /// The kinds this clause accepts.
    pub(crate) fn kinds(&self) -> Vec<SourceKind> {
        match self {
            Self::One(kind) => vec![*kind],
            Self::Many(kinds) => kinds.clone(),
        }
    }
}

/// The metavariable a `flow:` clause tests when it does not name one.
fn default_flow_variable() -> String {
    "ARG".to_owned()
}

/// A rule's `exclude_if:` clause, exactly as written in YAML.
///
/// ```yaml
/// exclude_if:
///   variable: ARG          # which capture to test; defaults to ARG
///   kind: constant_path    # closed_value | constant_path | shell_quoted |
///                          # stdin_dispatch | cli_argument | no_caller_input,
///                          # one kind or a list of them
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExcludeIfDef {
    /// The captured metavariable whose value is tested. Defaults to `ARG`,
    /// the same default `flow:` uses and for the same reason.
    #[serde(default = "default_flow_variable")]
    pub(crate) variable: String,
    /// Which Tier-2 structural predicate(s) to test.
    pub(crate) kind: ExcludeIfKindSpec,
}

/// One `exclude_if:` kind or several, so a rule author writes `kind:
/// closed_value` when one predicate is enough and `kind: [closed_value,
/// shell_quoted]` when the match should be dropped if *any* of them proves
/// the value safe.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum ExcludeIfKindSpec {
    One(ExcludeIfKind),
    Many(Vec<ExcludeIfKind>),
}

impl ExcludeIfKindSpec {
    pub(crate) fn kinds(&self) -> Vec<ExcludeIfKind> {
        match self {
            Self::One(kind) => vec![*kind],
            Self::Many(kinds) => kinds.clone(),
        }
    }
}

/// Which Python-only structural predicate `exclude_if:` tests. See
/// `crate::flow::graph::Resolved` for what each one means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExcludeIfKind {
    /// The value's origin is closed: drawn from a set this file itself
    /// fixes (a literal, a dict of literals with a proven membership check,
    /// ...).
    ClosedValue,
    /// A path expression built only from literals, `__file__`, and calls to
    /// a whitelisted set of pure path-construction functions.
    ConstantPath,
    /// Every non-literal segment is wrapped directly in
    /// `shlex.quote(...)`/`shlex.join(...)`.
    ShellQuoted,
    /// Every non-literal segment traces to a direct, unprocessed read of
    /// `sys.stdin` (`sys.stdin.read()`, `json.load(sys.stdin)`, `input()`).
    StdinDispatch,
    /// Every non-literal segment traces to the operator's own command line:
    /// `sys.argv[...]`, an attribute of `<ArgumentParser>.parse_args()`/
    /// `.parse_known_args()`, or a `click`/`typer` command function's own
    /// parameter.
    CliArgument,
    /// The value has no non-literal segment that a caller or remote party
    /// can supply: no function parameter (other than `self`/`cls` or a
    /// click/typer command parameter), no HTTP request data, and no result
    /// of a catalogued model, tool or retrieval call.
    NoCallerInput,
}
