//! Compiling loaded rules into matchers, and running them over source.
//!
//! # Multi-language dispatch
//!
//! `ast_grep_core`'s [`Pattern`] and [`RegexMatcher`] are both language-erased
//! *once compiled*: neither type carries a `Language` type parameter, so
//! nothing at the type level stops a `Pattern` compiled against one grammar
//! from being handed to [`ast_grep_core::matcher::MatcherExt::find_all`] on a
//! tree parsed with a *different* grammar. A `Pattern`'s internal node-kind
//! ids are meaningful only relative to the grammar it was compiled with;
//! comparing them against another grammar's tree would silently compare
//! unrelated numbers; not a compile error, not a panic, just wrong answers.
//!
//! [`RuleSet`] therefore keeps one compiled bucket of [`CompiledRule`] per
//! grammar (`python`, `javascript`, `typescript`, `tsx`) and [`scan_source`]
//! picks the bucket that matches the file's grammar *before* handing any
//! pattern to a tree. A rule is never even tried against a file whose
//! grammar it was not compiled for.
//!
//! The actual matching logic ([`scan_with`]) is written once, generic over
//! `L: LanguageExt + Copy`, rather than duplicated per language: `Pattern`,
//! `RegexMatcher`, `Any<Pattern>`, and `Node::{find_all,matches,inside}` are
//! all already generic over the document type, so the only place a concrete
//! language actually has to be named is where a [`Pattern`] or an
//! [`AstGrep`] tree is constructed.
//!
//! ## Why TypeScript rules compile twice
//!
//! `ast-grep-language` ships TypeScript and Tsx as two distinct
//! `tree-sitter` grammars (`tree-sitter-typescript`'s `LANGUAGE_TYPESCRIPT`
//! and `LANGUAGE_TSX`), each with its own node-kind table. They are close
//! enough that most everyday code parses identically under both, but they
//! are not guaranteed to agree, and in at least one case they concretely do
//! not: TypeScript's angle-bracket type assertion (`<Foo>bar`) parses to a
//! `type_assertion` node under the TypeScript grammar and to an `ERROR` node
//! under the Tsx grammar (JSX's `<Foo>` opening-tag syntax wins the
//! ambiguity). A `Pattern` compiled once against TypeScript and reused
//! against a Tsx tree would be trusting that every node-kind id it captured
//! happens to line up in a grammar it was never compiled against -- exactly
//! the class of silent mismatch this module exists to avoid.
//!
//! So a `language: typescript` rule in `bastyn.yml` is compiled twice, once
//! per grammar, in [`RuleSet::from_yaml`]: once against
//! [`ast_grep_language::TypeScript`] for `.ts`/`.cts`/`.mts` files, and once
//! against [`ast_grep_language::Tsx`] for `.tsx` files. Both compiles must
//! succeed for the rule to load -- if a pattern only parses under one
//! grammar, that is a real authoring bug the rule author needs to fix, not a
//! gap to paper over silently. There is deliberately no `RuleLanguage::Tsx`
//! variant in the schema: a rule author writes `language: typescript` once,
//! and covering `.tsx` is this module's job, not theirs. `RuleSet::len`
//! counts such a rule once, not twice; see its doc comment.
//!
//! ## Why JavaScript rules compile three times
//!
//! The same argument runs one step further, in one direction only.
//! JavaScript is a syntactic subset of TypeScript: every construct a
//! `language: javascript` pattern can describe is equally valid in a `.ts`
//! or `.tsx` file, so such a rule is compiled against all three grammars and
//! lands in all three buckets.
//!
//! Routing it to the JavaScript bucket alone was a silent coverage hole:
//! `eval($ARG)` written as a JavaScript rule scanned `.js` and skipped the
//! byte-identical `.ts` file beside it, with no error, no warning, and
//! nothing in the report to say one file had been scanned by fewer rules
//! than its neighbour. That is precisely the class of quiet mismatch this
//! per-grammar dispatch exists to prevent, so it is now pinned by
//! `a_javascript_rule_also_fires_on_typescript_and_tsx_files`.
//!
//! The subset relationship does not run the other way, and the dispatch must
//! not pretend it does. TypeScript-only syntax (`x satisfies T`, `interface`,
//! a type annotation) is not valid JavaScript, so a `language: typescript`
//! rule stays out of the JavaScript bucket -- pinned by
//! `a_typescript_rule_does_not_fire_on_javascript_files`.
//!
//! `RegexMatcher` (used for `metavariable_matches`) needs none of this: it
//! matches on a captured node's *text*, not its structure, so one compiled
//! regex is reused across every language a rule targets.
//!
//! # One traversal per file, not one per rule
//!
//! [`Node::find_all`] is `dfs().filter_map(..)`: calling it once per rule
//! walks the whole tree once per rule. With 21 Python rules loaded, plus the
//! separate `dfs()` that looks for parse errors, a Python file used to be
//! walked 22 times. Measured on a 250k-line repository, tree-cursor movement
//! (`ts_tree_cursor_*`) was 64% of the process's samples against 27% for
//! tree-sitter parsing itself — the scanner spent more than twice as long
//! re-walking trees as it did building them.
//!
//! [`scan_with`] therefore drives one [`Node::dfs`] itself and offers each
//! node to every rule, folding the parse-error check into the same pass. The
//! per-node work is unchanged: [`Node::find_all`]'s kind pre-filter is
//! reproduced by [`CompiledRule::can_match_kind`], and the matcher it calls
//! for a surviving node is the same [`ast_grep_core::matcher::MatcherExt::match_node`]
//! on the same [`Any`], so the same nodes match in the same order.

use std::cmp::Reverse;
use std::collections::HashSet;
use std::path::Path;

use ast_grep_core::matcher::{Matcher, MatcherExt, Pattern, RegexMatcher};
use ast_grep_core::meta_var::MetaVarEnv;
use ast_grep_core::ops::Any;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Doc, Node};
use ast_grep_language::{JavaScript, LanguageExt, Python, Tsx, TypeScript};

use crate::category::Category;
use crate::finding::{Confidence, Finding, Kind, Location, Severity};
use crate::flow::graph::{callee_path as flow_graph_callee_path, contains_sink_call};
use crate::flow::{FlowGraph, FlowLanguage, SinkKind, SourceKind, guards, shadow};
use crate::test_path::is_test_path;

use super::error::{Result, RuleError};
use super::schema::{
    ExcludeIfDef, ExcludeIfKind, RuleDef, RuleFile, RuleLanguage, TestPathPolicy, UnprovenDef,
    UnprovenKind,
};

/// A grammar the engine can parse and match rules against, guessed from a
/// file's extension.
///
/// This is the file-extension dispatch: a file whose extension maps to
/// `None` has no grammar in this binary and is skipped cleanly by
/// [`scan_source`] rather than being parsed as something it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceLanguage {
    Python,
    Javascript,
    Typescript,
    /// `.tsx` specifically -- see this module's docs for why it is not just
    /// `Typescript`.
    Tsx,
}

impl SourceLanguage {
    /// Guess a file's language from its extension.
    #[must_use]
    pub(crate) fn from_path(path: &Path) -> Option<Self> {
        match path.extension().and_then(|ext| ext.to_str())? {
            "py" => Some(Self::Python),
            "js" | "mjs" | "cjs" | "jsx" => Some(Self::Javascript),
            "ts" | "mts" | "cts" => Some(Self::Typescript),
            "tsx" => Some(Self::Tsx),
            _ => None,
        }
    }
}

/// A rule, compiled once so its patterns and regexes need not be rebuilt on
/// every file.
///
/// Deliberately not generic over a language: neither [`Pattern`] nor
/// [`RegexMatcher`] carry a language type parameter (see this module's
/// docs), so the same struct shape serves a rule compiled against any
/// grammar. What varies per grammar is which bucket in [`RuleSet`] a given
/// `CompiledRule` lives in, decided once at load time in
/// [`RuleSet::from_yaml`].
struct CompiledRule {
    id: String,
    title: String,
    kind: Kind,
    severity: Severity,
    confidence: Confidence,
    categories: Vec<Category>,
    description: String,
    remediation: String,
    in_test_paths: TestPathPolicy,
    any: Any<Pattern>,
    /// Node kinds `any` could possibly match, indexed by tree-sitter kind id,
    /// or `None` when it could match any kind at all.
    ///
    /// This is [`Any::potential_kinds`] flattened into a lookup table once at
    /// compile time. [`Node::find_all`] asks the matcher for the same bitset
    /// on every call and uses it to skip nodes before constructing a
    /// `MetaVarEnv`; [`scan_with`] drives the traversal itself, so it has to
    /// apply that filter itself to keep the per-node cost the same. A `Vec`
    /// rather than the `bit_set::BitSet` the matcher returns because
    /// `ast-grep-core` does not re-export that type, and because kind ids are
    /// dense and small enough that one byte each is cheaper to probe than a
    /// word-and-mask.
    any_kinds: Option<Vec<bool>>,
    none: Vec<Pattern>,
    inside: Vec<Pattern>,
    /// `none_in_file:` patterns paired with the metavariables each one
    /// shares with `any` (sorted, for deterministic iteration). Checked by
    /// [`CompiledRule::excluded_by_file`] against a whole-file search rather
    /// than the candidate node alone, unlike [`Self::none`].
    none_in_file: Vec<(Pattern, Vec<String>)>,
    /// `requires_in_file:` patterns, paired like [`Self::none_in_file`].
    /// Checked by [`CompiledRule::satisfies_file_requirement`].
    requires_in_file: Vec<(Pattern, Vec<String>)>,
    metavariable_matches: Vec<(String, RegexMatcher)>,
    metavariable_not_matches: Vec<(String, RegexMatcher)>,
    flow: Option<CompiledFlow>,
    exclude_if: Option<CompiledExcludeIf>,
}

/// Appended to the description of a finding reported through a `flow:`
/// rule's unproven path.
const UNPROVEN_NOTE: &str = "The origin of this value could not be traced within this file, so this is reported as an observation rather than a defect.";

/// What a `flow:` clause concludes about one captured value. Ordered from
/// weakest to strongest so the wrapper pass can take the strongest verdict
/// across a call's arguments with `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FlowVerdict {
    /// Not reported.
    Drop,
    /// Reported as an observation, if the unproven path's `requires` holds.
    Unproven,
    /// Reported with the rule's declared kind.
    Proven,
}

/// A validated `flow.unproven` clause.
struct CompiledUnproven {
    /// Captured metavariable name to the regex its text must match, applied
    /// only on the unproven path.
    requires: Vec<(String, RegexMatcher)>,
}

impl CompiledUnproven {
    /// Whether every `requires` regex matches its capture. A metavariable
    /// this match did not bind fails closed, as `metavariable_matches` does.
    fn met<D: Doc>(&self, env: &MetaVarEnv<'_, D>) -> bool {
        self.requires.iter().all(|(var, regex)| {
            env.get_match(var)
                .is_some_and(|node| regex.match_node(node.clone()).is_some())
        })
    }
}

/// A rule's `flow:` clause, validated at load time.
///
/// Everything above it in [`CompiledRule`] decides whether a piece of code
/// has the *shape* of a defect; this decides whether the value flowing
/// through that shape is one this rule should report at all. In its common
/// form (`sources: Some(...)`) it is the provenance gate: the value must
/// have come from somewhere untrusted, and [`crate::flow`] explains why that
/// distinction is the whole point of this tier. In its other form (`sources:
/// None`) there is no provenance question to ask -- every value not closed
/// over literals this file fixes and (with `unguarded`) not already
/// dominated by a guard is reported, whatever produced it; see
/// [`super::schema::FlowDef`]'s own docs for when a rule reaches for this
/// form instead.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent clause a rule opts into in YAML; a state machine would obscure which ones a rule set"
)]
struct CompiledFlow {
    /// Which captured metavariable to test.
    variable: String,
    /// The source kinds that satisfy the gate, when the rule has one.
    ///
    /// `Some(non_empty)` when the rule wrote a `source:` list (non-empty,
    /// enforced at load); `None` when it left `source:` out entirely, which
    /// means there is no provenance requirement at all -- every value that
    /// clears the closed/guard checks below is `Proven`.
    sources: Option<Vec<SourceKind>>,
    /// Whether a guard dominating the sink suppresses the match.
    unguarded: bool,
    /// When set, calls to a local function forwarding the value into a sink of
    /// this kind are reported too, at the call site.
    sink: Option<SinkKind>,
    /// When set, a value whose origin cannot be traced at all is reported as
    /// an observation instead of being dropped, provided its `requires`
    /// (if any) holds.
    unproven: Option<CompiledUnproven>,
    /// Drop a match whose callee is a bare name this file rebinds itself.
    builtin_callee: bool,
    /// When true, a match whose captured value is a pure pass-through of a
    /// non-entry-point function's own parameter, unreachable in this file
    /// from any recognized entry point, is reported as an observation
    /// instead of the rule's declared kind. See
    /// `crate::flow::graph::FlowGraph::is_passthrough_observation_eligible`.
    passthrough_downgrade: bool,
    /// When true, a match whose caller input is only function parameters of
    /// a function no recognized entry point reaches in this file is reported
    /// as an observation. See
    /// `crate::flow::graph::FlowGraph::is_unreached_parameter_input`.
    unreached_parameter_downgrade: bool,
}

impl CompiledFlow {
    /// What this clause concludes about `node_id`'s value in `graph`.
    fn verdict(&self, graph: &FlowGraph, node_id: usize) -> FlowVerdict {
        // A value drawn only from literals this file fixes cannot carry
        // anything an attacker wrote, whatever the rule is about.
        if graph.is_closed(node_id) {
            return FlowVerdict::Drop;
        }
        if self.unguarded && guards::is_guarded(graph, node_id) {
            return FlowVerdict::Drop;
        }
        // No `source:` list means no provenance requirement: a value that
        // reached this point is not closed and (if `unguarded`) not guarded,
        // so it is proven regardless of where it came from.
        let Some(sources) = &self.sources else {
            return FlowVerdict::Proven;
        };
        match graph.source_kind_of(node_id) {
            Some(kind) if sources.contains(&kind) => FlowVerdict::Proven,
            // An untraced value takes the unproven path when this clause
            // has one; a value traced to a source this rule does not list
            // is known not to be what the rule is about, so it is dropped
            // just the same as one with no known origin and no such path.
            None if self.unproven.is_some() => FlowVerdict::Unproven,
            Some(_) | None => FlowVerdict::Drop,
        }
    }
}

/// A rule's `exclude_if:` clause, validated at load time.
struct CompiledExcludeIf {
    /// Which captured metavariable to test.
    variable: String,
    /// Which Tier-2 predicate(s) to test it with; the match is dropped if
    /// *any* proves the value safe.
    kinds: Vec<ExcludeIfKind>,
}

impl CompiledRule {
    /// Compile `def` against `lang`. `grammar` is a human-readable name for
    /// that grammar (e.g. `"typescript"`, `"tsx"`) used only to make a
    /// pattern-compile error say which of a rule's (possibly several)
    /// target grammars actually failed.
    fn compile<L: LanguageExt + Copy>(
        def: RuleDef,
        grammar: &'static str,
        lang: L,
    ) -> Result<Self> {
        if def.any.is_empty() {
            return Err(RuleError::EmptyAny { id: def.id });
        }
        if def.categories.is_empty() {
            return Err(RuleError::EmptyCategories { id: def.id });
        }
        if def.kind == Kind::Defect
            && let Some(category) = def
                .categories
                .iter()
                .find(|category| category.is_context_dependent())
        {
            return Err(RuleError::ContextDependentDefect {
                id: def.id,
                category: category.id().to_string(),
            });
        }

        let any = compile_patterns(&def.id, grammar, &def.any, lang)?;
        let none = compile_patterns(&def.id, grammar, &def.none, lang)?;
        let inside = compile_patterns(&def.id, grammar, &def.inside, lang)?;

        // What the `any` patterns actually bind, so a field naming a
        // metavariable (`flow.unproven.requires`) can be checked against
        // real evidence rather than trusted blindly.
        let any_vars: HashSet<String> = any
            .iter()
            .flat_map(|pattern| pattern.defined_vars())
            .map(str::to_owned)
            .collect();

        let flow = compile_flow(&def, &any_vars)?;
        let none_in_file = compile_file_patterns(
            &def,
            "none_in_file",
            &def.none_in_file,
            grammar,
            lang,
            &any_vars,
        )?;
        let requires_in_file = compile_file_patterns(
            &def,
            "requires_in_file",
            &def.requires_in_file,
            grammar,
            lang,
            &any_vars,
        )?;
        let exclude_if = compile_exclude_if(&def.id, def.language, def.exclude_if)?;

        let mut metavariable_matches = Vec::with_capacity(def.metavariable_matches.len());
        for (var, regex_src) in def.metavariable_matches {
            let regex =
                RegexMatcher::try_new(&regex_src).map_err(|source| RuleError::InvalidRegex {
                    id: def.id.clone(),
                    var: var.clone(),
                    source,
                })?;
            metavariable_matches.push((var, regex));
        }

        let mut metavariable_not_matches = Vec::with_capacity(def.metavariable_not_matches.len());
        for (var, regex_src) in def.metavariable_not_matches {
            let regex =
                RegexMatcher::try_new(&regex_src).map_err(|source| RuleError::InvalidNotRegex {
                    id: def.id.clone(),
                    var: var.clone(),
                    source,
                })?;
            metavariable_not_matches.push((var, regex));
        }

        let any = Any::new(any);
        let any_kinds = any.potential_kinds().map(|kinds| {
            let mut table = vec![false; kinds.iter().max().map_or(0, |max| max + 1)];
            for kind in &kinds {
                table[kind] = true;
            }
            table
        });

        Ok(Self {
            id: def.id,
            title: def.title,
            kind: def.kind,
            severity: def.severity,
            confidence: def.confidence,
            categories: def.categories,
            description: def.description,
            remediation: def.remediation,
            in_test_paths: def.in_test_paths,
            any,
            any_kinds,
            none,
            inside,
            none_in_file,
            requires_in_file,
            metavariable_matches,
            metavariable_not_matches,
            flow,
            exclude_if,
        })
    }

    /// Whether a node of kind id `kind` is worth offering to [`Self::any`].
    ///
    /// Exactly the test [`Node::find_all`] applies before calling the
    /// matcher: a rule whose patterns all pin a concrete node kind can reject
    /// most of a tree on one indexed load. A rule that could match any kind
    /// (`any_kinds` is `None`) is always offered the node, as `find_all`
    /// would.
    fn can_match_kind(&self, kind: usize) -> bool {
        self.any_kinds
            .as_ref()
            .is_none_or(|kinds| kinds.get(kind).copied().unwrap_or(false))
    }

    /// Whether every `metavariable_matches` constraint is satisfied by the
    /// captures in `env`. A constraint on a variable that this particular
    /// match did not capture fails closed: no evidence, no match.
    ///
    /// Generic over the document type rather than fixed to one language,
    /// same reasoning as [`scan_with`]: `RegexMatcher` only ever looks at a
    /// captured node's text, so this logic is identical for every grammar
    /// and does not need writing more than once.
    fn metavariables_satisfied<D: Doc>(&self, env: &MetaVarEnv<'_, D>) -> bool {
        self.metavariable_matches.iter().all(|(var, regex)| {
            env.get_match(var)
                .is_some_and(|node| regex.match_node(node.clone()).is_some())
        })
    }

    /// Whether every `metavariable_not_matches` constraint is clear of the
    /// captures in `env`.
    ///
    /// The mirror image of [`Self::metavariables_satisfied`], and
    /// deliberately the *opposite* default on missing evidence: a variable
    /// this particular `any` pattern never bound has nothing to exclude, so
    /// it passes. That difference matters whenever a rule's `any` list mixes
    /// patterns that bind a variable with patterns that do not (e.g. a
    /// receiver-qualified call alongside a bare one) -- failing closed here
    /// the way the positive gate does would silently kill every match from
    /// the patterns that have no receiver to judge at all.
    fn metavariable_exclusions_clear<D: Doc>(&self, env: &MetaVarEnv<'_, D>) -> bool {
        self.metavariable_not_matches.iter().all(|(var, regex)| {
            env.get_match(var)
                .is_none_or(|node| regex.match_node(node.clone()).is_none())
        })
    }

    /// Whether a `none_in_file` pattern matches elsewhere in the file with
    /// the same bindings this candidate has. A pattern that shares a
    /// metavariable this candidate did not bind cannot match it, so it does
    /// not exclude the candidate.
    ///
    /// Only reached by candidates that passed every other gate, so the
    /// whole-file search runs on the few matches that would otherwise be
    /// reported.
    fn excluded_by_file<D: Doc>(&self, root: &Node<'_, D>, env: &MetaVarEnv<'_, D>) -> bool {
        self.none_in_file
            .iter()
            .any(|(pattern, vars)| file_has_match(root, env, pattern, vars).unwrap_or(false))
    }

    /// Whether the rule's `requires_in_file` is satisfied: vacuously true when
    /// the rule declares none, otherwise at least one required pattern must
    /// match elsewhere in the file with the same bindings this candidate has.
    /// A required pattern that shares a metavariable this candidate did not
    /// bind cannot be satisfied by it, so such a candidate is dropped when no
    /// other required pattern is satisfied.
    fn satisfies_file_requirement<D: Doc>(
        &self,
        root: &Node<'_, D>,
        env: &MetaVarEnv<'_, D>,
    ) -> bool {
        self.requires_in_file.is_empty()
            || self
                .requires_in_file
                .iter()
                .any(|(pattern, vars)| file_has_match(root, env, pattern, vars).unwrap_or(false))
    }
}

/// Compile `def.flow`, if present, given the metavariables `def.any` binds.
///
/// Split out of [`CompiledRule::compile`] to keep that function within
/// clippy's line-count lint -- the flow clause has enough of its own
/// validation to deserve its own scope.
fn compile_flow(def: &RuleDef, any_vars: &HashSet<String>) -> Result<Option<CompiledFlow>> {
    let Some(flow) = &def.flow else {
        return Ok(None);
    };
    // The dataflow graph is Python-only (see `crate::flow`), so a `flow:`
    // clause anywhere else would compile into a matcher that can never fire.
    // Rejecting it here is the same contract `RuleLanguage` itself keeps: a
    // rule we cannot honour fails to load rather than silently never
    // matching.
    if def.language != RuleLanguage::Python {
        return Err(RuleError::FlowUnsupportedLanguage {
            id: def.id.clone(),
            language: format!("{:?}", def.language).to_lowercase(),
        });
    }
    // `source:` is optional: a rule may skip the provenance gate entirely and
    // rely only on the closed/guard/shadow checks below (the same
    // unconditional-composition philosophy `BAS-LLM10-009`/`-017`/`-018`
    // already use). Only when the rule wrote a `source:` list is that list
    // validated -- there is nothing to validate about its absence.
    let sources = match &flow.source {
        None => None,
        Some(spec) => {
            let kinds = spec.kinds();
            if kinds.is_empty() {
                return Err(RuleError::EmptyFlowSources { id: def.id.clone() });
            }
            Some(kinds)
        }
    };
    // `unproven:` only changes what happens to a value whose source *cannot*
    // be traced against a `source:` list. With no `source:` at all, every
    // value that clears the closed/guard checks is already `Proven`, so
    // there is no untraceable path for `unproven:` to change anything about.
    if sources.is_none() && flow.unproven.is_some() {
        return Err(RuleError::UnprovenWithoutSource { id: def.id.clone() });
    }
    // A sourceless `flow:` clause combined with `flow.sink` would let the
    // wrapper-sink pass report every call to a local wrapper whose argument
    // is merely not closed and (with `unguarded`) not guarded -- a
    // materially broader reach than any shipped rule exercises today, and
    // genuinely untested behavior. Rejected here rather than shipped
    // silently; a rule author who actually needs this combination can lift
    // the restriction deliberately later.
    if sources.is_none() && flow.sink.is_some() {
        return Err(RuleError::FlowSinkWithoutSource { id: def.id.clone() });
    }
    // The wrapper-sink pass `flow.sink` turns on builds its findings
    // straight from `wrapper_sink_calls`, never through
    // `CompiledRule::excluded_by_file` -- see this module's `scan_with`. A
    // `none_in_file` exclusion on such a rule would therefore be silently
    // skipped for every wrapper-call finding, so the combination is rejected
    // here rather than shipped half-working.
    if flow.sink.is_some() && !def.none_in_file.is_empty() {
        return Err(RuleError::FlowSinkWithNoneInFile { id: def.id.clone() });
    }
    // Same reasoning for `requires_in_file`: the wrapper-sink pass never
    // consults `CompiledRule::satisfies_file_requirement`.
    if flow.sink.is_some() && !def.requires_in_file.is_empty() {
        return Err(RuleError::FlowSinkWithRequiresInFile { id: def.id.clone() });
    }
    // The wrapper-sink pass `flow.sink` turns on builds its own findings
    // straight from `wrapper_sink_calls`, bypassing the per-node match loop
    // `passthrough_downgrade` is computed in -- rejected here rather than
    // shipped silently half-working, for the same reason as the
    // `none_in_file` check just above.
    if flow.sink.is_some() && flow.passthrough_downgrade {
        return Err(RuleError::PassthroughDowngradeWithSink { id: def.id.clone() });
    }
    if flow.sink.is_some() && flow.unreached_parameter_downgrade {
        return Err(RuleError::UnreachedParameterDowngradeWithSink { id: def.id.clone() });
    }
    let unproven = match &flow.unproven {
        None => None,
        // `kind` is destructured, not ignored, so its only possible value is
        // a read rather than dead weight: the struct pattern is exhaustive
        // precisely because `UnprovenKind` has one variant.
        Some(UnprovenDef {
            kind: UnprovenKind::Observation,
            requires,
        }) => {
            // Sorted so the first `UnboundMetavariable` or
            // `InvalidUnprovenRegex` a rule author sees is deterministic
            // rather than a `HashMap` iteration order.
            let mut requires_entries: Vec<(&String, &String)> = requires.iter().collect();
            requires_entries.sort_by_key(|(var, _)| *var);

            let mut compiled = Vec::with_capacity(requires_entries.len());
            for (var, regex_src) in requires_entries {
                if !any_vars.contains(var) {
                    return Err(RuleError::UnboundMetavariable {
                        id: def.id.clone(),
                        field: "flow.unproven.requires".to_string(),
                        var: var.clone(),
                    });
                }
                let regex = RegexMatcher::try_new(regex_src).map_err(|source| {
                    RuleError::InvalidUnprovenRegex {
                        id: def.id.clone(),
                        var: var.clone(),
                        source,
                    }
                })?;
                compiled.push((var.clone(), regex));
            }
            Some(CompiledUnproven { requires: compiled })
        }
    };
    Ok(Some(CompiledFlow {
        variable: flow.variable.clone(),
        sources,
        unguarded: flow.unguarded,
        sink: flow.sink,
        unproven,
        builtin_callee: flow.builtin_callee,
        passthrough_downgrade: flow.passthrough_downgrade,
        unreached_parameter_downgrade: flow.unreached_parameter_downgrade,
    }))
}

/// Whether `pattern` matches anywhere under `root` with every metavariable in
/// `vars` bound to the same text as in the candidate's `env`.
///
/// Returns `None` when the candidate did not bind all of `vars` (it came from
/// an `any` pattern that does not define them), so there is nothing to
/// compare. The callers treat `None` as "no match": a `none_in_file` pattern
/// then does not exclude the candidate (it is kept), and a `requires_in_file`
/// pattern is not satisfied (the candidate is dropped, unless another
/// required pattern is satisfied).
fn file_has_match<D: Doc>(
    root: &Node<'_, D>,
    env: &MetaVarEnv<'_, D>,
    pattern: &Pattern,
    vars: &[String],
) -> Option<bool> {
    let wanted = vars
        .iter()
        .map(|var| env.get_match(var).map(|node| node.text().into_owned()))
        .collect::<Option<Vec<String>>>()?;
    Some(root.find_all(pattern).any(|hit| {
        vars.iter().zip(&wanted).all(|(var, text)| {
            hit.get_env()
                .get_match(var)
                .is_some_and(|node| node.text() == text.as_str())
        })
    }))
}

/// Compile one of a rule's whole-file pattern lists (`none_in_file` or
/// `requires_in_file`, named by `field`), pairing each pattern with the metavariables
/// (sorted, for deterministic error ordering) it shares with `any`.
///
/// Split out of [`CompiledRule::compile`] for the same reason
/// [`compile_flow`] is: keeping that function within clippy's line-count
/// lint.
fn compile_file_patterns<L: LanguageExt + Copy>(
    def: &RuleDef,
    field: &str,
    sources: &[String],
    grammar: &'static str,
    lang: L,
    any_vars: &HashSet<String>,
) -> Result<Vec<(Pattern, Vec<String>)>> {
    let patterns = compile_patterns(&def.id, grammar, sources, lang)?;
    patterns
        .into_iter()
        .map(|pattern| {
            let mut vars: Vec<String> = pattern
                .defined_vars()
                .into_iter()
                .map(str::to_owned)
                .collect();
            vars.sort_unstable();
            if let Some(var) = vars.iter().find(|var| !any_vars.contains(*var)) {
                return Err(RuleError::UnboundMetavariable {
                    id: def.id.clone(),
                    field: field.to_string(),
                    var: var.clone(),
                });
            }
            Ok((pattern, vars))
        })
        .collect()
}

/// Validate and compile a rule's `exclude_if:` clause, if it declared one.
///
/// Exactly the same Python-only contract `flow:` enforces, for the same
/// reason: the predicate this clause tests only exists for
/// tree-sitter-python. Split out of [`CompiledRule::compile`] to keep that
/// function's length in check, the same way [`compile_patterns`] is.
fn compile_exclude_if(
    id: &str,
    language: RuleLanguage,
    exclude_if: Option<ExcludeIfDef>,
) -> Result<Option<CompiledExcludeIf>> {
    match exclude_if {
        None => Ok(None),
        Some(_) if language != RuleLanguage::Python => {
            Err(RuleError::ExcludeIfUnsupportedLanguage {
                id: id.to_string(),
                language: format!("{language:?}").to_lowercase(),
            })
        }
        Some(exclude) => {
            let kinds = exclude.kind.kinds();
            if kinds.is_empty() {
                return Err(RuleError::EmptyExcludeIfKinds { id: id.to_string() });
            }
            Ok(Some(CompiledExcludeIf {
                variable: exclude.variable,
                kinds,
            }))
        }
    }
}

fn compile_patterns<L: LanguageExt + Copy>(
    id: &str,
    grammar: &'static str,
    patterns: &[String],
    lang: L,
) -> Result<Vec<Pattern>> {
    patterns
        .iter()
        .map(|pattern| {
            Pattern::try_new(pattern, lang).map_err(|source| RuleError::InvalidPattern {
                id: id.to_string(),
                language: grammar.to_string(),
                pattern: pattern.clone(),
                source,
            })
        })
        .collect()
}

/// A loaded, compiled set of rules ready to scan source with.
///
/// One bucket per grammar (see this module's docs for why `typescript` and
/// `tsx` are separate buckets fed by the same `language: typescript` rules).
pub struct RuleSet {
    python: Vec<CompiledRule>,
    javascript: Vec<CompiledRule>,
    typescript: Vec<CompiledRule>,
    tsx: Vec<CompiledRule>,
    /// Distinct rule ids loaded. A `language: typescript` rule compiles into
    /// both the `typescript` and `tsx` buckets, but is one rule as far as
    /// anyone asking "how many rules are loaded" is concerned -- this is
    /// tracked separately rather than derived from summing bucket lengths so
    /// that fact stays true regardless of how many grammars a language ends
    /// up compiling against.
    rule_count: usize,
}

impl std::fmt::Debug for RuleSet {
    /// Lists loaded rule ids. The compiled matchers behind them do not
    /// implement `Debug`, so this cannot show more than that.
    ///
    /// `tsx` and `rule_count` are deliberately not shown:
    /// `tsx`'s ids are always exactly the `typescript` bucket's ids (see this
    /// module's docs), so listing it too would only print every TypeScript
    /// rule id twice; `rule_count` is just `ids.len()` restated.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids = self
            .python
            .iter()
            .chain(&self.javascript)
            .chain(&self.typescript)
            .map(|rule| &rule.id)
            .collect::<Vec<_>>();
        f.debug_struct("RuleSet")
            .field("rules", &ids)
            .finish_non_exhaustive()
    }
}

impl RuleSet {
    /// Load a rule set from YAML text.
    ///
    /// # Errors
    /// Returns [`RuleError`] if the YAML is malformed, uses an unknown field,
    /// repeats a rule id, declares a `kind: defect` rule against a
    /// context-dependent category, or contains a pattern or
    /// `metavariable_matches` regex that fails to compile against the
    /// grammar(s) its `language` implies.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        Self::from_yaml_sources(std::slice::from_ref(&yaml))
    }

    /// Load one rule set from several YAML documents, merged into one corpus.
    ///
    /// The built-in corpus is split across files by subject -- see
    /// [`Self::embedded`] -- so that rules on unrelated subjects can be
    /// authored without every author editing the same file. The split is
    /// organisational only: the merged corpus behaves exactly as if the
    /// documents had been concatenated, and an id repeated across *any* two
    /// of them is still a [`RuleError::DuplicateId`], not a silent
    /// last-one-wins.
    ///
    /// # Errors
    /// As [`Self::from_yaml`].
    pub fn from_yaml_sources(sources: &[&str]) -> Result<Self> {
        let mut defs = Vec::new();
        for source in sources {
            let file: RuleFile = serde_yaml_ng::from_str(source)?;
            defs.extend(file.rules);
        }

        let mut seen_ids = HashSet::with_capacity(defs.len());
        let mut python = Vec::new();
        let mut javascript = Vec::new();
        let mut typescript = Vec::new();
        let mut tsx = Vec::new();
        let mut rule_count = 0;

        for def in defs {
            if !seen_ids.insert(def.id.clone()) {
                return Err(RuleError::DuplicateId { id: def.id });
            }
            rule_count += 1;

            // Exhaustive on purpose: adding a `RuleLanguage` variant without
            // routing it to a bucket here is a compile error, not a rule
            // that silently never matches.
            match def.language {
                RuleLanguage::Python => python.push(CompiledRule::compile(def, "python", Python)?),
                RuleLanguage::Javascript => {
                    javascript.push(CompiledRule::compile(
                        def.clone(),
                        "javascript",
                        JavaScript,
                    )?);
                    typescript.push(CompiledRule::compile(
                        def.clone(),
                        "typescript",
                        TypeScript,
                    )?);
                    tsx.push(CompiledRule::compile(def, "tsx", Tsx)?);
                }
                RuleLanguage::Typescript => {
                    typescript.push(CompiledRule::compile(
                        def.clone(),
                        "typescript",
                        TypeScript,
                    )?);
                    tsx.push(CompiledRule::compile(def, "tsx", Tsx)?);
                }
            }
        }

        Ok(Self {
            python,
            javascript,
            typescript,
            tsx,
            rule_count,
        })
    }

    /// The rules built into the binary.
    ///
    /// # Errors
    /// Returns [`RuleError`] under the same conditions as [`Self::from_yaml`]
    /// — the embedded rule file is validated exactly like a user-supplied
    /// one.
    pub fn embedded() -> Result<Self> {
        Self::from_yaml_sources(&[
            include_str!("../../rules/bastyn.yml"),
            include_str!("../../rules/frameworks.yml"),
            include_str!("../../rules/secrets.yml"),
            include_str!("../../rules/config.yml"),
            include_str!("../../rules/memory.yml"),
            include_str!("../../rules/mcp_transport.yml"),
        ])
    }

    /// How many distinct rules are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rule_count
    }

    /// Whether no rules are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rule_count == 0
    }
}

/// What attempting to run every applicable rule over one file's source
/// produced.
///
/// A bare `Vec<Finding>` cannot say why it is empty: a clean file that
/// parsed fine and a file the parser could not make sense of both look
/// identical to a caller that only sees the findings. That distinction
/// matters to `scan::analyse`, which reports how much of the tree it
/// actually covered -- counting a file it never really analysed as
/// "scanned" would claim coverage the scan does not have. See
/// [`scan_source_checked`].
#[derive(Debug, Clone)]
pub enum ScanOutcome {
    /// The file's extension mapped to a known grammar, and the parsed tree
    /// contained no syntax error anywhere in it. Every applicable rule ran;
    /// the `Vec` can still be empty if none of them matched, which is a
    /// clean result, not a skipped one.
    Scanned(Vec<Finding>),
    /// Either the file's extension has no grammar this engine knows, or the
    /// grammar parsed the content into a tree tree-sitter itself flags as
    /// broken (a syntax-error node, or a node it inserted to recover from a
    /// missing token, anywhere in the tree) -- invalid syntax, a truncated
    /// file, or a file whose real format does not match its extension. No
    /// rule ran; the caller should count this file as skipped, not scanned.
    Unparseable,
}

/// Run every applicable rule in `ruleset` over one file's source, dispatching
/// on the file's extension to the grammar (and rule bucket) it implies.
///
/// The source is parsed exactly once and the tree is shared across every
/// rule in the matching bucket. Findings are deduplicated within this scan
/// and sorted by location.
///
/// Prefer this over [`scan_source`] whenever the caller reports scan
/// coverage (files scanned vs. skipped): `scan_source` collapses "parsed
/// clean, nothing matched" and "could not parse" into the same empty `Vec`,
/// which is exactly the ambiguity that let an unparseable file get counted
/// as scanned in `scan::analyse` before this function existed.
#[must_use]
pub fn scan_source_checked(ruleset: &RuleSet, relative_path: &Path, source: &str) -> ScanOutcome {
    match SourceLanguage::from_path(relative_path) {
        Some(SourceLanguage::Python) => scan_with(&ruleset.python, Python, relative_path, source),
        Some(SourceLanguage::Javascript) => {
            scan_with(&ruleset.javascript, JavaScript, relative_path, source)
        }
        Some(SourceLanguage::Typescript) => {
            scan_with(&ruleset.typescript, TypeScript, relative_path, source)
        }
        Some(SourceLanguage::Tsx) => scan_with(&ruleset.tsx, Tsx, relative_path, source),
        None => ScanOutcome::Unparseable,
    }
}

/// Run every applicable rule in `ruleset` over one file's source, discarding
/// the parsed-vs-unparseable distinction [`scan_source_checked`] makes.
///
/// Kept for callers that only want "what did the rules find" and do not
/// report scan coverage -- most of this crate's own rule tests, which only
/// ever assert on finding content. A file whose extension the engine has no
/// grammar for, and source the matching parser cannot handle, both produce
/// an empty `Vec` here; a caller that needs to tell those apart from a
/// clean scan must use [`scan_source_checked`] instead.
#[must_use]
pub fn scan_source(ruleset: &RuleSet, relative_path: &Path, source: &str) -> Vec<Finding> {
    match scan_source_checked(ruleset, relative_path, source) {
        ScanOutcome::Scanned(findings) => findings,
        ScanOutcome::Unparseable => Vec::new(),
    }
}

/// The actual matching loop, written once and shared by every grammar via
/// generics rather than copy-pasted per language. See this module's docs for
/// why that is possible: every type this function touches (`Pattern`,
/// `RegexMatcher`, `Any<Pattern>`, `Node::{find_all,matches,inside}`) is
/// already generic over the document type upstream, so `L` only has to be
/// named where a tree gets parsed.
fn scan_with<L: LanguageExt + Copy>(
    rules: &[CompiledRule],
    lang: L,
    relative_path: &Path,
    source: &str,
) -> ScanOutcome {
    let Ok(root) = AstGrep::<StrDoc<L>>::try_new(source, lang) else {
        return ScanOutcome::Unparseable;
    };
    let node = root.root();

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    // Tier 2 is built at most once per file, and only when a rule that needs
    // it has already found a structural candidate. A file with no `eval`,
    // `exec` or other flow-gated shape in it never pays for the graph at all.
    let mut graph: Option<FlowGraph> = None;

    // One walk, shared by the parse-error check and every rule -- see this
    // module's docs. Both jobs want the same pre-order sequence of nodes, and
    // `find_all` would start a fresh walk for each of them.
    for current in node.dfs() {
        // `try_new` only fails when tree-sitter cannot produce a tree at all
        // (cancellation, or no language set) -- it does not fail on invalid
        // syntax. Tree-sitter's error recovery instead parses garbage input
        // into a tree that *has* a root, just with an ERROR node (content it
        // could not fit into the grammar) or a MISSING node (a token it
        // inserted to recover from one it expected but never found)
        // somewhere in it. Walking is ast-grep-core's only way to reach the
        // raw tree-sitter node flags recursively -- the crate exposes
        // neither the underlying `tree_sitter::Tree` nor a
        // `has_error()`-equivalent on its own `Node`.
        //
        // Findings collected from nodes before this one are discarded with
        // the rest of the file, exactly as they were when this check ran as
        // its own pass ahead of the rules.
        if current.is_error() || current.is_missing() {
            return ScanOutcome::Unparseable;
        }

        let kind = usize::from(current.kind_id());
        for rule in rules {
            if !rule.can_match_kind(kind) {
                continue;
            }
            let Some(candidate) = rule.any.match_node(current.clone()) else {
                continue;
            };
            let matched = candidate.get_node();

            if rule.none.iter().any(|pattern| matched.matches(pattern)) {
                continue;
            }
            if !rule.inside.is_empty() && !rule.inside.iter().any(|pattern| matched.inside(pattern))
            {
                continue;
            }
            if !rule.metavariables_satisfied(candidate.get_env()) {
                continue;
            }
            if !rule.metavariable_exclusions_clear(candidate.get_env()) {
                continue;
            }
            let mut unproven = false;
            if let Some(flow) = &rule.flow {
                // Fails closed on a metavariable this pattern never bound,
                // the same way `metavariable_matches` does: no evidence, no
                // match.
                let Some(captured) = candidate.get_env().get_match(&flow.variable) else {
                    continue;
                };
                if flow.builtin_callee && shadow::bare_callee_is_shadowed(&node, matched) {
                    continue;
                }
                let graph =
                    graph.get_or_insert_with(|| FlowGraph::build(&node, FlowLanguage::Python));
                match flow.verdict(graph, captured.node_id()) {
                    FlowVerdict::Drop => continue,
                    FlowVerdict::Proven => {}
                    FlowVerdict::Unproven => {
                        if !flow
                            .unproven
                            .as_ref()
                            .is_some_and(|u| u.met(candidate.get_env()))
                        {
                            continue;
                        }
                        unproven = true;
                    }
                }
            }
            // Keyed on who can reach this call, not on whether the value's
            // origin is provable -- see `passthrough_observation_for`.
            let passthrough_observation = rule.flow.as_ref().is_some_and(|flow| {
                passthrough_observation_for(flow, candidate.get_env(), matched, &node, &mut graph)
            });
            if rule.excluded_by_file(&node, candidate.get_env())
                || !rule.satisfies_file_requirement(&node, candidate.get_env())
            {
                continue;
            }
            if let Some(exclude) = &rule.exclude_if
                && excluded_by_predicate(exclude, candidate.get_env(), &node, &mut graph)
            {
                continue;
            }

            let finding = build_finding(
                rule,
                relative_path,
                source,
                matched,
                unproven,
                passthrough_observation,
            );
            push_unique(&mut findings, &mut seen, finding);
        }
    }

    // The wrapper-sink pass is per rule and per *file*, not per node: it asks
    // whether this file defines a function that forwards into a catalogued
    // sink, which is a property of the whole tree. It therefore runs once
    // after the traversal above rather than inside it -- running it per node
    // would repeat the same whole-file analysis for every node in the file.
    for rule in rules {
        // A sink one call away is the same defect, and no `any:` pattern can
        // describe it: the call site names a local function, not `eval`. Only
        // a rule that asked for this with `flow.sink` gets it.
        //
        // `contains_sink_call` is the cost guard, and it is exact rather than
        // a heuristic: a wrapper is a function whose body calls a catalogued
        // sink, so a file with no such call cannot hold one. It answers with a
        // single tree walk instead of a whole dataflow analysis. Without it the
        // graph was built for every Python file in the repository whether or
        // not it could possibly contain a wrapper -- measured on the
        // 65-repository corpus, that alone cost +64% of scan time outside the
        // one outlier repository.
        if let Some(flow) = &rule.flow
            && let Some(sink) = flow.sink
            && mentions_sink_name(source, sink)
            && contains_sink_call(&node, sink)
        {
            let graph = graph.get_or_insert_with(|| FlowGraph::build(&node, FlowLanguage::Python));
            for (call, unproven) in wrapper_sink_calls(&node, graph, sink, flow) {
                // `flow.sink` and `flow.passthrough_downgrade` are mutually
                // exclusive -- rejected at load time by
                // `RuleError::PassthroughDowngradeWithSink` -- so a rule
                // reaching this path never has `passthrough_downgrade` set,
                // and the real check is never needed here.
                let finding = build_finding(rule, relative_path, source, &call, unproven, false);
                push_unique(&mut findings, &mut seen, finding);
            }
        }
    }

    // `findings` is now in node-then-rule order rather than rule-then-node
    // order, which changes nothing a caller can see: `seen` keys on
    // (rule id, location) and a rule still meets its own matches in
    // pre-order, so the same match of each pair survives; and
    // `merge_same_location` sorts on (location, rule id), which those keys
    // make a total order.
    ScanOutcome::Scanned(merge_same_location(findings))
}

/// Whether `flow.passthrough_downgrade` proves the pass-through-observation
/// shape at `matched`'s captured value, building the flow graph on
/// first use. Split out of [`scan_with`] to keep that function within
/// clippy's line-count lint, the same reason [`compile_flow`] is split out of
/// [`CompiledRule::compile`].
///
/// Computed independently of [`CompiledFlow::verdict`]: that method answers
/// whether a value's *origin* is provable, this answers whether the function
/// it was captured in is reachable from a recognized entry point, so it can
/// apply even to a value `verdict` already called [`FlowVerdict::Proven`] --
/// `Origin::Parameter` traces perfectly well, it just traces to a caller this
/// file does not see.
fn passthrough_observation_for<'r, D: Doc>(
    flow: &CompiledFlow,
    candidate_env: &MetaVarEnv<'r, D>,
    matched: &Node<'r, D>,
    node: &Node<'r, D>,
    graph: &mut Option<FlowGraph>,
) -> bool {
    if !flow.passthrough_downgrade && !flow.unreached_parameter_downgrade {
        return false;
    }
    let Some(captured) = candidate_env.get_match(&flow.variable) else {
        return false;
    };
    let graph = graph.get_or_insert_with(|| FlowGraph::build(node, FlowLanguage::Python));
    (flow.passthrough_downgrade && graph.is_passthrough_observation_eligible(matched, captured))
        || (flow.unreached_parameter_downgrade
            && graph.is_unreached_parameter_input(matched, captured))
}

/// Whether `exclude.kind` proves the value at `exclude.variable` safe,
/// building the flow graph on first use. Split out of [`scan_with`] for the
/// same line-count reason as [`passthrough_observation_for`].
fn excluded_by_predicate<'r, D: Doc>(
    exclude: &CompiledExcludeIf,
    candidate_env: &MetaVarEnv<'r, D>,
    node: &Node<'r, D>,
    graph: &mut Option<FlowGraph>,
) -> bool {
    let Some(captured) = candidate_env.get_match(&exclude.variable) else {
        return false;
    };
    let graph = graph.get_or_insert_with(|| FlowGraph::build(node, FlowLanguage::Python));
    exclude.kinds.iter().any(|kind| match kind {
        ExcludeIfKind::ClosedValue => graph.is_closed(captured.node_id()),
        ExcludeIfKind::ConstantPath => graph.is_constant_path(captured.node_id()),
        ExcludeIfKind::ShellQuoted => graph.is_shell_quoted(captured.node_id()),
        ExcludeIfKind::StdinDispatch => graph.is_stdin_dispatch(captured.node_id()),
        ExcludeIfKind::CliArgument => graph.is_cli_argument(captured.node_id()),
        ExcludeIfKind::NoCallerInput => !graph.has_caller_input(captured.node_id()),
    })
}

/// Whether the file's text contains, as a whole identifier, any name a
/// `sink`-kind API ends in.
///
/// A cost guard in front of the structural walk, and nothing else. No finding
/// is ever derived from it: everything it lets through is then matched
/// structurally, and everything it rejects provably had nothing to match. A
/// callee's name appears in the source as a whole identifier token, so a file
/// whose text contains no such token contains no such call.
///
/// It earns its place because the walk it guards visits every node of every
/// Python file scanned. The whole-identifier part is most of the value:
/// plain substring search matches `exec` inside `execute` and `compile`
/// inside `re.compile`, which on one 685-file corpus repository was 383 files
/// to walk rather than 44.
fn mentions_sink_name(source: &str, sink: SinkKind) -> bool {
    crate::flow::catalogue::sink_leaf_names(sink).any(|name| contains_identifier(source, name))
}

/// Whether `needle` occurs in `haystack` bounded by non-identifier characters
/// on both sides.
fn contains_identifier(haystack: &str, needle: &str) -> bool {
    let is_identifier_char = |c: char| c.is_alphanumeric() || c == '_';
    haystack.match_indices(needle).any(|(start, _)| {
        let before = haystack[..start].chars().next_back();
        let after = haystack[start + needle.len()..].chars().next();
        !before.is_some_and(is_identifier_char) && !after.is_some_and(is_identifier_char)
    })
}

/// Record `finding` unless one with the same dedupe key is already recorded.
fn push_unique(
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, std::path::PathBuf, usize, usize)>,
    finding: Finding,
) {
    let key = finding.dedupe_key();
    let dedupe_key = (key.0.to_string(), key.1.clone(), key.2, key.3);
    if seen.insert(dedupe_key) {
        findings.push(finding);
    }
}

/// Calls, in this file, to a local function that forwards the argument into a
/// `sink`-kind sink, where that argument satisfies `flow`. The paired `bool`
/// is whether the call is reported only on the unproven path -- see
/// [`FlowVerdict`].
///
/// This is the caller-side half of the depth-one wrapper relation
/// [`crate::flow::graph`] computes. Keyword arguments are deliberately not
/// matched to parameter positions: doing so needs the callee's full signature
/// including defaults, and a wrong position would report the wrong value.
fn wrapper_sink_calls<'r, D: Doc>(
    root: &Node<'r, D>,
    graph: &FlowGraph,
    sink: SinkKind,
    flow: &CompiledFlow,
) -> Vec<(Node<'r, D>, bool)> {
    let mut calls = Vec::new();
    for call in root.dfs().filter(|node| node.kind() == "call") {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let path = flow_graph_callee_path(&callee);
        let local = path.rsplit('.').next().unwrap_or(path.as_str());
        let parameters = graph.wrapper_sink_parameters(local, sink);
        if parameters.is_empty() {
            continue;
        }
        let Some(arguments) = call.field("arguments") else {
            continue;
        };
        let positional: Vec<Node<'r, D>> = arguments
            .named_children()
            .filter(|argument| argument.kind() != "keyword_argument")
            .collect();

        let verdict = parameters
            .iter()
            .filter_map(|index| positional.get(*index))
            .map(|argument| flow.verdict(graph, argument.node_id()))
            .max()
            .unwrap_or(FlowVerdict::Drop);
        match verdict {
            FlowVerdict::Proven => calls.push((call, false)),
            // No metavariable environment exists here to test `requires`
            // against, so only a clause without `requires` reports it.
            FlowVerdict::Unproven
                if flow
                    .unproven
                    .as_ref()
                    .is_some_and(|u| u.requires.is_empty()) =>
            {
                calls.push((call, true));
            }
            FlowVerdict::Unproven | FlowVerdict::Drop => {}
        }
    }
    calls
}

/// `unproven` is whether this match is reported through a `flow.unproven`
/// path rather than proven provenance: it downgrades the kind to
/// [`Kind::Observation`], the confidence to [`Confidence::Low`], and appends
/// [`UNPROVEN_NOTE`] to the description, regardless of the rule's own
/// declared kind and confidence. `passthrough_observation` is whether
/// `flow.passthrough_downgrade` proved the pass-through-helper shape at this
/// match; unlike `unproven`, it changes only `kind` -- `confidence` and
/// `description` are untouched, since the value's origin here is proven
/// (`Origin::Parameter`), just not reachable from a recognized entry point.
fn build_finding<D: Doc>(
    rule: &CompiledRule,
    relative_path: &Path,
    source: &str,
    matched: &Node<'_, D>,
    unproven: bool,
    passthrough_observation: bool,
) -> Finding {
    let start = matched.start_pos();
    let line = start.line() + 1;
    let column = start.column(matched) + 1;

    let snippet = source
        .lines()
        .nth(start.line())
        .unwrap_or_default()
        .trim()
        .to_string();

    // A credential invented so a test can reach a throwaway container is not
    // a credential. Measured on 65 real repositories, 23 of this rule set's
    // 32 hardcoded-credential findings were exactly that -- so a match in a
    // test path becomes an observation, out of the default report but still
    // there under --show-observations. Suppressing it outright would be
    // the one way to hide a genuinely leaked secret that happens to sit in a
    // fixture; a rule that cannot afford even that says `in_test_paths:
    // report`.
    let kind = if unproven
        || passthrough_observation
        || (rule.in_test_paths == TestPathPolicy::Downgrade && is_test_path(relative_path))
    {
        Kind::Observation
    } else {
        rule.kind
    };
    let confidence = if unproven {
        Confidence::Low
    } else {
        rule.confidence
    };
    let description = if unproven {
        format!("{} {UNPROVEN_NOTE}", rule.description.trim_end())
    } else {
        rule.description.clone()
    };

    Finding {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        kind,
        severity: rule.severity,
        confidence,
        categories: rule.categories.clone(),
        location: Location {
            file: relative_path.to_path_buf(),
            line,
            column,
        },
        snippet,
        description,
        remediation: rule.remediation.clone(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    }
}

/// Collapse findings that share a location into one, keeping the defect over
/// the observation, then the highest-severity, then highest-confidence, then
/// lowest rule id, as the primary and recording the rest in
/// `secondary_rule_ids`.
fn merge_same_location(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        a.location
            .cmp(&b.location)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let mut merged: Vec<Finding> = Vec::with_capacity(findings.len());
    for finding in findings {
        if let Some(last) = merged.last_mut()
            && last.location == finding.location
        {
            // Kind leads, and leads inverted (`Defect` sorts before
            // `Observation`, so the *smaller* kind wins): a test-path
            // downgrade on one rule must not demote another rule's defect at
            // the same location just because the observation happens to
            // carry a higher severity.
            let promote = (Reverse(finding.kind), finding.severity, finding.confidence)
                > (Reverse(last.kind), last.severity, last.confidence);
            if promote {
                let mut promoted = finding;
                promoted.secondary_rule_ids = std::mem::take(&mut last.secondary_rule_ids);
                promoted.secondary_rule_ids.push(last.rule_id.clone());
                *last = promoted;
            } else {
                last.secondary_rule_ids.push(finding.rule_id);
            }
            last.secondary_rule_ids.sort_unstable();
            last.secondary_rule_ids.dedup();
            continue;
        }
        merged.push(finding);
    }
    merged
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assumption in a test should fail the test"
)]
mod traversal_tests {
    //! What the one-walk-per-file traversal has to keep true.
    //!
    //! [`scan_with`] folds the parse-error check into the same walk that runs
    //! the rules, so both of the things that used to be guaranteed by
    //! *ordering* between two separate passes now have to be guaranteed
    //! inside one: an error late in a file must still suppress a rule match
    //! early in it, and two rules meeting the same node must still merge the
    //! same way now that they meet it back to back rather than a whole tree
    //! apart.

    use super::*;

    fn ruleset(rules: &str) -> RuleSet {
        RuleSet::from_yaml(rules).unwrap()
    }

    const EVAL_RULE: &str = r"
rules:
  - id: BAS-TEST-001
    title: eval on untrusted input
    kind: defect
    severity: high
    confidence: high
    categories: [LLM01]
    language: python
    any:
      - eval($ARG)
    description: test rule
    remediation: test remediation
";

    /// The error check used to be a whole pass that finished before any rule
    /// ran, so a syntax error anywhere in a file suppressed every match in
    /// it. Fused into the rule walk, that only stays true if a match found
    /// before the error node is thrown away with the file rather than
    /// returned.
    #[test]
    fn a_match_before_a_later_syntax_error_is_still_discarded() {
        let rules = ruleset(EVAL_RULE);

        let clean = scan_source_checked(&rules, Path::new("a.py"), "eval(payload)\n");
        let ScanOutcome::Scanned(findings) = clean else {
            panic!("valid Python must scan: {clean:?}");
        };
        assert_eq!(findings.len(), 1, "{findings:#?}");

        // Same match, on the same first line, followed by content the Python
        // grammar cannot fit.
        let broken = scan_source_checked(
            &rules,
            Path::new("a.py"),
            "eval(payload)\ndef(:::: not python at all @#$%^&*(\n",
        );
        assert!(
            matches!(broken, ScanOutcome::Unparseable),
            "a syntax error after a match must still make the file unparseable: {broken:?}"
        );
    }

    /// Two rules that match the same node used to be a whole tree-walk
    /// apart; they now meet it one after the other. The merge that picks a
    /// primary and records the rest in `secondary_rule_ids` must not depend
    /// on which of those it was.
    #[test]
    fn two_rules_on_one_node_merge_into_one_finding() {
        // Declared low-severity-first, so the promotion path in
        // `merge_same_location` runs rather than the append path.
        let rules = ruleset(
            r"
rules:
  - id: BAS-TEST-001
    title: quiet
    kind: defect
    severity: low
    confidence: low
    categories: [LLM01]
    language: python
    any:
      - eval($ARG)
    description: test rule
    remediation: test remediation
  - id: BAS-TEST-002
    title: loud
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM01]
    language: python
    any:
      - eval($ARG)
    description: test rule
    remediation: test remediation
",
        );

        let outcome = scan_source_checked(&rules, Path::new("a.py"), "eval(payload)\n");
        let ScanOutcome::Scanned(findings) = outcome else {
            panic!("valid Python must scan: {outcome:?}");
        };

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-TEST-002");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].secondary_rule_ids, ["BAS-TEST-001"]);
    }

    /// A rule whose `any` patterns all pin one node kind is skipped on every
    /// other kind by [`CompiledRule::can_match_kind`], which stands in for
    /// the filter [`Node::find_all`] used to apply. A rule that could match
    /// any kind has to keep being offered every node.
    #[test]
    fn the_kind_filter_never_hides_a_rule_that_could_match_any_kind() {
        // A bare metavariable binds whatever node it lands on, so
        // `potential_kinds` cannot narrow it and `any_kinds` must be `None`.
        let rules = ruleset(
            r"
rules:
  - id: BAS-TEST-003
    title: anything
    kind: defect
    severity: low
    confidence: low
    categories: [LLM01]
    language: python
    any:
      - $ANY
    description: test rule
    remediation: test remediation
",
        );
        assert!(
            rules.python[0].any_kinds.is_none(),
            "a bare metavariable must not be narrowed to a kind set"
        );
        assert!(
            rules.python[0].can_match_kind(0) && rules.python[0].can_match_kind(usize::MAX),
            "an unnarrowed rule must be offered every node kind"
        );

        // And the narrowed case: `eval($ARG)` is a call, so most kinds are
        // rejected without ever building a `MetaVarEnv`.
        let narrowed = ruleset(EVAL_RULE);
        let kinds = narrowed.python[0]
            .any_kinds
            .as_ref()
            .expect("a concrete call pattern must narrow to a kind set");
        assert_eq!(
            kinds.iter().filter(|matched| **matched).count(),
            1,
            "eval($ARG) matches exactly one node kind"
        );
    }
}
