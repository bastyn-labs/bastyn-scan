//! Errors that can occur while loading or compiling a rule set.
//!
//! Kept local to this module rather than folded into [`crate::error::Error`]:
//! that type belongs to the traversal layer and this crate's contract forbids
//! changing it, so rule loading gets its own narrow error type instead.

use ast_grep_core::matcher::{PatternError, RegexMatcherError};

/// A specialised [`std::result::Result`] for rule loading and compilation.
pub type Result<T, E = RuleError> = std::result::Result<T, E>;

/// Anything that can go wrong while parsing or compiling rule YAML.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuleError {
    /// The YAML text could not be parsed, or used a field the schema does not
    /// define.
    #[error("malformed rule YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    /// A rule declared an `any` list with no patterns in it.
    #[error("rule `{id}`: `any` must contain at least one pattern")]
    EmptyAny {
        /// The offending rule's id.
        id: String,
    },

    /// A rule declared both `flow.sink` and `requires_in_file`.
    ///
    /// The wrapper-sink pass `flow.sink` turns on builds its findings
    /// directly from `wrapper_sink_calls`, never through
    /// `CompiledRule::satisfies_file_requirement`, so a `requires_in_file`
    /// condition on such a rule would be silently skipped for every finding
    /// the wrapper pass reports -- a load error rather than a check that
    /// quietly does nothing for half of what the rule can report.
    #[error(
        "rule `{id}`: `flow.sink` and `requires_in_file` cannot be combined; the wrapper-sink \
         pass `flow.sink` enables does not consult `requires_in_file`"
    )]
    FlowSinkWithRequiresInFile {
        /// The offending rule's id.
        id: String,
    },

    /// A rule declared a `categories` list with no categories in it.
    #[error("rule `{id}`: `categories` must contain at least one category")]
    EmptyCategories {
        /// The offending rule's id.
        id: String,
    },

    /// Two rules in the same set declared the same id.
    #[error("rule `{id}`: duplicate rule id")]
    DuplicateId {
        /// The id shared by two rules.
        id: String,
    },

    /// A `kind: defect` rule mapped to a category whose absence cannot be
    /// judged from the repository alone. Only observations may carry those.
    #[error(
        "rule `{id}`: kind is `defect` but category `{category}` is context-dependent; \
         context-dependent categories may only be observations"
    )]
    ContextDependentDefect {
        /// The offending rule's id.
        id: String,
        /// The context-dependent category that triggered the rejection.
        category: String,
    },

    /// One of a rule's `any`, `none`, or `inside` patterns failed to compile
    /// against the grammar its language implies.
    ///
    /// `language` names the grammar the pattern was compiled against, not
    /// just the schema-level `RuleLanguage`: a `language: typescript` rule
    /// compiles separately against the TypeScript and Tsx grammars (see
    /// `crate::rules::engine`'s module docs), and the two can disagree --
    /// TypeScript's angle-bracket cast syntax (`<Foo>bar`), for example, does
    /// not parse under the Tsx grammar at all. Naming the grammar, not just
    /// the rule id, tells the author which of the two compiles actually
    /// failed.
    #[error("rule `{id}`: invalid {language} pattern `{pattern}`: {source}")]
    InvalidPattern {
        /// The offending rule's id.
        id: String,
        /// The grammar the pattern was compiled against (e.g. `"python"`,
        /// `"typescript"`, `"tsx"`, `"javascript"`).
        language: String,
        /// The pattern text that failed to compile.
        pattern: String,
        /// The underlying pattern-compilation failure.
        #[source]
        source: PatternError,
    },

    /// A `metavariable_matches` regular expression failed to compile.
    #[error("rule `{id}`: invalid metavariable_matches regex for `{var}`: {source}")]
    InvalidRegex {
        /// The offending rule's id.
        id: String,
        /// The metavariable name the regex was attached to.
        var: String,
        /// The underlying regex-compilation failure.
        #[source]
        source: RegexMatcherError,
    },

    /// A rule declared a `flow:` clause in a language the dataflow graph
    /// cannot be built for.
    ///
    /// A load error rather than a rule that silently never matches: the
    /// graph is Python-only today (see the crate-internal `flow` module), and a `flow:`
    /// clause compiled against any other grammar would be a matcher that can
    /// never fire, with nothing in the report to say so.
    #[error(
        "rule `{id}`: `flow` is only supported for `language: python`, not `{language}`; \
         the dataflow graph has no other grammar"
    )]
    FlowUnsupportedLanguage {
        /// The offending rule's id.
        id: String,
        /// The language the rule declared.
        language: String,
    },

    /// A rule declared an `exclude_if:` clause in a language the dataflow
    /// graph cannot be built for.
    ///
    /// A load error rather than a rule that silently never excludes: the
    /// graph is Python-only today (see the crate-internal `flow` module), and an `exclude_if:`
    /// clause compiled against any other grammar would be a matcher that can
    /// never fire, with nothing in the report to say so.
    #[error(
        "rule `{id}`: `exclude_if` is only supported for `language: python`, not `{language}`; \
         the dataflow graph has no other grammar"
    )]
    ExcludeIfUnsupportedLanguage {
        /// The offending rule's id.
        id: String,
        /// The language the rule declared.
        language: String,
    },

    /// A rule declared a `flow:` clause with no source kinds in it.
    ///
    /// Such a rule can never match, because no origin satisfies an empty set.
    #[error("rule `{id}`: `flow.source` must name at least one source kind")]
    EmptyFlowSources {
        /// The offending rule's id.
        id: String,
    },

    /// A rule declared an `exclude_if:` clause with no kinds in it.
    ///
    /// Such a clause would silently compile into a no-op exclusion --
    /// `kinds.iter().any(...)` over an empty list is always `false`, so
    /// nothing would ever be excluded, with nothing in the report to say
    /// so. Rejecting it at load time is the same contract `flow.source`
    /// already keeps via `EmptyFlowSources`.
    #[error("rule `{id}`: `exclude_if.kind` must name at least one kind")]
    EmptyExcludeIfKinds {
        /// The offending rule's id.
        id: String,
    },

    /// A `metavariable_not_matches` regular expression failed to compile.
    ///
    /// Kept distinct from [`Self::InvalidRegex`] rather than sharing one
    /// variant: the two fields are opposite gates (must match / must not
    /// match), and a rule author staring at a compile error benefits from
    /// the message naming which one they got wrong.
    #[error("rule `{id}`: invalid metavariable_not_matches regex for `{var}`: {source}")]
    InvalidNotRegex {
        /// The offending rule's id.
        id: String,
        /// The metavariable name the regex was attached to.
        var: String,
        /// The underlying regex-compilation failure.
        #[source]
        source: RegexMatcherError,
    },

    /// A field names a metavariable that none of the rule's `any` patterns
    /// binds, so it could never be tested.
    #[error("rule `{id}`: `{field}` names `${var}`, which no `any` pattern binds")]
    UnboundMetavariable {
        /// The offending rule's id.
        id: String,
        /// The field that named the unbound metavariable.
        field: String,
        /// The metavariable name that no `any` pattern binds.
        var: String,
    },

    /// A `flow.unproven.requires` regular expression failed to compile.
    #[error("rule `{id}`: invalid flow.unproven.requires regex for `{var}`: {source}")]
    InvalidUnprovenRegex {
        /// The offending rule's id.
        id: String,
        /// The metavariable name the regex was attached to.
        var: String,
        /// The underlying regex-compilation failure.
        #[source]
        source: RegexMatcherError,
    },

    /// A rule declared both `flow.sink` and `none_in_file`.
    ///
    /// The wrapper-sink pass `flow.sink` turns on (`rules::engine::scan_with`)
    /// builds its findings directly from `wrapper_sink_calls`, never through
    /// `CompiledRule::excluded_by_file`, so a `none_in_file` exclusion on such
    /// a rule would be silently skipped for every finding the wrapper pass
    /// reports -- a load error rather than a check that quietly does nothing
    /// for half of what the rule can report.
    #[error(
        "rule `{id}`: `flow.sink` and `none_in_file` cannot be combined; the wrapper-sink pass \
         `flow.sink` enables does not consult `none_in_file`"
    )]
    FlowSinkWithNoneInFile {
        /// The offending rule's id.
        id: String,
    },

    /// A rule declared `flow.unproven` with no `flow.source` at all.
    ///
    /// `unproven:` only means something when a `source:` list exists for a
    /// value's origin to fail against. With no `source:`, the flow clause
    /// treats every value that clears the closed/guard checks as `Proven`
    /// outright -- there is no untraceable path left for `unproven:` to
    /// redirect, so the combination is a load error rather than a field that
    /// silently has no effect.
    #[error(
        "rule `{id}`: `flow.unproven` has no effect without `flow.source`; add a `flow.source` \
         list or remove `flow.unproven`"
    )]
    UnprovenWithoutSource {
        /// The offending rule's id.
        id: String,
    },

    /// A rule declared `flow.sink` with no `flow.source` at all.
    ///
    /// The wrapper-sink pass `flow.sink` turns on reports every call to a
    /// local function forwarding the captured value into a sink of that
    /// kind, wherever the flow clause's own verdict is `Proven` for that
    /// value. With a `source:` list, that is bounded to
    /// values traced to one of the listed kinds. With no `source:` at all,
    /// it would be every value that is merely not closed and (with
    /// `unguarded: true`) not guarded -- a materially broader, currently
    /// unexercised reach no shipped rule asks for. Rejected here rather than
    /// shipped as an untested, unbounded capability; lifting this
    /// restriction later is a deliberate choice for whoever needs it, not a
    /// silent default.
    #[error(
        "rule `{id}`: `flow.sink` requires `flow.source`; a sourceless `flow.sink` would report \
         every wrapper call whose argument is merely not closed and not guarded, which no rule \
         exercises today"
    )]
    FlowSinkWithoutSource {
        /// The offending rule's id.
        id: String,
    },

    /// A rule declared both `flow.sink` and `flow.passthrough_downgrade`.
    ///
    /// The wrapper-sink pass (`flow.sink`) builds its own findings straight
    /// from `wrapper_sink_calls`, bypassing the per-node match loop that
    /// `passthrough_downgrade` is computed in -- the combination is rejected
    /// here rather than shipped silently half-working, the same reasoning
    /// `FlowSinkWithNoneInFile` already applies to `none_in_file`.
    #[error(
        "rule `{id}`: `flow.sink` and `flow.passthrough_downgrade` cannot be combined; the \
         wrapper-sink pass `flow.sink` enables builds its findings outside the per-node match \
         loop `passthrough_downgrade` is computed in"
    )]
    PassthroughDowngradeWithSink {
        /// The offending rule's id.
        id: String,
    },

    /// A rule declared both `flow.sink` and `flow.unreached_parameter_downgrade`.
    ///
    /// Rejected for the same reason as [`Self::PassthroughDowngradeWithSink`]:
    /// the wrapper-sink pass builds its findings outside the per-node match
    /// loop the downgrade is computed in.
    #[error(
        "rule `{id}`: `flow.sink` and `flow.unreached_parameter_downgrade` cannot be combined; \
         the wrapper-sink pass `flow.sink` enables builds its findings outside the per-node \
         match loop `unreached_parameter_downgrade` is computed in"
    )]
    UnreachedParameterDowngradeWithSink {
        /// The offending rule's id.
        id: String,
    },
}
