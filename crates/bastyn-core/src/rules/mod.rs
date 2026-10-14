//! The rule engine: loads YAML rule definitions, matches them against
//! Python, TypeScript, and JavaScript source with `ast-grep`, and produces
//! [`crate::finding::Finding`] values. See the `engine` module's own docs for how
//! one rule set stays correct across several grammars at once.
//!
//! The rule schema is fixed: a rule is a set of `any` patterns to match, an
//! optional `none` list that suppresses a match on the same node, an optional
//! `inside` list that requires the match be nested in a particular shape, and
//! an optional `metavariable_matches` map of captured-variable name to a regex
//! its text must satisfy, and its inverse, `metavariable_not_matches`
//! (a captured variable's text must *not* match). Those two fields are the
//! precision lever the "say less, be right" principle depends on:
//! `eval($ARG)` alone is noise, but `eval($ARG)` with `ARG` constrained to
//! look like a model response is not -- and `metavariable_not_matches`
//! exists because `metavariable_matches` alone cannot also reject a known
//! placeholder shape (`user:password@localhost`) without a regex engine that
//! supports lookaround, which this one does not.
//!
//! A rule may also carry a `flow:` clause, which gates the match on where a
//! captured value *came from* rather than on what it is called:
//!
//! ```yaml
//! flow:
//!   source: model_output   # $ARG must originate from a model-output API
//!   unguarded: true        # and no guard may dominate this sink
//! ```
//!
//! That is a different question from `metavariable_matches`, and a better
//! one. A name gate on `eval($ARG)` survives 0 of 119 realistic renamings of
//! the same bug (`tests/brittleness_gate.rs`) because the name is a guess
//! about intent; provenance is a fact about the program, and renaming a
//! variable does not change it. The two clauses coexist so rules migrate one
//! at a time, and when both are present both apply. See the crate-internal
//! `flow` module for what the graph can and cannot prove, and for why a
//! `flow:` clause outside `language: python` is a load error rather than a
//! rule that quietly never matches.
//!
//! Loading enforces one product rule beyond what the schema alone can check:
//! a `kind: defect` rule may never map to a context-dependent category (see
//! [`crate::category::Category::is_context_dependent`]), because a missing
//! control is never a defect on its own.

mod engine;
mod error;
mod schema;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_exclude_if;
#[cfg(test)]
mod tests_flow;

#[cfg(test)]
mod tests_frameworks;

#[cfg(test)]
mod tests_memory;

#[cfg(test)]
mod tests_secrets;

#[cfg(test)]
mod tests_supply_chain;

pub(crate) use engine::SourceLanguage;
pub use engine::{RuleSet, ScanOutcome, scan_source, scan_source_checked};
pub use error::{Result, RuleError};
