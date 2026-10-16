//! Guard dominance: has this value already been checked?
//!
//! A guard *dominates* a sink when every path that reaches the sink has
//! passed through it. `none:` cannot express this and neither can `inside:`:
//! the first matches alternate shapes of the sink's own node, the second only
//! reaches its ancestors, and the proof that a value is safe usually lives in
//! a *sibling* statement -- the assignment above it, or the `if`/`raise` one
//! line up. Those are the two shapes recorded as unfixable
//! `[[known_false_positive]]` entries in `tests/corpus/expected.toml`, and
//! they are exactly the two this module recognises:
//!
//! ```python
//! class_name = self.__class__.__name__   # a closed set the file itself fixes
//! row = eval(class_name)
//!
//! if torch_dtype not in ("float16", "bfloat16", "float32"):
//!     raise ValueError(torch_dtype)
//! model = eval(f"torch.{torch_dtype}")   # guarded one line above
//! ```
//!
//! # Deliberately narrow
//!
//! A false "guarded" verdict silently suppresses a real vulnerability, which
//! is strictly worse than the false positive it removes. So the recognised
//! forms are few and each requires proof:
//!
//! - **A closed value.** Every name the sink expression depends on resolves,
//!   through the def-use chain, to a value drawn from a set this file fixes.
//! - **A negative membership check that does not fall through.**
//!   `if name not in <fixed set>:` whose body raises, returns, breaks,
//!   continues or exits. Reaching the sink then proves membership.
//! - **A positive membership check whose branch contains the sink.**
//!   `if name in <fixed set>:` with the sink inside the consequence.
//!
//! - **A calculator-only character class.** The value was filtered or
//!   fully matched so that it can contain only digits, whitespace,
//!   parentheses and the operators `+ - * / % .`. Such a value has no name,
//!   attribute access or call in it. See the `calculator` section below.
//!
//! The set must be *fixed* -- a tuple, list or set of literals, or a name
//! bound to one. `if x not in registry.known()` proves nothing this module
//! can check, so it does not count.
//!
//! `assert x in (...)` is deliberately **not** a guard: `python -O` removes
//! it, so it is a comment with syntax, not a check.
//!
//! Everything else answers "not guarded", which reports the finding. That is
//! the safe direction.

use std::collections::HashSet;

use ast_grep_core::{Doc, Node};

use super::graph::{FlowGraph, SCOPE_KINDS};

/// Statement kinds that stop execution falling through to the code after an
/// `if`. Without one of these in its body, a check proves nothing: the sink is
/// reached either way.
const TERMINATING_STATEMENTS: &[&str] = &[
    "raise_statement",
    "return_statement",
    "continue_statement",
    "break_statement",
];

/// Calls that end the process, and so terminate a branch as surely as a
/// `raise` does.
const EXITING_CALLS: &[&str] = &["sys.exit", "exit", "os._exit", "quit"];

/// Whether a guard dominates the call argument at `sink_node`.
pub(crate) fn is_guarded(graph: &FlowGraph, sink_node: usize) -> bool {
    graph.guard_dominates(sink_node)
}

/// Every call argument, and every f-string interpolation, in the file that a
/// guard dominates.
///
/// Those are the only two positions a `flow:` rule's captured metavariable
/// can sit in: a sink call's argument (`eval($ARG)`, `$CUR.execute($ARG)`),
/// or the `{...}` slot of an f-string a rule matches piecewise
/// (`f"$$$A{$VAR}$$$B"`, as `BAS-ZT4-001`/`-002` do). The latter needs its
/// own case rather than falling out of the `argument_list` walk: the
/// captured node there is the interpolation's own expression, not the whole
/// f-string -- the same node `super::graph`'s string-resolution case reads
/// the value from -- so guard dominance has to be checked against that same
/// node. Computing this for every expression node in the file would cost far
/// more than it could ever be asked about, so the walk stays limited to
/// these two positions.
pub(crate) fn collect_guarded<D: Doc>(root: &Node<'_, D>, graph: &FlowGraph) -> HashSet<usize> {
    let mut guarded = HashSet::new();
    for node in root.dfs() {
        match node.kind().as_ref() {
            "argument_list" => {
                for argument in node.named_children() {
                    if argument_is_guarded(&argument, graph) {
                        guarded.insert(argument.node_id());
                    }
                }
            }
            "interpolation" => {
                if let Some(expression) = node.named_children().next()
                    && argument_is_guarded(&expression, graph)
                {
                    guarded.insert(expression.node_id());
                }
            }
            _ => {}
        }
    }
    guarded
}

fn argument_is_guarded<D: Doc>(argument: &Node<'_, D>, graph: &FlowGraph) -> bool {
    if graph.is_closed(argument.node_id()) {
        return true;
    }
    let dependencies = dependency_names(argument);
    if dependencies.is_empty() {
        // Nothing to check means nothing was checked. `eval(fetch_code())`
        // depends on no name a guard could ever name.
        return false;
    }
    let proven = dominating_guards(argument, graph);
    dependencies.iter().all(|name| proven.contains(name))
}

/// The names whose values this expression carries.
///
/// An identifier in an attribute-name, callee or keyword-name position names
/// an API or a field, not a value, so it is not something a guard could check.
fn dependency_names<D: Doc>(expression: &Node<'_, D>) -> HashSet<String> {
    let mut names = HashSet::new();
    for node in expression.dfs() {
        if node.kind() != "identifier" {
            continue;
        }
        let is_naming_position = node.parent().is_some_and(|parent| {
            let field = match parent.kind().as_ref() {
                "attribute" => "attribute",
                "call" => "function",
                "keyword_argument" => "name",
                _ => return false,
            };
            parent
                .field(field)
                .is_some_and(|named| named.node_id() == node.node_id())
        });
        if !is_naming_position {
            names.insert(node.text().into_owned());
        }
    }
    names
}

/// The names proven to be members of a fixed set on every path reaching
/// `sink`.
///
/// Walks outwards from the sink, collecting checks from the statements that
/// precede it in each enclosing block and from each enclosing `if` whose
/// consequence contains it. Stops at the enclosing function: a check in a
/// caller is not visible here, and pretending otherwise is exactly the false
/// "guarded" verdict this module refuses to give.
fn dominating_guards<D: Doc>(sink: &Node<'_, D>, graph: &FlowGraph) -> HashSet<String> {
    let mut proven = HashSet::new();
    let mut calculator = Vec::new();
    let mut current = sink.clone();
    let mut scope = sink.clone();

    while let Some(parent) = current.parent() {
        match parent.kind().as_ref() {
            "block" | "module" => {
                for statement in parent.children() {
                    if statement.node_id() == current.node_id() {
                        break;
                    }
                    collect_terminating_check(&statement, graph, &mut proven);
                    calculator::collect_statement(&statement, &mut calculator);
                }
            }
            "if_statement" | "elif_clause" => {
                if parent
                    .field("consequence")
                    .is_some_and(|block| block.node_id() == current.node_id())
                    && let Some(condition) = parent.field("condition")
                {
                    collect_membership(&condition, graph, false, &mut proven);
                    calculator::collect_condition(
                        &condition,
                        true,
                        condition.range().end,
                        &mut calculator,
                    );
                }
            }
            _ => {}
        }
        scope = parent.clone();
        if SCOPE_KINDS.contains(&parent.kind().as_ref()) {
            break;
        }
        current = parent;
    }
    proven.extend(calculator::surviving_names(&scope, calculator));
    proven
}

/// Read `if name not in <fixed set>: raise ...` as a proof that, past this
/// statement, `name` is in the set.
fn collect_terminating_check<D: Doc>(
    statement: &Node<'_, D>,
    graph: &FlowGraph,
    proven: &mut HashSet<String>,
) {
    if statement.kind() != "if_statement" {
        return;
    }
    let (Some(condition), Some(consequence)) =
        (statement.field("condition"), statement.field("consequence"))
    else {
        return;
    };
    if !block_terminates(&consequence) {
        return;
    }
    collect_membership(&condition, graph, true, proven);
}

/// Whether a block always stops execution falling out of its bottom.
fn block_terminates<D: Doc>(block: &Node<'_, D>) -> bool {
    block.children().any(|statement| {
        if TERMINATING_STATEMENTS.contains(&statement.kind().as_ref()) {
            return true;
        }
        statement.kind() == "expression_statement"
            && statement.named_children().any(|expression| {
                expression.kind() == "call"
                    && expression.field("function").is_some_and(|callee| {
                        EXITING_CALLS.contains(&super::graph::callee_path(&callee).as_str())
                    })
            })
    })
}

/// Record `name` when `condition` is exactly `name in <fixed set>` (or its
/// negation, when `negated`).
fn collect_membership<D: Doc>(
    condition: &Node<'_, D>,
    graph: &FlowGraph,
    negated: bool,
    proven: &mut HashSet<String>,
) {
    if condition.kind() != "comparison_operator" {
        return;
    }
    let parts: Vec<Node<'_, D>> = condition.children().collect();
    let [left, operator, right] = parts.as_slice() else {
        return;
    };
    let wanted = if negated { "not in" } else { "in" };
    if operator.kind() != wanted || left.kind() != "identifier" {
        return;
    }
    if !graph.is_closed(right.node_id()) {
        return;
    }
    proven.insert(left.text().into_owned());
}

/// Calculator-only character classes.
///
/// A value that can contain only digits, whitespace, parentheses and the
/// operators `+ - * / % .` has no identifier, attribute access, call or
/// string in it, so `eval` on it cannot run arbitrary code. Three checks
/// prove that, and each is read strictly:
///
/// - `re.fullmatch(P, name)` (or `re.match`/`re.search` with a closing `$` or
///   `\Z`, and for `re.search` a leading `^` as well) where `P` is a single
///   non-negated character class with an optional `+`/`*`, tested in an `if`
///   that terminates or whose branch holds the sink.
/// - `name = re.sub(P, "", value)` where `P` is a single negated class: the
///   assignment removes everything outside the class. Only the three-argument
///   form counts, so a replacement count cannot leave characters behind.
/// - `name.isdigit()` / `name.isdecimal()`, and
///   `all(c in "<chars>" for c in name)`.
///
/// Every character the class or the string admits must be in the allowed
/// set; a letter, an underscore, a quote or a bracket other than a
/// parenthesis disqualifies it. A proof lapses when the name is assigned
/// again after the check, anywhere in the same function.
mod calculator {
    use std::collections::HashSet;

    use ast_grep_core::{Doc, Node};

    use crate::flow::graph::callee_path;

    /// A name proven calculator-only from byte offset `from` onwards.
    pub(super) struct Proof {
        name: String,
        from: usize,
    }

    /// Characters a calculator-only value may contain, besides digits and
    /// whitespace.
    const OPERATORS: &str = "+-*/%.()";

    fn is_allowed(c: char) -> bool {
        c.is_ascii_digit() || matches!(c, ' ' | '\t' | '\n' | '\r') || OPERATORS.contains(c)
    }

    /// Proofs a statement in a preceding position establishes.
    pub(super) fn collect_statement<D: Doc>(statement: &Node<'_, D>, out: &mut Vec<Proof>) {
        match statement.kind().as_ref() {
            "if_statement" => {
                let (Some(condition), Some(consequence)) =
                    (statement.field("condition"), statement.field("consequence"))
                else {
                    return;
                };
                if super::block_terminates(&consequence) {
                    collect_condition(&condition, false, statement.range().end, out);
                }
            }
            "expression_statement" => {
                for assignment in statement.named_children() {
                    if assignment.kind() != "assignment" {
                        continue;
                    }
                    let (Some(left), Some(right)) =
                        (assignment.field("left"), assignment.field("right"))
                    else {
                        continue;
                    };
                    if left.kind() == "identifier" && is_filter(&right) {
                        out.push(Proof {
                            name: left.text().into_owned(),
                            from: statement.range().end,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    /// Record the names `condition` proves calculator-only, given that it is
    /// known to be `holds` (true or false).
    pub(super) fn collect_condition<D: Doc>(
        condition: &Node<'_, D>,
        holds: bool,
        from: usize,
        out: &mut Vec<Proof>,
    ) {
        match condition.kind().as_ref() {
            "parenthesized_expression" => {
                if let Some(inner) = condition.named_children().next() {
                    collect_condition(&inner, holds, from, out);
                }
            }
            "not_operator" => {
                if let Some(argument) = condition.field("argument") {
                    collect_condition(&argument, !holds, from, out);
                }
            }
            "boolean_operator" => {
                let operator = condition.field("operator").map(|o| o.kind().into_owned());
                let wanted = if holds { "and" } else { "or" };
                if operator.as_deref() == Some(wanted) {
                    for side in ["left", "right"] {
                        if let Some(part) = condition.field(side) {
                            collect_condition(&part, holds, from, out);
                        }
                    }
                }
            }
            "comparison_operator" => {
                // `<call> is None` holds exactly when the call fails.
                let parts: Vec<Node<'_, D>> = condition.children().collect();
                let [left, operator, right] = parts.as_slice() else {
                    return;
                };
                if right.kind() == "none" && operator.kind() == "is" {
                    collect_condition(left, !holds, from, out);
                } else if right.kind() == "none" && operator.kind() == "is not" {
                    collect_condition(left, holds, from, out);
                }
            }
            "call" if holds => {
                if let Some(name) = checked_name(condition) {
                    out.push(Proof { name, from });
                }
            }
            _ => {}
        }
    }

    /// The names whose proofs have not been overwritten since the check.
    pub(super) fn surviving_names<D: Doc>(
        scope: &Node<'_, D>,
        proofs: Vec<Proof>,
    ) -> HashSet<String> {
        proofs
            .into_iter()
            .filter(|proof| !reassigned_after(scope, &proof.name, proof.from))
            .map(|proof| proof.name)
            .collect()
    }

    fn reassigned_after<D: Doc>(scope: &Node<'_, D>, name: &str, from: usize) -> bool {
        scope.dfs().any(|node| {
            let target = match node.kind().as_ref() {
                "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
                    node.field("left")
                }
                "named_expression" => node.field("name"),
                _ => None,
            };
            target.is_some_and(|target| {
                node.range().start >= from
                    && target
                        .dfs()
                        .any(|part| part.kind() == "identifier" && part.text() == name)
            })
        })
    }

    /// The name a call proves calculator-only when it holds.
    fn checked_name<D: Doc>(call: &Node<'_, D>) -> Option<String> {
        let callee = call.field("function")?;
        let argument_node = call.field("arguments")?;
        // A lone generator argument is the `arguments` node itself.
        let arguments: Vec<Node<'_, D>> = if argument_node.kind() == "generator_expression" {
            vec![argument_node]
        } else {
            argument_node.named_children().collect()
        };
        let path = callee_path(&callee);
        match path.as_str() {
            "re.fullmatch" | "re.match" | "re.search" => {
                let [pattern, value, ..] = arguments.as_slice() else {
                    return None;
                };
                if arguments
                    .iter()
                    .take(2)
                    .any(|a| a.kind() == "keyword_argument")
                {
                    return None;
                }
                let body = literal_body(pattern)?;
                let (needs_start, needs_end) = match path.as_str() {
                    "re.fullmatch" => (false, false),
                    "re.match" => (false, true),
                    _ => (true, true),
                };
                (value.kind() == "identifier" && full_class(&body, needs_start, needs_end))
                    .then(|| value.text().into_owned())
            }
            "all" => {
                let [generator] = arguments.as_slice() else {
                    return None;
                };
                all_characters_allowed(generator)
            }
            _ => {
                if callee.kind() != "attribute" || !arguments.is_empty() {
                    return None;
                }
                let attribute = callee.field("attribute")?;
                let object = callee.field("object")?;
                (object.kind() == "identifier"
                    && matches!(attribute.text().as_ref(), "isdigit" | "isdecimal"))
                .then(|| object.text().into_owned())
            }
        }
    }

    /// `all(c in "<chars>" for c in name)` with every char allowed.
    fn all_characters_allowed<D: Doc>(generator: &Node<'_, D>) -> Option<String> {
        if generator.kind() != "generator_expression" {
            return None;
        }
        let body = generator.field("body")?;
        let clause = generator
            .children()
            .find(|child| child.kind() == "for_in_clause")?;
        let (variable, iterable) = (clause.field("left")?, clause.field("right")?);
        if variable.kind() != "identifier" || iterable.kind() != "identifier" {
            return None;
        }
        let parts: Vec<Node<'_, D>> = body.children().collect();
        let [element, operator, allowed] = parts.as_slice() else {
            return None;
        };
        if body.kind() != "comparison_operator"
            || operator.kind() != "in"
            || element.kind() != "identifier"
            || element.text() != variable.text()
        {
            return None;
        }
        let chars = literal_body(allowed)?;
        (!chars.is_empty() && chars.chars().all(is_allowed)).then(|| iterable.text().into_owned())
    }

    /// Whether `value` is `re.sub(<negated class>, "", operand)`, possibly
    /// followed by `.strip()`-style calls that only remove characters.
    fn is_filter<D: Doc>(value: &Node<'_, D>) -> bool {
        if value.kind() != "call" {
            return false;
        }
        let Some(callee) = value.field("function") else {
            return false;
        };
        let trims = callee.kind() == "attribute"
            && callee
                .field("attribute")
                .is_some_and(|a| matches!(a.text().as_ref(), "strip" | "lstrip" | "rstrip"));
        if trims {
            let no_arguments = value
                .field("arguments")
                .is_some_and(|a| a.named_children().next().is_none());
            return no_arguments && callee.field("object").is_some_and(|o| is_filter(&o));
        }
        if callee_path(&callee) != "re.sub" {
            return false;
        }
        let Some(arguments) = value.field("arguments") else {
            return false;
        };
        let arguments: Vec<Node<'_, D>> = arguments.named_children().collect();
        let [pattern, replacement, _operand] = arguments.as_slice() else {
            return false;
        };
        if arguments.iter().any(|a| a.kind() == "keyword_argument") {
            return false;
        }
        literal_body(replacement).is_some_and(|r| r.is_empty())
            && literal_body(pattern).is_some_and(|body| negated_class(&body))
    }

    /// The text between the quotes of a plain or raw string literal. A
    /// non-raw literal that contains a backslash is refused, so no escape
    /// sequence has to be interpreted.
    fn literal_body<D: Doc>(node: &Node<'_, D>) -> Option<String> {
        if node.kind() != "string" || node.children().any(|c| c.kind() == "interpolation") {
            return None;
        }
        let text = node.text().into_owned();
        let quote = text.find(['"', '\''])?;
        let raw = match &text[..quote] {
            "" => false,
            "r" | "R" => true,
            _ => return None,
        };
        let rest = &text[quote..];
        let width = if rest.starts_with("\"\"\"") || rest.starts_with("'''") {
            3
        } else {
            1
        };
        let body = rest.get(width..rest.len().checked_sub(width)?)?;
        (raw || !body.contains('\\')).then(|| body.to_owned())
    }

    /// `^?[class]<quantifier>?$?` with a non-negated, calculator-only class.
    fn full_class(pattern: &str, needs_start: bool, needs_end: bool) -> bool {
        let (rest, start) = pattern
            .strip_prefix('^')
            .map_or((pattern, false), |r| (r, true));
        let (rest, end) = if let Some(r) = rest.strip_suffix("\\Z") {
            (r, true)
        } else if let Some(r) = rest.strip_suffix('$') {
            (r, true)
        } else {
            (rest, false)
        };
        if (needs_start && !start) || (needs_end && !end) {
            return false;
        }
        parse_class(rest) == Some(false)
    }

    /// `[^class]` with an optional `+`, whose members are all allowed.
    fn negated_class(pattern: &str) -> bool {
        parse_class(pattern) == Some(true)
    }

    /// Parse `[...]` plus an optional `+`/`*` and nothing else, and return
    /// whether the class is negated. `None` when the text is anything else
    /// or the class admits a character outside the allowed set.
    fn parse_class(pattern: &str) -> Option<bool> {
        let mut chars = pattern.strip_prefix('[')?.chars().peekable();
        let negated = chars.next_if_eq(&'^').is_some();
        let mut members = 0_usize;
        let mut previous: Option<char> = None;
        loop {
            let c = chars.next()?;
            if c == ']' {
                break;
            }
            if c == '-' && previous.is_some() && chars.peek() != Some(&']') {
                let end = chars.next()?;
                let end = if end == '\\' { chars.next()? } else { end };
                let start = previous?;
                if start > end || !(start..=end).all(is_allowed) {
                    return None;
                }
                previous = None;
                members += 1;
                continue;
            }
            let literal = if c == '\\' {
                match chars.next()? {
                    's' | 'd' => {
                        previous = None;
                        members += 1;
                        continue;
                    }
                    escaped if OPERATORS.contains(escaped) => escaped,
                    _ => return None,
                }
            } else {
                c
            };
            if !is_allowed(literal) {
                return None;
            }
            previous = Some(literal);
            members += 1;
        }
        let tail: String = chars.collect();
        (members > 0 && matches!(tail.as_str(), "" | "+" | "*")).then_some(negated)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "a failed assumption in a test should fail the test"
    )]

    use super::*;
    use crate::flow::graph::{FlowGraph, FlowLanguage};
    use ast_grep_core::AstGrep;
    use ast_grep_core::tree_sitter::StrDoc;
    use ast_grep_language::Python;

    /// Builds the graph and returns whether a guard dominates the first
    /// argument of the first `eval` call.
    fn eval_argument_is_guarded(source: &str) -> bool {
        let root = AstGrep::<StrDoc<Python>>::try_new(source, Python).expect("parses");
        let graph = FlowGraph::build(&root.root(), FlowLanguage::Python);
        let argument = root
            .root()
            .dfs()
            .filter(|node| node.kind() == "call")
            .find(|node| node.field("function").is_some_and(|f| f.text() == "eval"))
            .and_then(|call| call.field("arguments"))
            .and_then(|args| args.named_children().next())
            .expect("an eval call with an argument");
        is_guarded(&graph, argument.node_id())
    }

    /// `tests/corpus/vulnerable/real_misses/eval_guarded_by_local_check.py`,
    /// first shape: the value can only ever be a class's own name.
    #[test]
    fn a_value_from_a_closed_expression_is_guarded() {
        assert!(eval_argument_is_guarded(
            "\
def dispatch_step(step):
    class_name = step.__class__.__name__
    handler_cls = eval(class_name)
    return handler_cls()
"
        ));
    }

    /// The same file's second shape: an exact-match check against a literal
    /// whitelist that raises before the sink is reached.
    #[test]
    fn a_membership_check_that_raises_guards_what_follows_it() {
        assert!(eval_argument_is_guarded(
            "\
ALLOWED_DTYPES = (\"float32\", \"float16\", \"bfloat16\")


def run_dtype_op(torch_dtype):
    if torch_dtype not in ALLOWED_DTYPES:
        raise ValueError(f\"unsupported dtype: {torch_dtype}\")
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// The control: the same sink, the same names, no check.
    #[test]
    fn the_same_shape_without_the_check_is_not_guarded() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype):
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// The positive form: the sink sits inside the branch the check opened.
    #[test]
    fn a_positive_membership_check_guards_its_own_branch() {
        assert!(eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype):
    if torch_dtype in (\"float32\", \"float16\"):
        return eval(f\"torch.{torch_dtype}\")
    return None
"
        ));
    }

    /// A check on a different name proves nothing about this one.
    #[test]
    fn a_check_on_another_name_does_not_guard() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype, mode):
    if mode not in (\"fast\", \"slow\"):
        raise ValueError(mode)
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// A branch that falls through checks nothing: execution reaches the sink
    /// either way.
    #[test]
    fn a_check_whose_branch_falls_through_does_not_guard() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype):
    if torch_dtype not in (\"float32\", \"float16\"):
        log(\"unusual dtype\")
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// A check after the sink cannot dominate it.
    #[test]
    fn a_check_after_the_sink_does_not_guard() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype):
    value = eval(f\"torch.{torch_dtype}\")
    if torch_dtype not in (\"float32\", \"float16\"):
        raise ValueError(torch_dtype)
    return value
"
        ));
    }

    /// A whitelist that is not a fixed set is not a whitelist.
    #[test]
    fn a_membership_check_against_a_dynamic_set_does_not_guard() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype, registry):
    if torch_dtype not in registry.known():
        raise ValueError(torch_dtype)
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// Model output that happens to be checked against nothing at all stays
    /// unguarded even when the surrounding function has guards for other
    /// values -- the guard must cover *this* value.
    #[test]
    fn a_guard_in_a_sibling_branch_does_not_reach_the_sink() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype, flag):
    if flag:
        if torch_dtype not in (\"float32\",):
            raise ValueError(torch_dtype)
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// Wraps `body` in a function so each test states only the check.
    fn guarded_after(body: &str) -> bool {
        let indented = body
            .lines()
            .map(|line| format!("    {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        eval_argument_is_guarded(&format!("import re\n\n\ndef calc(expr):\n{indented}\n"))
    }

    #[test]
    fn a_full_match_on_a_calculator_class_that_raises_guards() {
        assert!(guarded_after(
            "if not re.fullmatch(r\"[0-9+\\-*/(). ]+\", expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
        assert!(guarded_after(
            "if re.fullmatch(r\"[0-9+\\-*/(). ]+\", expr) is None:\n    return None\nreturn eval(expr)"
        ));
        assert!(guarded_after(
            "if expr and re.fullmatch(r\"[0-9\\s()+*/%.-]*\", expr):\n    return eval(expr)\nreturn None"
        ));
        assert!(guarded_after(
            "if not expr or not re.fullmatch(r\"[0-9+*/() ]+\", expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
    }

    #[test]
    fn a_class_that_admits_a_letter_or_other_symbol_does_not_guard() {
        for class in [
            "[0-9a-z+*/() ]+",
            "[0-9_+*/() ]+",
            "[\\w+*/() ]+",
            "[0-9+*/()\\[\\] ]+",
            "[0-9+*/(). \\\"]+",
            "[+-/0-9]+",
            "[^0-9+*/() ]+",
            "[0-9]+|x",
        ] {
            let body = format!(
                "if not re.fullmatch(r\"{class}\", expr):\n    raise ValueError(expr)\nreturn eval(expr)"
            );
            assert!(!guarded_after(&body), "{class}");
        }
    }

    #[test]
    fn a_match_that_is_not_anchored_at_the_end_does_not_guard() {
        assert!(!guarded_after(
            "if not re.match(r\"[0-9+*/() ]+\", expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
        assert!(!guarded_after(
            "if not re.search(r\"[0-9+*/() ]+\", expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
        assert!(!guarded_after(
            "if not re.search(r\"^[0-9+*/() ]+\", expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
        assert!(guarded_after(
            "if not re.match(r\"[0-9+*/() ]+$\", expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
        assert!(guarded_after(
            "if not re.search(r\"^[0-9+*/() ]+$\", expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
    }

    #[test]
    fn a_full_match_whose_branch_falls_through_does_not_guard() {
        assert!(!guarded_after(
            "if not re.fullmatch(r\"[0-9+*/() ]+\", expr):\n    print(expr)\nreturn eval(expr)"
        ));
    }

    #[test]
    fn a_full_match_on_another_name_does_not_guard() {
        assert!(!guarded_after(
            "if not re.fullmatch(r\"[0-9+*/() ]+\", other):\n    raise ValueError(other)\nreturn eval(expr)"
        ));
    }

    #[test]
    fn a_calculator_proof_lapses_when_the_name_is_reassigned() {
        assert!(!guarded_after(
            "if not re.fullmatch(r\"[0-9+*/() ]+\", expr):\n    raise ValueError(expr)\nexpr = expr + \"__import__('os')\"\nreturn eval(expr)"
        ));
        assert!(!guarded_after(
            "if not re.fullmatch(r\"[0-9+*/() ]+\", expr):\n    raise ValueError(expr)\nif expr:\n    expr = open(expr).read()\nreturn eval(expr)"
        ));
    }

    #[test]
    fn a_substitution_that_removes_everything_outside_the_class_guards() {
        assert!(guarded_after(
            "clean = re.sub(r\"[^0-9+\\-*/(). ]\", \"\", expr).strip()\nreturn eval(clean)"
        ));
        assert!(guarded_after(
            "expr = re.sub(r'[^0-9+\\-*/(). ]+', '', expr)\nreturn eval(expr)"
        ));
    }

    #[test]
    fn a_substitution_that_leaves_other_characters_behind_does_not_guard() {
        for statement in [
            "clean = re.sub(r\"[^0-9a-z+*/() ]\", \"\", expr)",
            "clean = re.sub(r\"[0-9+*/() ]\", \"\", expr)",
            "clean = re.sub(r\"[^0-9+*/() ]\", \"x\", expr)",
            "clean = re.sub(r\"[^0-9+*/() ]\", \"\", expr, count=1)",
            "clean = re.sub(r\"[^0-9+*/() ]\", \"\", expr, 1)",
            "clean = re.sub(r\"[^0-9+*/() ]\", \"\", expr).replace(\"x\", \"y\")",
        ] {
            let body = format!("{statement}\nreturn eval(clean)");
            assert!(!guarded_after(&body), "{statement}");
        }
    }

    #[test]
    fn a_digit_check_and_an_all_characters_check_guard() {
        assert!(guarded_after(
            "if not expr.isdigit():\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
        assert!(guarded_after(
            "if not all(ch in \"0123456789+-*/() \" for ch in expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
        assert!(!guarded_after(
            "if not all(ch in \"0123456789+-*/() abc\" for ch in expr):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
        assert!(!guarded_after(
            "if not all(ch in \"0123456789+-*/() \" for ch in other):\n    raise ValueError(expr)\nreturn eval(expr)"
        ));
    }
}
