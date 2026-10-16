//! Dockerfile instruction parsing and the `BAS-INFRA-001` / `BAS-INFRA-002` /
//! `BAS-INFRA-006` checks.

use std::path::Path;

use crate::category::Category;
use crate::credential;
use crate::finding::{Confidence, Finding, Kind, Location, Severity};

/// Who a stage ends up running as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EffectiveUser<'a> {
    /// No `USER` instruction anywhere in the final stage's inheritance chain.
    /// Docker defaults to root, but the Dockerfile never says so.
    Unset,
    /// The final stage runs as this user, set at this line.
    Set { name: &'a str, line: usize },
}

/// One build stage: everything between one `FROM` and the next.
#[derive(Debug)]
struct Stage<'a> {
    /// The `AS <alias>` name, lower-cased — stage references are
    /// case-insensitive.
    alias: Option<String>,
    /// The image or stage this one builds on, lower-cased.
    base: String,
    /// The last `USER` in this stage. The last one wins: `USER root` followed
    /// by `USER app` runs as `app`.
    user: Option<(&'a str, usize)>,
}

/// One Dockerfile instruction, with its continuation lines already joined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Instruction {
    /// The keyword, upper-cased. Dockerfile keywords are case-insensitive.
    pub(super) keyword: String,
    /// Everything after the keyword, with `\` continuations joined into one
    /// line and interior comment lines removed.
    pub(super) arguments: String,
    /// 1-indexed line the instruction starts on.
    pub(super) line: usize,
}

/// Parse a Dockerfile into its instruction list.
///
/// Three details of the format decide every check downstream, and all three
/// are handled here rather than at each call site: keywords are
/// case-insensitive, a trailing `\` continues an instruction onto the next
/// line, and a line whose first non-blank character is `#` is a comment —
/// including *inside* a continuation, where Docker removes it before joining.
///
/// The `# escape=` parser directive, which swaps the continuation character
/// for a backtick on Windows builds, is not honoured. It appears in no
/// Dockerfile in the calibration corpus, and misreading one costs a joined
/// line, not a wrong finding.
pub(super) fn parse(contents: &str) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut pending: Option<(usize, String)> = None;

    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            // A blank or comment line neither starts an instruction nor ends
            // a continuation: Docker drops it and keeps joining.
            continue;
        }

        let (text, continues) = match line.strip_suffix('\\') {
            Some(head) => (head.trim_end(), true),
            None => (line, false),
        };

        let (start, mut joined) = pending.take().unwrap_or_else(|| (index + 1, String::new()));
        if !joined.is_empty() && !text.is_empty() {
            joined.push(' ');
        }
        joined.push_str(text);

        if continues {
            pending = Some((start, joined));
        } else if let Some(instruction) = split_instruction(start, &joined) {
            instructions.push(instruction);
        }
    }

    // A file ending mid-continuation is malformed, but the instruction it was
    // building is still the best reading of what the author meant.
    if let Some((start, joined)) = pending
        && let Some(instruction) = split_instruction(start, &joined)
    {
        instructions.push(instruction);
    }

    instructions
}

/// Split one joined logical line into its keyword and arguments.
fn split_instruction(line: usize, joined: &str) -> Option<Instruction> {
    let trimmed = joined.trim();
    let (keyword, arguments) = trimmed.split_once(char::is_whitespace)?;
    Some(Instruction {
        keyword: keyword.to_ascii_uppercase(),
        arguments: arguments.trim().to_owned(),
        line,
    })
}

/// Split the instruction list into build stages, one per `FROM`.
///
/// Instructions before the first `FROM` — only `ARG` is legal there — belong
/// to no stage and are dropped.
fn stages(instructions: &[Instruction]) -> Vec<Stage<'_>> {
    let mut stages: Vec<Stage<'_>> = Vec::new();
    for instruction in instructions {
        match instruction.keyword.as_str() {
            "FROM" => stages.push(new_stage(&instruction.arguments)),
            "USER" => {
                if let Some(stage) = stages.last_mut() {
                    // Overwrite rather than keep the first: the last `USER` in
                    // a stage is the one the image runs as.
                    stage.user = Some((instruction.arguments.trim(), instruction.line));
                }
            }
            _ => {}
        }
    }
    stages
}

/// Read one `FROM <image> [AS <alias>]` line. Platform flags (`--platform=…`)
/// are skipped so they are not mistaken for the image reference.
fn new_stage(arguments: &str) -> Stage<'_> {
    let mut words = arguments
        .split_whitespace()
        .skip_while(|word| word.starts_with("--"));
    let base = words.next().unwrap_or_default().to_ascii_lowercase();
    let alias = match (words.next(), words.next()) {
        (Some(keyword), Some(alias)) if keyword.eq_ignore_ascii_case("as") => {
            Some(alias.to_ascii_lowercase())
        }
        _ => None,
    };
    Stage {
        alias,
        base,
        user: None,
    }
}

/// The user the image actually runs as, resolved across stages.
///
/// Only the final stage ships, so only the final stage is asked. Docker resets
/// the user to root at every `FROM`, which is why a builder stage's `USER` —
/// root or otherwise — says nothing about the shipped image. The one exception
/// is `FROM <earlier stage>`: that copies the referenced stage's image config,
/// `USER` included, so the chain is followed backwards until a stage sets one
/// or the chain reaches a base image we cannot read.
pub(super) fn effective_user(instructions: &[Instruction]) -> EffectiveUser<'_> {
    let stages = stages(instructions);
    let Some(mut index) = stages.len().checked_sub(1) else {
        return EffectiveUser::Unset;
    };

    loop {
        if let Some((name, line)) = stages[index].user {
            return EffectiveUser::Set { name, line };
        }
        // Only stages declared *earlier* can be referenced, so walking
        // backwards always terminates.
        let base = &stages[index].base;
        match stages[..index]
            .iter()
            .rposition(|stage| stage.alias.as_deref() == Some(base.as_str()))
        {
            Some(parent) => index = parent,
            None => return EffectiveUser::Unset,
        }
    }
}

/// True if a `USER` argument names root.
///
/// The argument may carry a group (`root:root`, `0:0`); only the user half
/// decides. A variable reference such as `$USERNAME` is deliberately not root:
/// the build arg could hold anything, and guessing is how a scanner earns its
/// reputation for noise.
fn is_root(argument: &str) -> bool {
    let user = argument
        .split(':')
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches(['"', '\'']);
    user == "root" || user == "0"
}

/// Run the Dockerfile checks: `BAS-INFRA-001` on the effective final user, and
/// `BAS-INFRA-002` on every `ENV`/`ARG` value.
pub(super) fn run_all(relative_path: &Path, contents: &str) -> Vec<Finding> {
    let instructions = parse(contents);
    if instructions.is_empty() {
        // A file with no instructions describes no container, so there is no
        // boundary to have an opinion about.
        return Vec::new();
    }

    let mut findings = Vec::new();
    findings.extend(check_effective_user(&instructions, relative_path, contents));
    findings.extend(check_key_literals(&instructions, relative_path));
    findings.extend(check_credential_literals(&instructions, relative_path));
    findings
}

/// `BAS-INFRA-001` — the container runs as root.
///
/// Two outcomes, and the split is the point. Explicitly choosing root is a
/// defect: the Dockerfile says so, and no deployment makes it right. Having no
/// `USER` at all is an observation, because that is what most Dockerfiles in
/// the wild look like — reporting each one as a bug is precisely the noise
/// that gets a scanner uninstalled.
fn check_effective_user(
    instructions: &[Instruction],
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    match effective_user(instructions) {
        EffectiveUser::Set { name, .. } if !is_root(name) => None,
        EffectiveUser::Set { name, line } => Some(Finding {
            rule_id: "BAS-INFRA-001".to_owned(),
            title: "Container image runs as root".to_owned(),
            kind: Kind::Defect,
            severity: Severity::High,
            confidence: Confidence::High,
            categories: vec![Category::Zt3],
            location: location(relative_path, line),
            snippet: format!("USER {name}"),
            description:
                "The final build stage sets `USER root`, so every process in this container — \
                 the agent and anything its tools spawn — runs with full privileges inside it, \
                 and any writable host mount is writable as root."
                    .to_owned(),
            remediation:
                "Create an unprivileged user in the image and end the final stage with it, \
                 e.g. `RUN useradd -m app` followed by `USER app`. Keep the `USER root` only \
                 around the instructions that genuinely need it."
                    .to_owned(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        }),
        EffectiveUser::Unset => Some(Finding {
            rule_id: "BAS-INFRA-001".to_owned(),
            title: "Container image declares no unprivileged user".to_owned(),
            kind: Kind::Observation,
            severity: Severity::Low,
            confidence: Confidence::High,
            categories: vec![Category::Zt3],
            location: location(relative_path, first_stage_line(instructions)),
            snippet: first_stage_snippet(contents, instructions),
            description:
                "No `USER` instruction appears in the final build stage, so the container \
                 falls back to root. Whether that matters depends on how the image is run — \
                 a `--user` flag or a Kubernetes `securityContext` can set it from outside."
                    .to_owned(),
            remediation:
                "If nothing outside this repository sets the user, add an unprivileged one \
                 to the final stage: `RUN useradd -m app` followed by `USER app`."
                    .to_owned(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        }),
    }
}

/// The line of the final stage's `FROM`, which is the most useful place to
/// point at when the thing being reported is an instruction that is missing.
fn first_stage_line(instructions: &[Instruction]) -> usize {
    instructions
        .iter()
        .rfind(|instruction| instruction.keyword == "FROM")
        .map_or(1, |instruction| instruction.line)
}

fn first_stage_snippet(contents: &str, instructions: &[Instruction]) -> String {
    let line = first_stage_line(instructions);
    contents
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// `BAS-INFRA-002` — a provider API key baked into the image.
///
/// An `ENV` value is written into the image's metadata, so it is readable by
/// `docker inspect` and by anyone who pulls the image; an `ARG` default is
/// committed to the Dockerfile itself. Neither is a place a live key can be.
fn check_key_literals(instructions: &[Instruction], relative_path: &Path) -> Vec<Finding> {
    instructions
        .iter()
        .filter(|instruction| instruction.keyword == "ENV" || instruction.keyword == "ARG")
        .flat_map(|instruction| {
            assignments(&instruction.arguments)
                .into_iter()
                .filter(|(_, value)| credential::is_provider_key_literal(value))
                .map(move |(name, value)| Finding {
                    rule_id: "BAS-INFRA-002".to_owned(),
                    title: "Provider API key baked into the container image".to_owned(),
                    kind: Kind::Defect,
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    categories: vec![Category::Zt1],
                    location: location(relative_path, instruction.line),
                    snippet: format!("{} {name}={value}", instruction.keyword),
                    description: format!(
                        "`{name}` holds a provider API key as a literal. An `ENV` value is part \
                         of the image metadata and an `ARG` default is committed to this file, \
                         so the key travels with every pull, every layer cache, and every clone."
                    ),
                    remediation: format!(
                        "Remove the literal and inject `{name}` at run time — a `--env-file`, an \
                         orchestrator secret, or a BuildKit `--mount=type=secret` — then rotate \
                         the key that leaked into history."
                    ),
                    secondary_rule_ids: Vec::new(),
                    references: Vec::new(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// `BAS-INFRA-006` — a hardcoded password, secret, or token literal in `ENV`
/// or `ARG`, not shaped like a known provider key.
///
/// The generic sibling of `BAS-INFRA-002`: that rule owns the narrow `sk-`
/// provider-key shape, this one owns everything else credential-named —
/// database passwords, service tokens, generic API secrets. A value already
/// caught by [`credential::is_provider_key_literal`] is excluded here so the
/// two rules never double-report the same literal. See [`credential`] for the
/// shared name/value judgment the Compose `environment:` check under the same
/// rule id reuses.
fn check_credential_literals(instructions: &[Instruction], relative_path: &Path) -> Vec<Finding> {
    instructions
        .iter()
        .filter(|instruction| instruction.keyword == "ENV" || instruction.keyword == "ARG")
        .flat_map(|instruction| {
            assignments(&instruction.arguments)
                .into_iter()
                .filter(|(name, value)| {
                    !credential::is_provider_key_literal(value)
                        && credential::looks_like_credential_key(name)
                        && credential::is_hardcoded_credential_value(value)
                })
                .map(move |(name, value)| Finding {
                    rule_id: "BAS-INFRA-006".to_owned(),
                    title: "Hardcoded credential in deployment configuration".to_owned(),
                    // Reported as an observation: the match alone does not show a real problem.
                    kind: Kind::Observation,
                    severity: credential::credential_severity(&name, &value),
                    confidence: Confidence::High,
                    categories: vec![Category::Zt1],
                    location: location(relative_path, instruction.line),
                    snippet: format!("{} {name}={value}", instruction.keyword),
                    description: format!(
                        "`{name}` holds a literal credential. An `ENV` value is part of the \
                         image metadata and an `ARG` default is committed to this file, so it \
                         ships with every pull, every layer cache, and every clone."
                    ),
                    remediation: format!(
                        "Remove the literal and inject `{name}` at run time — a `--env-file`, an \
                         orchestrator secret, or a BuildKit `--mount=type=secret` — then rotate \
                         the credential that leaked into history."
                    ),
                    secondary_rule_ids: Vec::new(),
                    references: Vec::new(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The `NAME=value` pairs one `ENV` or `ARG` declares.
///
/// Both forms are handled: the modern `ENV A=1 B=2`, and the legacy
/// `ENV NAME the rest of the line`, where the value is everything after the
/// first space and may itself contain `=`. `ARG NAME` with no default declares
/// no value and yields nothing.
fn assignments(arguments: &str) -> Vec<(String, String)> {
    let words = split_respecting_quotes(arguments);
    let Some(first) = words.first() else {
        return Vec::new();
    };

    if !first.contains('=') {
        // Legacy form. Everything after the name is one value, `=` included.
        let value = arguments
            .trim()
            .split_once(char::is_whitespace)
            .map(|(_, rest)| rest.trim());
        return match value {
            Some(value) if !value.is_empty() => {
                vec![(first.clone(), unquote(value).to_owned())]
            }
            _ => Vec::new(),
        };
    }

    words
        .iter()
        .filter_map(|word| {
            let (name, value) = word.split_once('=')?;
            Some((name.to_owned(), unquote(value).to_owned()))
        })
        .collect()
}

/// Split on whitespace, but not whitespace inside quotes, so
/// `ENV A="one two" B=3` is two assignments rather than three words.
fn split_respecting_quotes(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in text.chars() {
        match quote {
            Some(open) if ch == open => quote = None,
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn unquote(value: &str) -> &str {
    let trimmed = value.trim();
    for quote in ['"', '\''] {
        if trimmed.len() >= 2 && trimmed.starts_with(quote) && trimmed.ends_with(quote) {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

fn location(relative_path: &Path, line: usize) -> Location {
    Location {
        file: relative_path.to_path_buf(),
        line,
        column: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keywords(contents: &str) -> Vec<String> {
        parse(contents).into_iter().map(|i| i.keyword).collect()
    }

    #[test]
    fn keywords_are_upper_cased_and_comments_dropped() {
        let contents = "# syntax=docker/dockerfile:1\nfrom python:3.12\n\n  Run pip install .\n";

        let parsed = parse(contents);

        assert_eq!(keywords(contents), ["FROM", "RUN"]);
        assert_eq!(parsed[0].arguments, "python:3.12");
        assert_eq!(parsed[0].line, 2);
        assert_eq!(parsed[1].line, 4);
    }

    #[test]
    fn a_continuation_joins_into_one_instruction() {
        let contents = "RUN apt-get update && \\\n    apt-get install -y curl\nUSER app\n";

        let parsed = parse(contents);

        assert_eq!(parsed.len(), 2, "{parsed:#?}");
        assert_eq!(parsed[0].keyword, "RUN");
        assert_eq!(
            parsed[0].arguments,
            "apt-get update && apt-get install -y curl"
        );
        assert_eq!(parsed[0].line, 1);
        assert_eq!(parsed[1].line, 3, "the USER line number survives the join");
    }

    #[test]
    fn a_comment_inside_a_continuation_is_ignored_not_treated_as_an_instruction() {
        // Docker strips comment lines before joining continuations, so the
        // `USER` here is a comment about the build, not an instruction.
        let contents = "RUN set -eux \\\n# USER root would be wrong here\n    && id\n";

        let parsed = parse(contents);

        assert_eq!(keywords(contents), ["RUN"], "{parsed:#?}");
        assert_eq!(parsed[0].arguments, "set -eux && id");
    }

    #[test]
    fn a_trailing_continuation_at_end_of_file_does_not_hang_or_panic() {
        let parsed = parse("RUN echo hi && \\\n");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].keyword, "RUN");
    }

    #[test]
    fn an_empty_file_parses_to_nothing() {
        assert_eq!(
            parse(""),
            Vec::<crate::infra::dockerfile::Instruction>::new()
        );
        assert_eq!(
            parse("\n\n   \n# just a comment\n"),
            Vec::<crate::infra::dockerfile::Instruction>::new()
        );
    }

    fn user_of(contents: &str) -> String {
        match effective_user(&parse(contents)) {
            EffectiveUser::Unset => "<unset>".to_owned(),
            EffectiveUser::Set { name, .. } => name.to_owned(),
        }
    }

    fn rules(contents: &str) -> Vec<String> {
        run_all(Path::new("Dockerfile"), contents)
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect()
    }

    #[test]
    fn the_last_user_in_the_final_stage_wins() {
        // Verbatim shape of the one `USER root` in the calibration corpus:
        // root to install packages, then back down to an unprivileged user.
        // Reporting it would be a false positive on the only sample we have.
        let contents = "FROM python:3.12\nUSER root\nRUN apt-get install -y curl\nUSER app\n";

        assert_eq!(user_of(contents), "app");
        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }

    #[test]
    fn explicit_root_as_the_final_user_is_a_defect() {
        for line in ["USER root", "USER 0", "USER root:root", "USER 0:0"] {
            let contents = format!("FROM python:3.12\n{line}\nCMD [\"python\", \"app.py\"]\n");
            assert_eq!(
                rules(&contents),
                ["BAS-INFRA-001"],
                "{line} should be read as root"
            );
        }
    }

    #[test]
    fn root_defect_carries_the_right_kind_and_line() {
        let findings = run_all(
            Path::new("Dockerfile"),
            "FROM python:3.12\nWORKDIR /app\nUSER root\n",
        );

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].kind, Kind::Defect);
        assert_eq!(findings[0].categories, vec![Category::Zt3]);
        assert_eq!(findings[0].location.line, 3);
        assert_eq!(findings[0].snippet, "USER root");
    }

    #[test]
    fn no_user_instruction_is_an_observation_not_a_defect() {
        // Most Dockerfiles in the wild have no USER at all. Calling every one
        // a defect is exactly the noise this scanner exists to avoid.
        let findings = run_all(
            Path::new("Dockerfile"),
            "FROM python:3.12\nCMD [\"python\"]\n",
        );

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-INFRA-001");
        assert_eq!(findings[0].kind, Kind::Observation);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn a_builder_stages_user_does_not_settle_the_final_stage() {
        // Docker resets to root at every FROM, so a `USER app` in a builder
        // says nothing about what the shipped image runs as — and a `USER
        // root` in a builder is not a defect, because that stage is discarded.
        let builder_drops_root = "FROM node:22 AS builder\nUSER root\nRUN npm ci\n\nFROM node:22-slim\nCOPY --from=builder /app /app\nUSER app\n";
        assert_eq!(user_of(builder_drops_root), "app");
        assert_eq!(rules(builder_drops_root), Vec::<String>::new());

        let builder_only = "FROM node:22 AS builder\nUSER app\nRUN npm ci\n\nFROM node:22-slim\nCOPY --from=builder /app /app\n";
        assert_eq!(user_of(builder_only), "<unset>");
        let observed = run_all(Path::new("Dockerfile"), builder_only);
        assert_eq!(observed.len(), 1, "{observed:#?}");
        assert_eq!(observed[0].kind, Kind::Observation);
    }

    #[test]
    fn a_final_stage_built_on_a_named_stage_inherits_its_user() {
        // `FROM <stage>` copies the referenced stage's image config, USER
        // included — so the inherited value is what actually runs.
        let inherits_app = "FROM node:22 AS base\nUSER app\n\nFROM base\nCMD [\"node\"]\n";
        assert_eq!(user_of(inherits_app), "app");
        assert_eq!(rules(inherits_app), Vec::<String>::new());

        let inherits_root = "FROM node:22 AS base\nUSER root\n\nFROM base\nCMD [\"node\"]\n";
        assert_eq!(user_of(inherits_root), "root");
        assert_eq!(rules(inherits_root), ["BAS-INFRA-001"]);
    }

    #[test]
    fn a_variable_user_is_not_read_as_root() {
        // `USER $USERNAME` appears verbatim in the corpus. The build arg could
        // hold anything; claiming it is root would be a guess.
        let contents = "FROM python:3.12\nARG USERNAME=dev\nUSER $USERNAME\n";

        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }

    #[test]
    fn a_provider_key_literal_in_env_or_arg_is_a_defect() {
        for instruction in [
            "ENV OPENAI_API_KEY=sk-proj-9f2b7d41c6a8e35019bd",
            "ENV OPENAI_API_KEY=\"sk-proj-9f2b7d41c6a8e35019bd\"",
            "ARG OPENAI_API_KEY=sk-proj-9f2b7d41c6a8e35019bd",
            "ENV OPENAI_API_KEY sk-proj-9f2b7d41c6a8e35019bd",
        ] {
            let contents = format!("FROM python:3.12\n{instruction}\nUSER app\n");
            assert_eq!(
                rules(&contents),
                ["BAS-INFRA-002"],
                "{instruction} should be flagged"
            );
        }
    }

    #[test]
    fn an_env_var_holding_a_variable_name_is_not_a_credential() {
        // The whole point of anchoring on the value's shape: this names a
        // variable, it does not hold a key.
        let contents = "FROM python:3.12\nENV OPENAI_API_KEY_NAME=OPENAI_API_KEY\nUSER app\n";

        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }

    #[test]
    fn env_forms_that_are_not_credentials_stay_quiet() {
        for instruction in [
            // A build-arg reference, not a value.
            "ENV OPENAI_API_KEY=$OPENAI_API_KEY",
            "ENV OPENAI_API_KEY=${OPENAI_API_KEY}",
            // Declared with no default at all.
            "ARG OPENAI_API_KEY",
            // Too short to be a provider key, and a placeholder besides.
            "ENV OPENAI_API_KEY=sk-changeme",
            // A path that merely starts with the same letters.
            "ENV SDK_PATH=sk-tools/bin",
        ] {
            let contents = format!("FROM python:3.12\n{instruction}\nUSER app\n");
            assert!(
                rules(&contents).is_empty(),
                "{instruction} was wrongly flagged"
            );
        }
    }

    #[test]
    fn a_key_in_a_multi_pair_env_is_still_found() {
        let contents = "FROM python:3.12\nENV LOG_LEVEL=debug KEY=sk-proj-9f2b7d41c6a8e35019bd PORT=8080\nUSER app\n";

        assert_eq!(rules(contents), ["BAS-INFRA-002"]);
    }

    #[test]
    fn a_hardcoded_weak_password_in_env_or_arg_is_a_defect() {
        for instruction in [
            "ENV DB_PASSWORD=Sup3rWeakPass!",
            "ARG DB_PASSWORD=Sup3rWeakPass!",
            "ENV DB_PASSWORD Sup3rWeakPass!",
        ] {
            let contents = format!("FROM python:3.12\n{instruction}\nUSER app\n");
            assert_eq!(
                rules(&contents),
                ["BAS-INFRA-006"],
                "{instruction} should be flagged"
            );
        }
    }

    #[test]
    fn a_provider_key_literal_is_not_double_reported_as_a_generic_credential() {
        // BAS-INFRA-002 already owns the `sk-`-shaped provider key. The
        // generic credential check must not also fire on the same value.
        let contents =
            "FROM python:3.12\nENV OPENAI_API_KEY=sk-proj-9f2b7d41c6a8e35019bd\nUSER app\n";

        assert_eq!(rules(contents), ["BAS-INFRA-002"]);
    }

    #[test]
    fn an_interpolated_or_placeholder_env_credential_is_not_flagged() {
        for instruction in [
            "ENV DB_PASSWORD=$DB_PASSWORD",
            "ENV DB_PASSWORD=${DB_PASSWORD}",
            "ENV DB_PASSWORD=changeme",
            "ARG DB_PASSWORD",
        ] {
            let contents = format!("FROM python:3.12\n{instruction}\nUSER app\n");
            assert!(
                rules(&contents).is_empty(),
                "{instruction} was wrongly flagged"
            );
        }
    }

    #[test]
    fn an_empty_dockerfile_produces_nothing() {
        // A file with no instructions describes no container, so there is no
        // boundary to have an opinion about.
        assert_eq!(
            run_all(Path::new("Dockerfile"), ""),
            Vec::<crate::finding::Finding>::new()
        );
        assert_eq!(
            run_all(Path::new("Dockerfile"), "# notes only\n"),
            Vec::<crate::finding::Finding>::new()
        );
    }
}
