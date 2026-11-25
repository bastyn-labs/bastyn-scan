//! Argument definitions.

use std::path::PathBuf;

use bastyn_core::Framework;
use clap::{Args, Parser, Subcommand, ValueEnum};

/// A fast, single-binary code security scanner.
#[derive(Debug, Parser)]
#[command(
    name = "bastyn",
    version,
    about,
    long_about = None,
    propagate_version = true,
    args_conflicts_with_subcommands = true,
    arg_required_else_help = true,
)]
pub(crate) struct Cli {
    /// The subcommand to run. Absent when `--watch` is given.
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// Options for watch mode, which runs instead of a subcommand.
    #[command(flatten)]
    pub(crate) watch: WatchArgs,

    /// Options shared by every subcommand.
    #[command(flatten)]
    pub(crate) global: GlobalArgs,
}

impl Cli {
    /// Checks the combinations that clap's declarative rules cannot express.
    ///
    /// Watch mode has no machine-readable output, so `--format json` and
    /// `--format sarif` with `--watch` are refused, and so is a command line
    /// that names neither a subcommand nor `--watch`.
    pub(crate) fn validate(&self) -> Result<(), clap::Error> {
        let mut command = <Self as clap::CommandFactory>::command();
        if self.command.is_none() && self.watch.watch.is_none() {
            return Err(command.error(
                clap::error::ErrorKind::MissingSubcommand,
                "a subcommand or `--watch <PATH>` is required",
            ));
        }
        if self.watch.watch.is_some() && self.global.format != Format::Text {
            return Err(command.error(
                clap::error::ErrorKind::ArgumentConflict,
                "`--format` cannot be combined with `--watch`: watch output is text only",
            ));
        }
        Ok(())
    }
}

/// Options for watch mode: `bastyn --watch <PATH>`.
///
/// Watch mode is offline. It never contacts an MCP server, never sends the
/// anonymous scan summary and never looks up CVEs.
#[derive(Debug, Args)]
pub(crate) struct WatchArgs {
    /// Watch a directory for new findings in skill and instruction files.
    ///
    /// Runs until stopped. Each new finding is printed in red and, with
    /// `--reporter`, sent once to the reporter's endpoint. Watch mode is
    /// offline: it never contacts an MCP server, never sends the anonymous
    /// scan summary and never looks up CVEs. Output is text only.
    #[arg(long, value_name = "PATH")]
    pub(crate) watch: Option<PathBuf>,

    /// Where to send each new finding, besides the terminal.
    ///
    /// The webhook token is read only from the environment variable
    /// `BASTYN_OPENCLAW_TOKEN`, never from an argument.
    #[arg(long, value_enum, requires_all = ["watch", "report_url"])]
    pub(crate) reporter: Option<Reporter>,

    /// The reporter's webhook URL, such as `http://127.0.0.1:18789/hooks/agent`.
    ///
    /// Plain http is accepted only for loopback hosts (127.0.0.1, localhost,
    /// `[::1]`); any other host needs https.
    #[arg(long, value_name = "URL", requires = "reporter")]
    pub(crate) report_url: Option<String>,

    /// Agent to address in the webhook message (`agentId`).
    ///
    /// Optional. Set it when the gateway has no default agent.
    #[arg(long, value_name = "ID", requires = "reporter")]
    pub(crate) openclaw_agent_id: Option<String>,
}

/// Where watch mode sends findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub(crate) enum Reporter {
    /// An `OpenClaw` webhook.
    Openclaw,
}

/// Options that apply to every subcommand.
#[derive(Debug, Args)]
pub(crate) struct GlobalArgs {
    /// Output format.
    #[arg(long, short, global = true, value_enum, default_value_t = Format::Text)]
    pub(crate) format: Format,

    /// Suppress the per-finding listing and print only the summary.
    ///
    /// Has no effect on `--format json` or `--format sarif`, whose shapes are
    /// contracts.
    #[arg(long, short, global = true)]
    pub(crate) quiet: bool,

    /// Disable colour in terminal output. Also honoured via `NO_COLOR`.
    #[arg(long, global = true)]
    pub(crate) no_color: bool,
}

/// How results are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub(crate) enum Format {
    /// Human-readable, grouped by threat layer.
    Text,
    /// A single JSON object, for `jq` or a CI step.
    Json,
    /// SARIF 2.1.0, for GitHub code scanning and GitLab.
    Sarif,
}

/// Which framework the terminal report expands in full.
///
/// Modelled on [`Format`]: a small closed set of names, one of which is the
/// behaviour that existed before the flag did. Unlike `--format` this lives on
/// `scan` rather than on every subcommand, because grouping is a property of a
/// set of findings, and a future subcommand that produces none would have no
/// use for it.
///
/// The frameworks are always crosswalked; this only says how much of that is
/// printed. [`GroupBy::Layer`] leaves every framework summarised, which is
/// what a scan with no flags does. Naming a framework lists the findings under
/// each of its areas and drops the other two, which is what a reader who has
/// already chosen a framework wants.
///
/// A crosswalk is never a compliance assessment. It groups findings by the
/// areas of a framework they are relevant to; it never states that an
/// obligation is or is not met.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum GroupBy {
    /// Expand none of them: the defect listing stays grouped by Bastyn's own
    /// threat-model layers — entry vectors, amplifiers, impacts, cross-layer
    /// threats, then missing defenses — and every framework is summarised
    /// below it. The default, and the only value that names no framework.
    #[value(name = "layer")]
    Layer,
    /// Areas of the EU AI Act the findings are relevant to. A crosswalk, not
    /// a compliance assessment.
    #[value(name = "eu-ai-act")]
    EuAiAct,
    /// Subcategories of the NIST AI Risk Management Framework 1.0 the
    /// findings are relevant to. A crosswalk, not a compliance assessment.
    #[value(name = "nist-ai-rmf")]
    NistAiRmf,
    /// Risks in the NIST Generative AI Profile the findings are relevant to.
    /// A crosswalk, not a compliance assessment.
    #[value(name = "nist-genai")]
    NistGenAi,
}

impl GroupBy {
    /// The framework to expand in full, or `None` to summarise every one.
    ///
    /// Written as an exhaustive match so that adding a value without deciding
    /// what it groups by is a compile error rather than a flag that parses
    /// and then silently does nothing — a CI job that asked for a grouping
    /// and got none would read the empty result as "nothing to report".
    pub(crate) const fn framework(self) -> Option<Framework> {
        match self {
            Self::Layer => None,
            Self::EuAiAct => Some(Framework::EuAiAct),
            Self::NistAiRmf => Some(Framework::NistAiRmf),
            Self::NistGenAi => Some(Framework::NistGenAi),
        }
    }
}

/// The minimum severity that makes the command exit non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lower")]
pub(crate) enum FailOn {
    /// Never fail on findings. Report only.
    None,
    /// Fail on anything at all.
    Low,
    /// Fail on medium and above.
    Medium,
    /// Fail on high and above.
    High,
    /// Fail on critical only.
    Critical,
}

/// The available subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Scan a repository for AI and agentic security issues.
    Scan(ScanArgs),

    /// Print the project ID that scans of a directory report under.
    ///
    /// Reads the directory's git configuration and never runs `git`, writes
    /// no file and uses no network.
    ProjectId(ProjectIdArgs),

    /// Connect to an MCP server and write its tool list to a snapshot file.
    ///
    /// This is the one command that connects to a server you name, or starts
    /// a command from a config file, and only when you run it. `scan` connects
    /// to MCP servers only with `--inspect-remote`.
    InspectServer(InspectServerArgs),
}

/// Arguments for `bastyn inspect-server`.
#[derive(Debug, Args)]
pub(crate) struct InspectServerArgs {
    /// URL of a Streamable HTTP server.
    #[arg(long, conflicts_with = "config", required_unless_present = "config")]
    pub(crate) url: Option<String>,

    /// Request header for `--url`, as `Name: value`. Repeatable.
    #[arg(long = "header", value_name = "NAME: VALUE", requires = "url", value_parser = parse_header)]
    pub(crate) headers: Vec<(String, String)>,

    /// MCP config file holding the server entry.
    #[arg(long, value_name = "FILE", requires = "server")]
    pub(crate) config: Option<PathBuf>,

    /// Name of the server entry in `--config`.
    #[arg(long, value_name = "NAME", requires = "config", conflicts_with = "url")]
    pub(crate) server: Option<String>,

    /// Allow starting the entry's command. Without it a `command` entry is
    /// refused and nothing runs.
    #[arg(long, requires = "config", conflicts_with = "url")]
    pub(crate) allow_spawn: bool,

    /// Write the snapshot here instead of standard output.
    #[arg(long, value_name = "FILE")]
    pub(crate) out: Option<PathBuf>,
}

/// Split `Name: value` into its two halves.
fn parse_header(text: &str) -> Result<(String, String), String> {
    match text.split_once(':') {
        Some((name, value)) if !name.trim().is_empty() => {
            Ok((name.trim().to_owned(), value.trim().to_owned()))
        }
        _ => Err("expected `Name: value`".to_owned()),
    }
}

/// Arguments for `bastyn project-id`.
#[derive(Debug, Args)]
pub(crate) struct ProjectIdArgs {
    /// Directory to resolve the project ID for.
    #[arg(default_value = ".", value_name = "PATH")]
    pub(crate) path: PathBuf,

    /// Also print how the ID was derived and exactly what was hashed.
    #[arg(long)]
    pub(crate) explain: bool,
}

/// Arguments for `bastyn scan`.
#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "command-line flags are booleans; a state machine would obscure the surface"
)]
pub(crate) struct ScanArgs {
    /// Directory to scan.
    #[arg(default_value = ".", value_name = "PATH")]
    pub(crate) path: PathBuf,

    /// Minimum severity that makes this command exit non-zero.
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    pub(crate) fail_on: FailOn,

    /// Which compliance framework to expand in full.
    ///
    /// Every scan already ends with a summary of all three: which areas of the
    /// EU AI Act and the two NIST documents the findings are relevant to, with
    /// counts and no per-finding lines. Naming one here lists the findings
    /// under each of its areas instead, and leaves the other two out.
    ///
    /// These are **crosswalks**: which regulatory areas the findings are
    /// relevant to. Bastyn cannot determine compliance — that depends on the
    /// deployment context, the system's risk classification, and the
    /// organisation's documentation and processes, none of which are in the
    /// source code. Finding nothing does not mean an obligation is met.
    ///
    /// The grouping is a view, never a filter: it changes no finding, no
    /// count, and no exit code. It appears in `--format json` and, as SARIF
    /// taxonomies, in `--format sarif`.
    #[arg(long, value_enum, default_value_t = GroupBy::Layer, value_name = "TAXONOMY")]
    pub(crate) group_by: GroupBy,

    /// Show context-dependent observations alongside defects.
    ///
    /// Observations describe a control the repository shows to be absent
    /// without showing that its absence is wrong — a public chatbot needs no
    /// authentication, and a rate limiter usually lives at the edge. They are
    /// counted either way; this decides whether they are listed.
    #[arg(long)]
    pub(crate) show_observations: bool,

    /// List every file the scan read, grouped by kind.
    ///
    /// Without this flag the text report prints only a one-line count of each
    /// kind. This affects `--format text` only: JSON and SARIF output,
    /// findings, counts and exit codes are the same either way.
    #[arg(long)]
    pub(crate) show_coverage: bool,

    /// Skip the CVE lookup, and do not send the anonymous scan summary. It
    /// also overrides --inspect-remote.
    #[arg(long)]
    pub(crate) offline: bool,

    #[arg(
        long,
        help = "Do not send the anonymous scan summary. Reporting also stops with --offline, or when DO_NOT_TRACK is set to a value other than 0"
    )]
    pub(crate) no_reporting: bool,

    /// Connect to the public https MCP servers named in config files and
    /// check the tools they list. Off by default: a scan otherwise contacts
    /// no MCP server. Entries with headers, credentials in the URL or
    /// placeholders, commands, and non-public addresses are never contacted. `--offline` overrides this
    /// flag. Servers that are not contacted are listed under Coverage gaps.
    #[arg(long)]
    pub(crate) inspect_remote: bool,

    /// With --inspect-remote, write each inspected server's tool list to DIR
    /// as *.bastyn-tools.json.
    #[arg(long, value_name = "DIR", requires = "inspect_remote")]
    pub(crate) save_snapshots: Option<std::path::PathBuf>,

    /// Debugging aid: write every Python rule candidate whose value's
    /// provenance could not be proven to FILE as JSON Lines. Does not change
    /// the scan's output or exit code.
    #[arg(long, hide = true, value_name = "FILE")]
    pub(crate) debug_unresolved: Option<std::path::PathBuf>,

    /// Do not scan paths matching GLOB. Repeatable.
    ///
    /// Uses `.gitignore` syntax: `dist/` skips every directory called `dist`,
    /// `/dist` only the one at the root, `*.min.js` matches at any depth, and
    /// a leading `!` re-includes. Every path it drops is listed in the
    /// report's "Coverage gaps" section — an exclusion the report does not
    /// mention would be a place a finding could hide.
    ///
    /// Unlike `--no-ignore`, this is not about ignore files, so the two do
    /// not cancel out: an `--exclude` typed on this command line still
    /// applies under `--no-ignore`.
    #[arg(long, value_name = "GLOB")]
    pub(crate) exclude: Vec<String>,

    /// Do not honour `.gitignore`, `.ignore`, `.bastynignore` or global Git
    /// excludes.
    #[arg(long)]
    pub(crate) no_ignore: bool,

    /// Include dot-files and dot-directories.
    #[arg(long)]
    pub(crate) hidden: bool,

    /// Follow symbolic links.
    #[arg(long)]
    pub(crate) follow_symlinks: bool,

    /// Stop descending after this many directory levels.
    #[arg(long, value_name = "N")]
    pub(crate) max_depth: Option<usize>,
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use clap::{CommandFactory as _, Parser as _};

    use super::{Cli, Command, GroupBy, ProjectIdArgs, Reporter, ScanArgs};
    use bastyn_core::Framework;

    /// The `scan` arguments of a parsed command line.
    fn scan_args(cli: &Cli) -> &ScanArgs {
        match &cli.command {
            Some(Command::Scan(args)) => args,
            _ => unreachable!("these tests parse `scan`"),
        }
    }

    /// Exactly one `--group-by` value is not a crosswalk, and it is the
    /// default.
    ///
    /// If the default ever became a framework, every existing invocation would
    /// start emitting a regulatory grouping nobody asked for, into JSON a
    /// pipeline is already parsing.
    #[test]
    fn the_default_grouping_is_the_one_that_existed_before_the_flag() {
        let cli = Cli::parse_from(["bastyn", "scan"]);
        let args = scan_args(&cli);
        assert_eq!(args.group_by, GroupBy::Layer);
        assert_eq!(args.group_by.framework(), None);
    }

    /// The name typed on the command line is the name that comes back in the
    /// JSON, for every value that names a framework.
    ///
    /// Two spellings of one framework would send anyone filtering the output
    /// to a value the CLI rejects, which is a bug that only shows up in
    /// someone else's pipeline.
    #[test]
    fn every_framework_value_is_spelled_the_same_on_both_sides() {
        for (typed, framework) in [
            ("eu-ai-act", Framework::EuAiAct),
            ("nist-ai-rmf", Framework::NistAiRmf),
            ("nist-genai", Framework::NistGenAi),
        ] {
            let cli = Cli::parse_from(["bastyn", "scan", "--group-by", typed]);
            let args = scan_args(&cli);
            assert_eq!(
                args.group_by.framework(),
                Some(framework),
                "--group-by {typed} must select {}",
                framework.name()
            );
            assert_eq!(framework.id(), typed, "the two spellings have drifted");
        }
    }

    /// Every framework the core offers is reachable from the command line.
    ///
    /// A framework that exists in the crosswalk but cannot be asked for is
    /// work nobody can use.
    #[test]
    fn no_framework_is_unreachable_from_the_command_line() {
        for framework in Framework::ALL {
            let cli = Cli::parse_from(["bastyn", "scan", "--group-by", framework.id()]);
            let args = scan_args(&cli);
            assert_eq!(args.group_by.framework(), Some(framework));
        }
    }

    /// The flag's help says what the grouping is not.
    ///
    /// `--help` is where a first-time user meets this feature, and it is the
    /// one place the caveat cannot be skipped by reading only the output.
    #[test]
    fn the_help_text_refuses_to_promise_compliance() {
        let mut command = Cli::command().find_subcommand("scan").unwrap().clone();
        let rendered = command.render_long_help().to_string();
        // clap wraps to the terminal width, so an assertion about the wording
        // must not also be an assertion about where the lines broke.
        let help = rendered.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(help.contains("crosswalk"), "{rendered}");
        assert!(help.contains("cannot determine compliance"), "{rendered}");
        assert!(
            help.contains("Finding nothing does not mean an obligation is met"),
            "{rendered}"
        );
        for word in ["complies", "compliant", "certified", "audit passed"] {
            assert!(
                !help.to_lowercase().contains(word),
                "{word:?} appears in --help"
            );
        }
    }

    /// An unknown value is refused, and the error names what is accepted.
    #[test]
    fn an_unknown_grouping_is_rejected_with_the_valid_values() {
        let error = Cli::try_parse_from(["bastyn", "scan", "--group-by", "iso-42001"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("eu-ai-act"), "{error}");
        assert!(error.contains("layer"), "{error}");
    }

    /// Reporting is on unless the flag is given, and the flag does not touch
    /// `--offline`.
    #[test]
    fn no_reporting_is_a_separate_opt_out() {
        let cli = Cli::parse_from(["bastyn", "scan"]);
        assert!(!scan_args(&cli).no_reporting);
        assert!(!scan_args(&cli).offline);

        let cli = Cli::parse_from(["bastyn", "scan", "--no-reporting"]);
        assert!(scan_args(&cli).no_reporting);
        assert!(!scan_args(&cli).offline);
    }

    /// `project-id` defaults to the current directory and takes `--explain`.
    #[test]
    fn project_id_arguments_parse() {
        let cli = Cli::parse_from(["bastyn", "project-id"]);
        let Some(Command::ProjectId(ProjectIdArgs { path, explain })) = &cli.command else {
            unreachable!("parsed `project-id`");
        };
        assert_eq!(path.as_os_str(), ".");
        assert!(!explain);

        let cli = Cli::parse_from(["bastyn", "project-id", "some/dir", "--explain"]);
        let Some(Command::ProjectId(ProjectIdArgs { path, explain })) = &cli.command else {
            unreachable!("parsed `project-id`");
        };
        assert_eq!(path.as_os_str(), "some/dir");
        assert!(explain);
    }

    /// The watch flags parse, and a plain `scan` is untouched by them.
    #[test]
    fn watch_arguments_parse() {
        let cli = Cli::parse_from([
            "bastyn",
            "--watch",
            ".",
            "--reporter",
            "openclaw",
            "--report-url",
            "http://127.0.0.1:18789/hooks/agent",
            "--openclaw-agent-id",
            "main",
        ]);
        assert!(cli.command.is_none());
        assert_eq!(cli.watch.watch.as_deref(), Some(std::path::Path::new(".")));
        assert_eq!(cli.watch.reporter, Some(Reporter::Openclaw));
        assert_eq!(cli.watch.openclaw_agent_id.as_deref(), Some("main"));
        cli.validate().unwrap();
    }

    /// Each reporter flag needs the flags it depends on.
    #[test]
    fn watch_flag_dependencies_are_enforced() {
        for args in [
            vec![
                "bastyn",
                "--reporter",
                "openclaw",
                "--report-url",
                "http://127.0.0.1/x",
            ],
            vec!["bastyn", "--watch", ".", "--reporter", "openclaw"],
            vec![
                "bastyn",
                "--watch",
                ".",
                "--report-url",
                "http://127.0.0.1/x",
            ],
            vec!["bastyn", "--watch", ".", "--openclaw-agent-id", "main"],
            vec![
                "bastyn",
                "--watch",
                ".",
                "--reporter",
                "slack",
                "--report-url",
                "x",
            ],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
    }

    /// Bare `bastyn` and `--watch` with a machine format are usage errors.
    #[test]
    fn bare_and_machine_format_watch_are_refused() {
        assert!(Cli::try_parse_from(["bastyn"]).is_err());
        let cli = Cli::parse_from(["bastyn", "--quiet"]);
        assert!(cli.validate().is_err());
        for format in ["json", "sarif"] {
            let cli = Cli::parse_from(["bastyn", "--watch", ".", "--format", format]);
            let error = cli.validate().unwrap_err().to_string();
            assert!(error.contains("text only"), "{error}");
        }
        Cli::parse_from(["bastyn", "--watch", ".", "--format", "text"])
            .validate()
            .unwrap();
    }

    /// The watch flags cannot be mixed with a subcommand.
    #[test]
    fn watch_conflicts_with_subcommands() {
        assert!(Cli::try_parse_from(["bastyn", "--watch", ".", "scan"]).is_err());
    }

    /// The help says what watch mode does not do and where the token comes from.
    #[test]
    fn the_watch_help_states_its_limits() {
        let rendered = Cli::command().render_long_help().to_string();
        let help = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains("never contacts an MCP server"), "{rendered}");
        assert!(help.contains("BASTYN_OPENCLAW_TOKEN"), "{rendered}");
        assert!(help.contains("loopback"), "{rendered}");
    }
}
