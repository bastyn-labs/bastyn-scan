//! Shared `Report` fixtures for the renderer test suites.
//!
//! Test-only: this module is compiled solely under `#[cfg(test)]` from
//! `render/mod.rs`, and its items are visible to the sibling `json`, `sarif`
//! and `stdout` test modules through ordinary Rust module privacy.

use std::path::PathBuf;

use crate::category::Category;
use crate::finding::{Confidence, Finding, Kind, Location, Severity};
use crate::report::{CveStatus, Report, Skip, SkipReason, Summary};

/// A defect: critical severity, high confidence, improper-output-handling.
pub(crate) fn defect() -> Finding {
    Finding {
        rule_id: "BAS-LLM10-001".to_string(),
        title: "Model output executed as code".to_string(),
        kind: Kind::Defect,
        severity: Severity::Critical,
        confidence: Confidence::High,
        categories: vec![Category::Llm10, Category::Zt4],
        location: Location {
            file: PathBuf::from("src/agents.py"),
            line: 81,
            column: 12,
        },
        snippet: "exec(response.text)".to_string(),
        description: "The model's raw output is passed straight to exec.".to_string(),
        remediation: "Parse the output as JSON and validate against a schema.".to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    }
}

/// An observation with severity `High` on purpose, so tests can confirm
/// observations still map to SARIF `note` regardless of severity.
pub(crate) fn observation() -> Finding {
    Finding {
        rule_id: "BAS-LLM06-001".to_string(),
        title: "No token ceiling on LLM call".to_string(),
        kind: Kind::Observation,
        severity: Severity::High,
        confidence: Confidence::Medium,
        categories: vec![Category::Llm06],
        location: Location {
            file: PathBuf::from("main.py"),
            line: 172,
            column: 1,
        },
        snippet: "client.chat.completions.create(...)".to_string(),
        description: "No max_tokens ceiling is set on this call.".to_string(),
        remediation: "Set a token ceiling appropriate to the caller.".to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    }
}

/// A defect on a Windows-style path, to prove SARIF always emits `/`.
pub(crate) fn windows_path_defect() -> Finding {
    let mut finding = defect();
    finding.rule_id = "BAS-ZT1-001".to_string();
    finding.location.file = PathBuf::from("src\\windows\\creds.rs");
    finding
}

/// A representative report: one defect, one observation, and the given CVE
/// status.
pub(crate) fn report_with(cve: CveStatus) -> Report {
    Report {
        bastyn_version: "0.1.0".to_string(),
        root: "/repo".to_string(),
        summary: Summary {
            files_scanned: 17,
            files_skipped: 0,
            defects: 1,
            observations: 1,
        },
        cve,
        findings: vec![defect(), observation()],
        skipped: Vec::new(),
        coverage: crate::report::Coverage::default(),
        crosswalks: Vec::new(),
    }
}

/// A report with two findings for one rule id and one for another, to
/// exercise SARIF rule deduplication.
pub(crate) fn duplicate_rule_report() -> Report {
    let mut second = defect();
    second.location = Location {
        file: PathBuf::from("src/other.py"),
        line: 5,
        column: 1,
    };

    Report {
        bastyn_version: "0.1.0".to_string(),
        root: "/repo".to_string(),
        summary: Summary {
            files_scanned: 2,
            files_skipped: 0,
            defects: 2,
            observations: 1,
        },
        cve: CveStatus::NoManifest,
        findings: vec![defect(), second, observation()],
        skipped: Vec::new(),
        coverage: crate::report::Coverage::default(),
        crosswalks: Vec::new(),
    }
}

/// A defect built from the parts a layering test actually cares about.
///
/// Titles are distinct across [`layered_report`] so a test can count how many
/// times one was printed and get a real answer.
fn layered_defect(
    rule_id: &str,
    title: &str,
    categories: Vec<Category>,
    file: &str,
    line: usize,
    severity: Severity,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        title: title.to_string(),
        kind: Kind::Defect,
        severity,
        confidence: Confidence::High,
        categories,
        location: Location {
            file: PathBuf::from(file),
            line,
            column: 1,
        },
        snippet: "...".to_string(),
        description: "...".to_string(),
        remediation: "...".to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    }
}

/// A defect on every layer, for the terminal renderer's grouping.
///
/// Two of them carry more than one category on purpose: `BAS-ZT4-001` names an
/// entry vector and the perimeter defense that would have stopped it, and
/// `BAS-LLM10-001` names a cross-layer threat and the same defense. Those are
/// the cases where the renderer has to choose one section and print the
/// finding exactly once.
///
/// The observation is included because it maps to `LLM06`, an `Impact`
/// category — the renderer must still keep it out of the impacts section,
/// since an observation is not something a reader has been told to fix.
pub(crate) fn layered_report() -> Report {
    let findings = vec![
        layered_defect(
            "BAS-ZT4-001",
            "Raw user input folded into a system prompt",
            vec![Category::Llm01, Category::Zt4],
            "src/prompts.py",
            26,
            Severity::High,
        ),
        layered_defect(
            "BAS-MCP-005",
            "MCP server launched without a version pin",
            vec![Category::Llm04],
            "mcp.json",
            5,
            Severity::High,
        ),
        layered_defect(
            "BAS-LLM08-001",
            "Secret embedded inside a prompt template",
            vec![Category::Llm08],
            "src/prompts.py",
            8,
            Severity::Critical,
        ),
        layered_defect(
            "BAS-LLM02-001",
            "Customer record logged in full",
            vec![Category::Llm02],
            "src/app.py",
            44,
            Severity::High,
        ),
        defect(),
        layered_defect(
            "BAS-MCP-001",
            "MCP server granted root filesystem access",
            vec![Category::Zt3],
            "mcp.json",
            5,
            Severity::High,
        ),
        layered_defect(
            "BAS-ZT1-001",
            "Hardcoded API key",
            vec![Category::Zt1],
            "src/config.py",
            13,
            Severity::Critical,
        ),
        observation(),
    ];

    Report {
        bastyn_version: "0.1.0".to_string(),
        root: "/repo".to_string(),
        summary: Summary {
            files_scanned: 6,
            files_skipped: 0,
            defects: 7,
            observations: 1,
        },
        cve: CveStatus::SkippedOffline,
        findings,
        skipped: Vec::new(),
        coverage: crate::report::Coverage::default(),
        crosswalks: Vec::new(),
    }
}

/// A report with no findings at all.
pub(crate) fn empty_report() -> Report {
    Report {
        bastyn_version: "0.1.0".to_string(),
        root: "/repo".to_string(),
        summary: Summary::default(),
        cve: CveStatus::NoManifest,
        findings: Vec::new(),
        skipped: Vec::new(),
        coverage: crate::report::Coverage::default(),
        crosswalks: Vec::new(),
    }
}

/// One entry for every reason a path can end up outside the scan.
///
/// The coverage-gap listing is the only place a reader learns that coverage
/// was narrowed, so every reason has to survive rendering. A category that
/// quietly stopped printing would be exactly the hiding place that section
/// exists to close, and no single real repository produces all six.
pub(crate) fn every_skip_reason() -> Vec<Skip> {
    vec![
        Skip::excluded("vendor/".to_owned(), "vendor/"),
        Skip::excluded("web/app.min.js".to_owned(), "*.min.js"),
        Skip::ignore_file(".bastynignore".to_owned()),
        Skip::generated(
            "web/bundle.js".to_owned(),
            "minified, 65536 bytes per line on average over the first 65536 bytes".to_owned(),
        ),
        Skip::unreadable("assets/logo.py".to_owned()),
        Skip::unparseable("broken.py".to_owned()),
        Skip::unpinned(
            "requirements.txt:18".to_owned(),
            "opentelemetry-api".to_owned(),
            "*",
        ),
    ]
}

/// A defect whose every string is longer than a terminal is wide.
///
/// The eighty-column promise is easy to keep on the fixtures above, all of
/// which happen to be short. This one has a deep path, a title that runs past
/// the wrap on its own, a paragraph of description, a paragraph of
/// remediation, and one unbreakable word longer than the line — the case a
/// space-only wrapper cannot handle.
pub(crate) fn verbose_defect() -> Finding {
    Finding {
        rule_id: "BAS-LLM10-00042".to_string(),
        title: "Model output is concatenated into a database query, a shell command and a \
template render in the same request handler, without validation at any of the three"
            .to_string(),
        kind: Kind::Defect,
        severity: Severity::Critical,
        confidence: Confidence::High,
        categories: vec![Category::Llm10, Category::Zt4, Category::Llm01, Category::Zt3],
        location: Location {
            file: PathBuf::from(
                "services/ingestion/pipelines/enrichment/handlers/generated/very_deeply_nested/\
model_output_handler_implementation.py",
            ),
            line: 1_048_576,
            column: 4,
        },
        snippet: "cursor.execute(f\"select * from t where x = '{reply}'\")".to_string(),
        description: "The handler takes the model's reply and interpolates it into a SQL \
statement, then passes the same value to a subprocess invoked through a shell, and finally \
renders it into an HTML template with autoescaping disabled. Any one of those is arbitrary \
execution in a different interpreter; together they mean a single injected instruction reaches \
three of them. See https://example.invalid/advisories/aVeryLongUnbreakableIdentifierThatNoWrapperCanSplitOnSpacesAlone \
for the write-up."
            .to_string(),
        remediation: "Stop the model's reply at the boundary of the handler. Bind it as a query \
parameter rather than concatenating it, pass it to the subprocess as one element of an argument \
vector with no shell involved, and let the template engine escape it. Each of those is a \
one-line change and none of them depends on the others, so there is no ordering to get right."
            .to_string(),
        secondary_rule_ids: Vec::new(),
        references: vec![
            "CVE-2026-00001".to_string(),
            "CVE-2026-00002".to_string(),
            "CVE-2026-00003".to_string(),
            "CVE-2026-00004".to_string(),
            "CVE-2026-00005".to_string(),
        ],
    }
}

/// A report built to break an eighty-column layout, with every skip reason in
/// it as well.
pub(crate) fn verbose_report() -> Report {
    Report {
        bastyn_version: "0.1.0".to_string(),
        root: "/a/very/long/path/to/a/repository/that/somebody/really/did/check/out/here"
            .to_string(),
        summary: Summary {
            files_scanned: 42,
            files_skipped: 7,
            defects: 2,
            observations: 1,
        },
        cve: CveStatus::Unreachable {
            reason: "the OSV endpoint did not answer within thirty seconds".to_string(),
        },
        findings: vec![verbose_defect(), defect(), observation()],
        skipped: every_skip_reason(),
        coverage: crate::report::Coverage::default(),
        crosswalks: Vec::new(),
    }
}

/// Two defects in one layer, the worse one in the alphabetically later file.
///
/// The old layout grouped by file inside a layer, so this pair printed the
/// `high` first. Severity is the order the work gets done in, and the file is
/// on the finding's own line now, so there is nothing left for the file to
/// order.
pub(crate) fn worse_finding_in_the_later_file() -> Report {
    let mut high = defect();
    high.rule_id = "BAS-LLM10-004".to_string();
    high.title = "eval() or exec() run on a non-literal expression".to_string();
    high.severity = Severity::High;
    high.location = Location {
        file: PathBuf::from("aaa_graph.py"),
        line: 138,
        column: 1,
    };

    let mut critical = defect();
    critical.rule_id = "BAS-LLM10-003".to_string();
    critical.title = "Model output concatenated into a SQL query".to_string();
    critical.severity = Severity::Critical;
    critical.location = Location {
        file: PathBuf::from("zzz_tools.py"),
        line: 214,
        column: 1,
    };

    Report {
        bastyn_version: "0.1.0".to_string(),
        root: "/repo".to_string(),
        summary: Summary {
            files_scanned: 2,
            files_skipped: 0,
            defects: 2,
            observations: 0,
        },
        cve: CveStatus::SkippedOffline,
        findings: vec![high, critical],
        skipped: Vec::new(),
        coverage: crate::report::Coverage::default(),
        crosswalks: Vec::new(),
    }
}

/// A report whose observations were counted but not collected.
///
/// What a scan without `--show-observations` produces: the findings list holds
/// only defects, and the summary still knows how many observations there were.
/// The report used to print "No observations." over the top of that count.
pub(crate) fn observations_withheld() -> Report {
    let mut report = report_with(CveStatus::SkippedOffline);
    report.summary.observations = 3;
    report
        .findings
        .retain(|finding| finding.kind == Kind::Defect);
    report
}

/// Every reason a real scan can produce.
///
/// So a test can assert the listing covers all of them rather than the handful
/// whichever fixture it happens to be holding contains.
/// [`SkipReason::Unstated`] is deliberately absent: no scan produces it, and a
/// test that expected it in rendered output would be pinning a case that
/// cannot arise.
pub(crate) const EVERY_REASON: [SkipReason; 6] = [
    SkipReason::Excluded,
    SkipReason::IgnoreFile,
    SkipReason::Generated,
    SkipReason::Unreadable,
    SkipReason::Unparseable,
    SkipReason::Unpinned,
];
