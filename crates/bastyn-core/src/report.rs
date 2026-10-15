//! The report model. Every output format renders from exactly this, so JSON,
//! SARIF and the terminal can never disagree with each other.

use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// What happened to the CVE lookup.
///
/// A CVE section that silently reports nothing because it had no data reads as
/// "clean", which is the worst possible failure for a security tool. The report
/// always says which of these applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CveStatus {
    /// Queried successfully.
    Checked {
        /// How many dependencies were resolved and looked up.
        dependencies: usize,
    },
    /// Queried, but some follow-up requests failed or came back unreadable,
    /// so some dependencies' results may be missing.
    Partial {
        /// How many dependencies were looked up.
        dependencies: usize,
        /// How many of them may have advisories missing from this report.
        incomplete: usize,
    },
    /// Skipped because no dependency manifest was found.
    NoManifest,
    /// Skipped on purpose, via `--offline`.
    SkippedOffline,
    /// Skipped because the lookup could not be reached.
    Unreachable {
        /// Why, in one line, for the report.
        reason: String,
    },
}

/// Why a path is not covered by a scan.
///
/// The reason is scan-time knowledge. It used to survive only as English
/// inside the line a reader saw, which meant the report could group by it
/// solely by taking that English apart again — and prose that six formatting
/// sites write and one site re-parses drifts silently. The reason is data
/// now, and the prose is derived from it rather than the other way round.
///
/// Ordered so the report lists the deliberate exclusions before the ones the
/// scan hit by accident: a pattern the caller typed is a decision they can
/// revisit, an unreadable file is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// An `--exclude` pattern matched.
    Excluded,
    /// A `.bastynignore` was honoured.
    IgnoreFile,
    /// The bytes say the file is machine output.
    Generated,
    /// The file could not be read, or is not UTF-8.
    Unreadable,
    /// The file was read but could not be parsed.
    Unparseable,
    /// A dependency is pinned to a range, so no advisory could be matched.
    Unpinned,
    /// Read back out of a serialised report, which carries the line but not
    /// the reason.
    ///
    /// No scan produces this. [`Report::skipped`] serialises as the array of
    /// lines it has always been — a published contract — and a line does not
    /// say which of [`Self::Unreadable`] and [`Self::Unparseable`] produced
    /// it, so deserialising cannot honestly claim either. Saying "the reason
    /// was not recorded" is the only true answer, and it is a better one than
    /// guessing from the punctuation.
    Unstated,
}

impl SkipReason {
    /// The sentence that introduces a group of entries sharing this reason.
    ///
    /// `count` is interpolated, because "1 file was excluded" and "4 files
    /// were excluded" are not the same sentence and a security tool that gets
    /// that wrong invites the reader to wonder what else it did not check.
    #[must_use]
    pub fn sentence(self, count: usize) -> String {
        let plural = count != 1;
        match self {
            Self::Excluded if plural => {
                format!("{count} paths were excluded by a pattern given on the command line:")
            }
            Self::Excluded => "1 path was excluded by a pattern given on the command line:".into(),
            Self::IgnoreFile if plural => {
                format!("{count} .bastynignore files were honoured, so paths matching their patterns were not scanned:")
            }
            Self::IgnoreFile => {
                "1 .bastynignore file was honoured, so paths matching its patterns were not scanned:".into()
            }
            Self::Generated if plural => {
                format!("{count} files were not parsed because their bytes say they are generated:")
            }
            Self::Generated => {
                "1 file was not parsed because its bytes say it is generated:".into()
            }
            Self::Unreadable if plural => {
                format!("{count} files could not be read, or are not valid UTF-8:")
            }
            Self::Unreadable => "1 file could not be read, or is not valid UTF-8:".into(),
            Self::Unparseable if plural => format!("{count} files could not be parsed:"),
            Self::Unparseable => "1 file could not be parsed:".into(),
            Self::Unpinned if plural => format!(
                "{count} dependencies have unpinned versions and could not be matched to CVEs:"
            ),
            Self::Unpinned => {
                "1 dependency has an unpinned version and could not be matched to CVEs:".into()
            }
            Self::Unstated if plural => {
                format!("{count} paths were not covered, for reasons this report did not record:")
            }
            Self::Unstated => {
                "1 path was not covered, for a reason this report did not record:".into()
            }
        }
    }
}

/// Which agent files a scan covered, by kind, and what it skipped.
///
/// Every key is always serialised, except `remote_servers`, which is omitted
/// when empty (it is filled only when `--inspect-remote` ran). An empty
/// `mcp_manifests` says that no MCP configuration was parsed, which is
/// information a consumer needs and cannot get from the absence of a key.
/// Paths use forward slashes and are relative to the scanned root, in the
/// order the scan walked them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Coverage {
    /// MCP configuration files that were read and parsed. A config that was
    /// read but did not parse is not listed here: it is reported as a
    /// `BAS-MCP-000` finding instead.
    #[serde(default)]
    pub mcp_manifests: Vec<String>,
    /// `SKILL.md` files that were read.
    #[serde(default)]
    pub skill_files: Vec<String>,
    /// Text files of a skill that were scanned (`references/` and files next
    /// to the manifest): `.md`, `.markdown` and `.txt` files read and checked
    /// for the skill phrase checks and hidden Unicode. A file that could not be
    /// read is listed under `skipped` instead. Sorted by path.
    #[serde(default)]
    pub skill_reference_files: Vec<String>,
    /// Agent instruction files (such as `AGENTS.md`) that were read. An MCP
    /// configuration is listed only under `mcp_manifests`, and a `SKILL.md`
    /// only under `skill_files`, never here.
    #[serde(default)]
    pub instruction_files: Vec<String>,
    /// Files located under a skill directory (the directory of a `SKILL.md`,
    /// at any depth) that no analyser reads, such as shell scripts and
    /// images. They are present in the skill but were not inspected. A file
    /// that was skipped as unreadable or unparseable is listed under `skipped`
    /// only. For a `SKILL.md` at the scan root, only the `scripts/`,
    /// `references/` and `assets/` folders are considered, never the rest of
    /// the repository. Each file is listed once, sorted bytewise by path.
    #[serde(default)]
    pub skill_unanalysed: Vec<String>,
    /// The structured form of [`Report::skipped`]: the same entries in the
    /// same order, with the reason as data.
    #[serde(default)]
    pub skipped: Vec<CoveredSkip>,
    /// The remote server entries `--inspect-remote` considered, in config
    /// and entry order. Empty, and omitted from the JSON, unless that option
    /// ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_servers: Vec<RemoteServer>,
}

/// What happened to one remote server entry during `--inspect-remote`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteStatus {
    /// The server was contacted and its tools were checked.
    Inspected,
    /// The URL is not a public `https` address, so it was not contacted.
    NotPublic,
    /// The entry carries credentials, headers or a variable placeholder, so it
    /// was not contacted, or the server answered 401 or 403.
    NeedsCredentials,
    /// The entry is not a Streamable HTTP server: a command, or SSE. A server
    /// that turns out to use SSE is only recognised after it was contacted.
    Unsupported,
    /// The server was contacted and the capture failed.
    Unreachable,
    /// The entry was eligible but `--offline` forbids contacting it.
    Offline,
}

/// One server entry considered by `--inspect-remote`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteServer {
    /// The config file, relative to the scanned root.
    pub file: String,
    /// The entry's name in that file.
    pub server: String,
    /// What happened to it.
    pub status: RemoteStatus,
    /// Number of tools captured; present only when inspected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<usize>,
}

/// The structured form of one [`Report::skipped`] line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoveredSkip {
    /// What the entry is about, as in [`Skip::path`].
    pub path: String,
    /// Why the path is not covered.
    pub reason: SkipReason,
    /// The one thing that differs between entries sharing a reason, as in
    /// [`Skip::detail`]. Omitted when empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

impl From<&Skip> for CoveredSkip {
    fn from(skip: &Skip) -> Self {
        Self {
            path: skip.path.clone(),
            reason: skip.reason,
            detail: skip.detail.clone(),
        }
    }
}

/// One thing the scan did not cover, and why.
///
/// Serialises as the single line it has always been, because
/// [`Report::skipped`] is a published contract other tools parse. The
/// structure is what the terminal renderer groups by; the line is what the
/// JSON carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Skip {
    /// Why this path is not covered.
    pub reason: SkipReason,
    /// What the entry is about: a path, a path with a trailing `/` for a
    /// directory, or `path:line` for one entry inside a manifest.
    pub path: String,
    /// The one thing that differs between entries sharing a reason — the
    /// dependency name, the pattern that excluded it, the measurement that
    /// judged it generated. Empty when the path says everything.
    pub detail: String,
    /// The exact text this entry contributes to the serialised `skipped`
    /// array. Built by the constructors below and never assembled anywhere
    /// else, so the prose has one home.
    line: String,
}

impl Skip {
    /// A path an `--exclude` pattern removed.
    #[must_use]
    pub fn excluded(path: String, pattern: &str) -> Self {
        let line = format!("{path} \u{2014} excluded by pattern \"{pattern}\"");
        Self {
            reason: SkipReason::Excluded,
            path,
            detail: pattern.to_owned(),
            line,
        }
    }

    /// A `.bastynignore` that was honoured.
    #[must_use]
    pub fn ignore_file(path: String) -> Self {
        let line =
            format!("{path} \u{2014} honoured: paths matching its patterns were not scanned");
        Self {
            reason: SkipReason::IgnoreFile,
            path,
            detail: String::new(),
            line,
        }
    }

    /// A file whose bytes say it is machine output. `measurement` is the
    /// evidence, so a reader can disagree with the verdict without re-deriving
    /// it.
    #[must_use]
    pub fn generated(path: String, measurement: String) -> Self {
        let line = format!("{path} \u{2014} generated: {measurement}");
        Self {
            reason: SkipReason::Generated,
            path,
            detail: measurement,
            line,
        }
    }

    /// A file that could not be read, or is not UTF-8.
    #[must_use]
    pub fn unreadable(path: String) -> Self {
        Self::bare(SkipReason::Unreadable, path)
    }

    /// A file that was read but could not be parsed.
    #[must_use]
    pub fn unparseable(path: String) -> Self {
        Self::bare(SkipReason::Unparseable, path)
    }

    /// A dependency pinned to a range rather than an exact version.
    #[must_use]
    pub fn unpinned(path: String, name: String, constraint: &str) -> Self {
        let line =
            format!("{path} \u{2014} {name} {constraint} is not pinned, so CVEs were not checked");
        Self {
            reason: SkipReason::Unpinned,
            path,
            detail: name,
            line,
        }
    }

    /// An entry read back out of a serialised report.
    #[must_use]
    fn unstated(line: String) -> Self {
        Self {
            reason: SkipReason::Unstated,
            path: line.clone(),
            detail: String::new(),
            line,
        }
    }

    /// The two reasons that carry nothing but a path.
    ///
    /// Deliberately indistinguishable once written down: that is what the
    /// published contract says, and inventing a suffix for them now would
    /// change bytes other tools already parse.
    fn bare(reason: SkipReason, path: String) -> Self {
        Self {
            reason,
            line: path.clone(),
            path,
            detail: String::new(),
        }
    }

    /// The line this entry contributes to the serialised `skipped` array.
    #[must_use]
    pub fn line(&self) -> &str {
        &self.line
    }
}

/// Ordered by the serialised line first, so the report's `skipped` array is in
/// exactly the order it was before the reason became data — the array is a
/// contract, and reordering it is as much a change as reshaping it.
impl Ord for Skip {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.line
            .cmp(&other.line)
            .then_with(|| self.reason.cmp(&other.reason))
            .then_with(|| self.detail.cmp(&other.detail))
    }
}

impl PartialOrd for Skip {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for Skip {
    /// As the bare line, which is what `skipped` has always contained.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.line)
    }
}

impl<'de> Deserialize<'de> for Skip {
    /// From the bare line, with the reason honestly marked as absent — see
    /// [`SkipReason::Unstated`].
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::unstated)
    }
}

/// Counts, so a reader does not have to total the findings themselves.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Summary {
    /// Files parsed.
    pub files_scanned: usize,
    /// Entries in [`Report::skipped`]: everything the scan did not cover,
    /// whether it could not (unreadable, unparseable, an unpinned dependency)
    /// or would not (an exclude pattern, a `.bastynignore`, a file whose bytes
    /// say it is generated).
    pub files_skipped: usize,
    /// Defects found.
    pub defects: usize,
    /// Observations found.
    pub observations: usize,
}

/// The complete result of one scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The version of Bastyn that produced this.
    pub bastyn_version: String,
    /// The root that was scanned, as the user spelled it.
    pub root: String,
    /// Counts.
    pub summary: Summary,
    /// What happened to the CVE lookup.
    pub cve: CveStatus,
    /// Findings, sorted: defects first, then severity, then confidence.
    pub findings: Vec<Finding>,
    /// Everything the scan did not cover, sorted, and serialised as one line
    /// each — the array of strings this field has always been.
    ///
    /// A bare path is a file that could not be read or parsed. Anything the
    /// scan left out on purpose carries its reason after an em dash, in the
    /// same `path — why` shape an unpinned dependency already used:
    ///
    /// ```text
    /// broken.py
    /// vendor/ — excluded by pattern "vendor/"
    /// .bastynignore — honoured: paths matching its patterns were not scanned
    /// web/bundle.js — generated: minified, 65536 bytes per line on average …
    /// requirements.txt:2 — flask >=2.0 is not pinned, so CVEs were not checked
    /// ```
    ///
    /// In memory each entry is a [`Skip`], which carries the reason as data
    /// so the terminal can group by it. Deserialising gives the lines back
    /// with [`SkipReason::Unstated`], because the reason is not in the
    /// contract and guessing it from the punctuation would be a worse answer
    /// than admitting it was not recorded.
    ///
    /// Never silently dropped: a scan that quietly covered less than it
    /// claimed is a place a real finding hides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<Skip>,

    /// The paths the scan covered, per kind of agent file, and the skipped
    /// paths with their reasons as data.
    ///
    /// `coverage.skipped` is exactly [`Report::skipped`], in the same order,
    /// with the reason as a field instead of prose. `skipped` itself is
    /// unchanged because it is a published contract.
    #[serde(default)]
    pub coverage: Coverage,

    /// The findings regrouped by the areas of each compliance framework they
    /// are relevant to, one entry per framework.
    ///
    /// A vector rather than a single optional crosswalk because the default
    /// scan now produces all of them: a reader who has to remember a flag to
    /// see the EU AI Act would also have to remember a second one to see NIST,
    /// and whichever they forgot would look like an area with nothing in it.
    /// Ordered, and the order is [`crate::compliance::Framework::ALL`], so a
    /// consumer indexing into it gets the same framework on every run rather
    /// than whichever one the command line happened to name.
    ///
    /// The grouping is additive: each [`crate::compliance::Group::findings`]
    /// holds indices into [`Report::findings`], which no crosswalk reorders or
    /// rewrites, so a consumer resolves them against this report's own array
    /// and nothing else. Empty when nothing was grouped, and skipped when
    /// serialising then, so an empty key never reads as "no areas apply".
    ///
    /// A crosswalk is not a compliance verdict. [`crate::compliance::Crosswalk`]
    /// carries [`crate::compliance::DISCLAIMER`] on each value so that a
    /// consumer reading this field cannot avoid reading what it does not mean.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crosswalks: Vec<crate::compliance::Crosswalk>,
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod remote_tests {
    use super::*;

    #[test]
    fn remote_servers_are_omitted_when_empty() {
        let value = serde_json::to_value(Coverage::default()).unwrap();
        assert!(value.get("remote_servers").is_none());
        let back: Coverage = serde_json::from_value(value).unwrap();
        assert_eq!(back.remote_servers.len(), 0);
    }

    #[test]
    fn a_remote_server_serialises_with_a_snake_case_status() {
        let coverage = Coverage {
            remote_servers: vec![RemoteServer {
                file: "mcp.json".into(),
                server: "docs".into(),
                status: RemoteStatus::Inspected,
                tools: Some(3),
            }],
            ..Coverage::default()
        };
        let value = serde_json::to_value(&coverage).unwrap();
        assert_eq!(
            value["remote_servers"],
            serde_json::json!([
                {"file": "mcp.json", "server": "docs", "status": "inspected", "tools": 3}
            ])
        );
        let back: Coverage = serde_json::from_value(value).unwrap();
        assert_eq!(back, coverage);
    }

    #[test]
    fn tools_are_omitted_when_none() {
        let server = RemoteServer {
            file: "mcp.json".into(),
            server: "docs".into(),
            status: RemoteStatus::NeedsCredentials,
            tools: None,
        };
        let value = serde_json::to_value(&server).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"file": "mcp.json", "server": "docs", "status": "needs_credentials"})
        );
    }
}
