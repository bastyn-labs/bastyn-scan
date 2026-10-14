//! Container configuration inspection.
//!
//! ZT3 — no sandbox boundary, unrestricted filesystem or network reach — is
//! close to undetectable in application source, because the boundary is not
//! expressed there. It *is* expressed, mechanically and unambiguously, in
//! container configuration, which is why this module exists and why it is not
//! a set of rules in `bastyn.yml`.
//!
//! Scope is Dockerfiles and Docker Compose, and nothing else. Of 65 real
//! third-party AI repositories we measured, 38% carry a Dockerfile; Terraform
//! appears in three of them and genuine Kubernetes manifests total 21 files
//! across the whole corpus. Support for those is not here because the evidence
//! does not yet ask for it.
//!
//! # Checks
//!
//! | Rule | What it flags | Kind | Category |
//! | --- | --- | --- | --- |
//! | `BAS-INFRA-001` | `USER root` as the effective final user | defect | `ZT3` |
//! | `BAS-INFRA-001` | No `USER` instruction at all | observation | `ZT3` |
//! | `BAS-INFRA-002` | A provider API key literal in `ENV` or `ARG` | defect | `ZT1` |
//! | `BAS-INFRA-003` | A volume mounting `/var/run/docker.sock` | defect | `ZT3` |
//! | `BAS-INFRA-004` | `privileged: true` | defect | `ZT3` |
//! | `BAS-INFRA-005` | `network_mode: host` | observation | `ZT3` |
//! | `BAS-INFRA-006` | A hardcoded password/secret/token in `ENV`/`ARG` or Compose `environment:` | defect | `ZT1` |
//! | `BAS-INFRA-010` | `pid: host` | observation | `ZT3` |
//!
//! # ZT3.1 and ZT3.2 are mostly already here
//!
//! The rule catalogue's ZT3.1 ("a code-exec sandbox container runs
//! `privileged: true`") and ZT3.2 ("an MCP/agent container bind-mounts the
//! Docker socket or shares the host network/PID namespace") describe checks
//! that, for the most part, already existed here before those catalogue
//! entries were written: `BAS-INFRA-004` fires on `privileged: true`
//! unconditionally (not narrowed to services classified as "a sandbox",
//! which is a strictly stronger signal than the catalogue asks for), and
//! `BAS-INFRA-003`/`BAS-INFRA-005` already cover the Docker-socket and
//! host-network halves of ZT3.2. `BAS-INFRA-010` closes the one gap that was
//! left: the host PID namespace.
//!
//! # Why two kinds under one rule id
//!
//! Most Dockerfiles in the wild carry no `USER` instruction: 35 of the 57 the
//! scan reaches in our calibration corpus. Reporting each one as a defect
//! would be the exact noise this scanner exists to avoid, and it would drown
//! the one case that is unambiguous — a Dockerfile that explicitly ends as
//! root. So absence is an observation, hidden unless asked for, and an
//! explicit choice of root is a defect.
//!
//! The same line separates `BAS-INFRA-004` from `BAS-INFRA-005`: a privileged
//! container and a mounted Docker socket are escapes in every deployment,
//! while sharing the host network stack is how a sidecar is normally run.

mod compose;
mod dockerfile;

pub(crate) use compose::DOCKER_SOCKET;

use std::path::Path;

use crate::finding::Finding;

/// True if this path is a container configuration file we know how to inspect.
#[must_use]
pub fn is_infra_file(path: &Path) -> bool {
    kind_of(path).is_some()
}

/// Which analyser claims this path, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Dockerfile,
    Compose,
}

/// Extensions that settle the question against a file whose name otherwise
/// looks like a Dockerfile. All three sit beside a real Dockerfile somewhere
/// in the calibration corpus — `Dockerfile-deploy.dockerignore`,
/// `DOCKERFILE_SECURITY_ASSESSMENT_2025-12-21.md`, `docker-compose.md` — and a
/// prefix match alone claims every one of them.
const NEVER_DOCKERFILE_EXTENSIONS: &[&str] = &[
    "dockerignore",
    "md",
    "txt",
    "json",
    "yaml",
    "yml",
    "toml",
    "lock",
    "log",
];

fn kind_of(path: &Path) -> Option<FileKind> {
    let name = path.file_name().and_then(|name| name.to_str())?;
    let lower = name.to_ascii_lowercase();

    if is_compose_name(&lower) {
        return Some(FileKind::Compose);
    }
    if is_dockerfile_name(&lower) {
        return Some(FileKind::Dockerfile);
    }
    None
}

/// True for `docker-compose.yml`, `compose.yaml`, and the
/// `docker-compose.<variant>.yml` overlay convention.
///
/// The YAML extension is required, which is what keeps `docker-compose.md`
/// — a document *about* a compose file — out.
fn is_compose_name(lower_name: &str) -> bool {
    let Some(stem) = lower_name
        .strip_suffix(".yml")
        .or_else(|| lower_name.strip_suffix(".yaml"))
    else {
        return false;
    };
    stem == "compose"
        || stem == "docker-compose"
        || stem.starts_with("compose.")
        || stem.starts_with("docker-compose.")
}

/// True for the Dockerfile naming conventions in the wild: the bare name, the
/// `Dockerfile.<variant>` and `Dockerfile-<variant>` suffixes, and the
/// `<variant>.dockerfile` form some editors prefer.
///
/// Matching is on the file name because a Dockerfile has no extension, so
/// `SourceLanguage::from_path` cannot route it.
fn is_dockerfile_name(lower_name: &str) -> bool {
    if lower_name.ends_with(".dockerfile") {
        return true;
    }
    let Some(rest) = lower_name.strip_prefix("dockerfile") else {
        return false;
    };
    if !(rest.is_empty() || rest.starts_with('.') || rest.starts_with('-')) {
        return false;
    }
    let extension = rest.rsplit('.').next().unwrap_or("");
    !NEVER_DOCKERFILE_EXTENSIONS.contains(&extension)
}

/// Why [`inspect`] could not analyse a file it claims.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InfraError {
    /// A Compose file is not valid YAML, so none of its services were
    /// checked.
    #[error("the Compose file is not valid YAML")]
    UnparseableCompose,
}

/// Inspect one container configuration file. `relative_path` is used in
/// findings, and its file name selects the analyser.
///
/// A Dockerfile is never an error: there is no I/O here, and a Dockerfile we
/// cannot make sense of still yields whatever findings its own checks could
/// establish. A Compose file that does not parse is different — unlike an
/// MCP config, whose name promises a schema and is itself worth reporting as
/// `BAS-MCP-000`, a Compose file's checks simply have no services to look
/// at — but the scan still needs to know it did not get to check the file,
/// so the caller can list it as skipped rather than count it as covered.
///
/// A path this module does not claim yields `Ok(Vec::new())`, so a caller
/// that has not consulted [`is_infra_file`] still gets a correct answer.
pub fn inspect(relative_path: &Path, contents: &str) -> Result<Vec<Finding>, InfraError> {
    match kind_of(relative_path) {
        Some(FileKind::Dockerfile) => Ok(dockerfile::run_all(relative_path, contents)),
        Some(FileKind::Compose) => compose::run_all(relative_path, contents),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    use crate::finding::Kind;

    fn rules(name: &str, contents: &str) -> Vec<String> {
        inspect(Path::new(name), contents)
            .unwrap()
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect()
    }

    #[test]
    fn recognises_dockerfile_names() {
        for name in [
            "Dockerfile",
            "dockerfile",
            "DockerFile",
            "Dockerfile.dev",
            "Dockerfile.worker",
            "Dockerfile-deploy",
            "app.dockerfile",
            "deploy/Dockerfile",
            ".devcontainer/Dockerfile.dev",
        ] {
            assert_eq!(
                kind_of(Path::new(name)),
                Some(FileKind::Dockerfile),
                "{name} should be read as a Dockerfile"
            );
        }
    }

    #[test]
    fn rejects_files_that_merely_mention_docker() {
        // Every one of these sits next to a real Dockerfile in the calibration
        // corpus. A prefix match alone would claim all of them.
        for name in [
            "Dockerfile-deploy.dockerignore",
            ".dockerignore",
            "DOCKERFILE_SECURITY_ASSESSMENT_2025-12-21.md",
            "docker-compose.md",
            "docker/README.md",
        ] {
            assert_eq!(kind_of(Path::new(name)), None, "{name} was wrongly claimed");
        }
    }

    #[test]
    fn recognises_compose_names() {
        for name in [
            "docker-compose.yml",
            "docker-compose.yaml",
            "docker-compose.offline.yml",
            "compose.yaml",
            "compose.yml",
            "deploy/docker-compose.yml",
        ] {
            assert_eq!(
                kind_of(Path::new(name)),
                Some(FileKind::Compose),
                "{name} should be read as a Compose file"
            );
        }
    }

    #[test]
    fn does_not_claim_ordinary_yaml() {
        for name in ["config.yaml", "ci.yml", ".github/workflows/build.yml"] {
            assert_eq!(kind_of(Path::new(name)), None, "{name} was wrongly claimed");
        }
    }

    #[test]
    fn is_infra_file_agrees_with_the_dispatch_table() {
        assert!(is_infra_file(Path::new("Dockerfile")));
        assert!(is_infra_file(Path::new("docker-compose.yml")));
        assert!(!is_infra_file(Path::new("src/main.py")));
    }

    /// No file may be claimed by two analysers: `scan.rs` runs each one it
    /// claims, so an overlap is a doubly-reported file, and the order the
    /// analysers happen to run in would decide which finding won
    /// deduplication.
    #[test]
    fn no_infra_file_is_also_claimed_by_the_mcp_or_cve_analysers() {
        for name in [
            "Dockerfile",
            "Dockerfile.dev",
            "app.dockerfile",
            "docker-compose.yml",
            "compose.yaml",
        ] {
            let path = Path::new(name);
            assert!(
                !crate::mcp::is_mcp_config(path),
                "{name} is claimed by both infra and mcp"
            );
            assert!(
                !crate::cve::is_manifest(path),
                "{name} is claimed by both infra and cve"
            );
        }

        for name in [
            "mcp.json",
            ".mcp.yaml",
            "claude_desktop_config.json",
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "Cargo.toml",
        ] {
            assert!(
                !is_infra_file(Path::new(name)),
                "{name} is claimed by both infra and another analyser"
            );
        }
    }

    #[test]
    fn a_compose_file_that_is_not_yaml_is_an_error() {
        let result = inspect(
            Path::new("compose.yaml"),
            "services:\n  app: [\n    privileged: true\n",
        );
        assert_eq!(result, Err(InfraError::UnparseableCompose));
    }

    #[test]
    fn an_empty_compose_file_is_silent_not_an_error() {
        assert_eq!(inspect(Path::new("compose.yaml"), ""), Ok(Vec::new()));
    }

    #[test]
    fn a_compose_file_without_services_is_silent_not_an_error() {
        assert_eq!(
            inspect(
                Path::new("docker-compose.yml"),
                "version: '3'\nx-anchors: {}\n"
            ),
            Ok(Vec::new())
        );
    }

    #[test]
    fn a_dockerfile_is_routed_to_the_dockerfile_checks() {
        let contents =
            "FROM python:3.12\nENV OPENAI_API_KEY=sk-proj-9f2b7d41c6a8e35019bd\nUSER root\n";

        let mut found = rules("deploy/Dockerfile", contents);
        found.sort();

        assert_eq!(found, ["BAS-INFRA-001", "BAS-INFRA-002"]);
    }

    #[test]
    fn a_compose_file_is_routed_to_the_compose_checks() {
        let contents = "services:\n  agent:\n    privileged: true\n    network_mode: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n";

        let mut found = rules("docker-compose.yml", contents);
        found.sort();

        assert_eq!(found, ["BAS-INFRA-003", "BAS-INFRA-004", "BAS-INFRA-005"]);
    }

    #[test]
    fn an_unclaimed_path_yields_nothing_even_with_dockerfile_content() {
        assert_eq!(
            rules("notes.md", "FROM python:3.12\nUSER root\n"),
            Vec::<String>::new()
        );
    }

    /// The precision-preserving decision in this module, asserted rather than
    /// described: choosing root is a defect, and the far more common case of
    /// saying nothing at all is not.
    #[test]
    fn only_the_context_dependent_checks_are_observations() {
        let observation_rules: Vec<(&str, &str)> = vec![
            ("Dockerfile", "FROM python:3.12\nCMD [\"python\"]\n"),
            (
                "docker-compose.yml",
                "services:\n  agent:\n    network_mode: host\n",
            ),
        ];
        for (name, contents) in observation_rules {
            let findings = inspect(Path::new(name), contents).unwrap();
            assert!(
                findings.iter().all(|f| f.kind == Kind::Observation),
                "{name}: {findings:#?}"
            );
        }

        let defect_rules: Vec<(&str, &str)> = vec![
            ("Dockerfile", "FROM python:3.12\nUSER root\n"),
            (
                "docker-compose.yml",
                "services:\n  a:\n    privileged: true\n",
            ),
            (
                "docker-compose.yml",
                "services:\n  a:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
            ),
        ];
        for (name, contents) in defect_rules {
            let findings = inspect(Path::new(name), contents).unwrap();
            assert!(!findings.is_empty(), "{name} produced nothing");
            assert!(
                findings.iter().all(|f| f.kind == Kind::Defect),
                "{name}: {findings:#?}"
            );
        }
    }

    /// Every category these rules claim must be one a defect is allowed to
    /// carry. `Category::is_context_dependent` marks the four that may only
    /// ever be observations, and rule loading rejects a defect on one of
    /// them — a check written in YAML gets that for free, and a check written
    /// in Rust has to assert it.
    #[test]
    fn no_defect_claims_a_context_dependent_category() {
        let samples = [
            (
                "Dockerfile",
                "FROM python:3.12\nUSER root\nENV K=sk-proj-9f2b7d41c6a8e35019bd\n",
            ),
            (
                "docker-compose.yml",
                "services:\n  a:\n    privileged: true\n    network_mode: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
            ),
        ];
        for (name, contents) in samples {
            for finding in inspect(Path::new(name), contents).unwrap() {
                assert!(!finding.categories.is_empty(), "{finding:#?}");
                if finding.kind == Kind::Defect {
                    assert!(
                        finding
                            .categories
                            .iter()
                            .all(|category| !category.is_context_dependent()),
                        "{finding:#?}"
                    );
                }
            }
        }
    }
}
