//! Docker Compose checks: `BAS-INFRA-003`, `BAS-INFRA-004`, `BAS-INFRA-005`,
//! `BAS-INFRA-006`, `BAS-INFRA-010`.

use std::path::Path;

use serde_yaml_ng::Value;

use crate::category::Category;
use crate::credential;
use crate::finding::{Confidence, Finding, Kind, Location, Severity};
use crate::mcp::checks::locate;

/// The one host path that is a container escape wherever it is mounted:
/// writing to it drives the Docker daemon, which runs as root on the host.
pub(crate) const DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Run every Compose check against every service, in service-name order so
/// two runs over one file always produce findings in the same order.
///
/// A file that parses but has no `services` map yields `Ok(Vec::new())`
/// rather than an error: templated or generated files often carry that
/// shape and still deserve to be read silently, the same way a `services:`
/// map with nothing worth flagging in it does. Invalid YAML is different —
/// no check here can even look at the file — so it comes back as
/// [`super::InfraError::UnparseableCompose`], the same treatment an
/// unparseable MCP config or manifest gets, so the caller can list the file
/// as skipped rather than count it as covered.
pub(super) fn run_all(
    relative_path: &Path,
    contents: &str,
) -> Result<Vec<Finding>, super::InfraError> {
    let document = serde_yaml_ng::from_str::<Value>(contents)
        .map_err(|_| super::InfraError::UnparseableCompose)?;
    let Some(services) = document.get("services").and_then(Value::as_mapping) else {
        return Ok(Vec::new());
    };

    let mut named: Vec<(&str, &Value)> = services
        .iter()
        .filter_map(|(name, service)| Some((name.as_str()?, service)))
        .collect();
    named.sort_by_key(|(name, _)| *name);

    let mut findings = Vec::new();
    for (name, service) in named {
        findings.extend(check_docker_socket(name, service, relative_path, contents));
        findings.extend(check_privileged(name, service, relative_path, contents));
        findings.extend(check_host_network(name, service, relative_path, contents));
        findings.extend(check_host_pid(name, service, relative_path, contents));
        findings.extend(check_environment_credentials(
            name,
            service,
            relative_path,
            contents,
        ));
    }
    Ok(findings)
}

/// `BAS-INFRA-003` — a service that mounts the Docker socket.
///
/// This is not a weakened boundary, it is the absence of one: a process that
/// can talk to the daemon can start a new container with the host filesystem
/// mounted and become root on the host. `:ro` changes nothing, because the
/// API is driven by writing to the socket either way.
fn check_docker_socket(
    name: &str,
    service: &Value,
    relative_path: &Path,
    contents: &str,
) -> Vec<Finding> {
    let Some(volumes) = service.get("volumes").and_then(Value::as_sequence) else {
        return Vec::new();
    };

    volumes
        .iter()
        .filter(|volume| mounts_docker_socket(volume))
        .map(|_| {
            let (line, snippet) = locate_in_service(contents, name, DOCKER_SOCKET);
            Finding {
                rule_id: "BAS-INFRA-003".to_owned(),
                title: "Service mounts the Docker socket".to_owned(),
                kind: Kind::Defect,
                severity: Severity::Critical,
                confidence: Confidence::High,
                categories: vec![Category::Zt3],
                location: location(relative_path, line),
                snippet,
                description: format!(
                    "Service `{name}` mounts `{DOCKER_SOCKET}`, which is full control of the \
                     Docker daemon. Anything running in this container — including a tool an \
                     agent chooses to call — can start a privileged container and take the host."
                ),
                remediation: "Remove the socket mount. If the service genuinely needs to manage \
                     containers, put a scoped proxy in front of the daemon that exposes only \
                     the endpoints it uses, and never mount the raw socket."
                    .to_owned(),
                secondary_rule_ids: Vec::new(),
                references: Vec::new(),
            }
        })
        .collect()
}

/// True if this volume entry binds the Docker socket, in either the short
/// `source:target[:mode]` form or the long `{type, source, target}` form.
fn mounts_docker_socket(volume: &Value) -> bool {
    let source = match volume {
        Value::String(short) => short.split(':').next().unwrap_or_default(),
        Value::Mapping(_) => volume
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        _ => return false,
    };
    source.trim() == DOCKER_SOCKET
}

/// `BAS-INFRA-004` — a privileged service.
///
/// `privileged: true` drops every capability restriction, seccomp filter and
/// device restriction at once. It is a container escape in every deployment,
/// so there is nothing here for context to soften.
fn check_privileged(
    name: &str,
    service: &Value,
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    if !is_true(service.get("privileged")?) {
        return None;
    }
    let (line, snippet) = locate_in_service(contents, name, "privileged");

    Some(Finding {
        rule_id: "BAS-INFRA-004".to_owned(),
        title: "Service runs privileged".to_owned(),
        kind: Kind::Defect,
        severity: Severity::Critical,
        confidence: Confidence::High,
        categories: vec![Category::Zt3],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "Service `{name}` sets `privileged: true`, which removes the capability, seccomp \
             and device restrictions that make a container a boundary at all. Escaping to the \
             host from here is a documented one-liner, not an exploit."
        ),
        remediation: "Drop `privileged: true` and grant only what the workload needs — specific \
             `cap_add` entries, or a single `devices` mapping. If nothing can be named, the \
             workload does not belong in a container."
            .to_owned(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    })
}

/// True for YAML `true` and for the string `"true"`, which is what a quoted
/// or interpolated value deserialises to.
fn is_true(value: &Value) -> bool {
    value.as_bool() == Some(true) || value.as_str().is_some_and(|text| text == "true")
}

/// `BAS-INFRA-005` — a service on the host network.
///
/// An observation, not a defect. `network_mode: host` is how a metrics agent,
/// a sidecar, or anything doing service discovery on the host is normally
/// deployed. It does remove a boundary, and the repository cannot show whether
/// removing it was wrong.
fn check_host_network(
    name: &str,
    service: &Value,
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    if service.get("network_mode")?.as_str()?.trim() != "host" {
        return None;
    }
    let (line, snippet) = locate_in_service(contents, name, "network_mode");

    Some(Finding {
        rule_id: "BAS-INFRA-005".to_owned(),
        title: "Service shares the host network namespace".to_owned(),
        kind: Kind::Observation,
        severity: Severity::Low,
        confidence: Confidence::High,
        categories: vec![Category::Zt3],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "Service `{name}` uses `network_mode: host`, so it reaches every port bound on the \
             host, including services that only listen on loopback. Normal for a metrics or \
             discovery sidecar; a wide reach for an agent that runs model-chosen tools."
        ),
        remediation: "If the service does not need to see the host's own listeners, put it on a \
             Compose network and publish only the ports it serves."
            .to_owned(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    })
}

/// `BAS-INFRA-010` — a service on the host PID namespace.
///
/// An observation, for the same reason `BAS-INFRA-005` is: `pid: host` is how
/// a process-monitoring, debugging, or `docker top`-style sidecar is normally
/// deployed, and the repository cannot show whether sharing the namespace was
/// the wrong call for this service. What it does grant is real — every
/// process on the host becomes visible (and, with the right capabilities,
/// signalable) from inside the container — which is why it is worth surfacing
/// at all, just not as an unconditional defect the way `BAS-INFRA-003` and
/// `BAS-INFRA-004` are.
fn check_host_pid(
    name: &str,
    service: &Value,
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    if service.get("pid")?.as_str()?.trim() != "host" {
        return None;
    }
    let (line, snippet) = locate_in_service(contents, name, "pid");

    Some(Finding {
        rule_id: "BAS-INFRA-010".to_owned(),
        title: "Service shares the host PID namespace".to_owned(),
        kind: Kind::Observation,
        severity: Severity::Low,
        confidence: Confidence::High,
        categories: vec![Category::Zt3],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "Service `{name}` uses `pid: host`, so every process on the host is visible from \
             inside the container. Normal for a monitoring or debugging sidecar; a wide reach \
             for an agent that runs model-chosen tools."
        ),
        remediation: "If the service does not need to see host processes, remove `pid: host` \
             and let it keep its own PID namespace."
            .to_owned(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    })
}

/// `BAS-INFRA-006` — a hardcoded credential in a service's `environment:`
/// block.
///
/// Covers both Compose forms: the list of `NAME=value` strings and the
/// mapping form. A value is reported only when it is a real literal — not an
/// interpolation (`${DB_PASSWORD}`, the correct pattern), not empty, not a
/// boolean/numeric flag that merely sits on a credential-named key, and not
/// an obvious documentation placeholder. See [`credential`] for the shared
/// judgment, which the Dockerfile `ENV`/`ARG` check under the same rule id
/// reuses rather than duplicates.
fn check_environment_credentials(
    name: &str,
    service: &Value,
    relative_path: &Path,
    contents: &str,
) -> Vec<Finding> {
    let Some(environment) = service.get("environment") else {
        return Vec::new();
    };

    environment_pairs(environment)
        .into_iter()
        .filter(|(key, _)| credential::looks_like_credential_key(key))
        .filter(|(_, value)| credential::is_hardcoded_credential_value(value))
        .map(|(key, value)| {
            let (line, snippet) = locate_in_service(contents, name, &key);
            Finding {
                rule_id: "BAS-INFRA-006".to_owned(),
                title: "Hardcoded credential in deployment configuration".to_owned(),
                kind: Kind::Defect,
                severity: credential::credential_severity(&key, &value),
                confidence: Confidence::High,
                categories: vec![Category::Zt1],
                location: location(relative_path, line),
                snippet,
                description: format!(
                    "Service `{name}` sets `{key}` to a literal credential in \
                     `environment:`. Whatever `docker compose up` reads for this value is \
                     exactly what runs — a real password, not documentation — and it ships \
                     with every clone of the repo."
                ),
                remediation: format!(
                    "Read `{key}` from the real environment instead: `{key}: ${{{key}}}`, an \
                     `.env` file kept out of version control, or a secret manager. Rotate the \
                     credential that leaked into history."
                ),
                secondary_rule_ids: Vec::new(),
                references: Vec::new(),
            }
        })
        .collect()
}

/// The `NAME=value` pairs an `environment:` value declares, in either
/// Compose form. An entry with no value at all (`- SOME_VAR`, meaning
/// "pass through from the host") yields nothing — there is no literal to
/// judge.
fn environment_pairs(environment: &Value) -> Vec<(String, String)> {
    match environment {
        Value::Mapping(map) => map
            .iter()
            .filter_map(|(key, value)| Some((key.as_str()?.to_owned(), value.as_str()?.to_owned())))
            .collect(),
        Value::Sequence(items) => items
            .iter()
            .filter_map(|item| {
                let (key, value) = item.as_str()?.split_once('=')?;
                Some((key.to_owned(), value.to_owned()))
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The line one service's offending key sits on.
///
/// [`locate`] finds the *first* occurrence of a needle anywhere in the file,
/// which is the wrong line as soon as two services carry the same flag — and
/// two findings at one location deduplicate down to one, silently dropping a
/// real problem. Anchoring on the service's own key first, then scanning
/// forward, keeps them apart. [`locate`] still supplies both the anchor and
/// the fallback for a needle the raw text does not contain, which happens when
/// a value arrives through a YAML anchor or an `extends`.
fn locate_in_service(contents: &str, service: &str, needle: &str) -> (usize, String) {
    let (anchor, _) = locate(contents, &format!("{service}:"));
    contents
        .lines()
        .enumerate()
        .skip(anchor.saturating_sub(1))
        .find(|(_, line)| line.contains(needle))
        .map_or_else(
            || locate(contents, needle),
            |(index, line)| (index + 1, line.trim().to_owned()),
        )
}

fn location(relative_path: &Path, line: usize) -> Location {
    Location {
        file: relative_path.to_path_buf(),
        line,
        column: 1,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    fn rules(contents: &str) -> Vec<String> {
        run_all(Path::new("docker-compose.yml"), contents)
            .unwrap()
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect()
    }

    #[test]
    fn malformed_yaml_is_reported_as_unparseable_and_does_not_panic() {
        // Every repository has a broken YAML file somewhere. A compose file
        // we cannot read cannot be checked for the container boundary it
        // claims to describe, so it comes back as an error — the same
        // treatment an unparseable MCP config or manifest gets.
        for broken in [
            "services:\n  web:\n    privileged: true\n   bad indent: yes\n",
            "\tservices:\n",
            "services: [unclosed\n",
            "%YAML 9.9\n---\nservices: {}\n",
        ] {
            assert_eq!(
                run_all(Path::new("docker-compose.yml"), broken),
                Err(crate::infra::InfraError::UnparseableCompose),
                "{broken:?} did not report as unparseable"
            );
        }
    }

    #[test]
    fn a_yaml_file_without_services_is_not_a_compose_file() {
        assert_eq!(
            rules("name: something-else\nfoo: bar\n"),
            Vec::<String>::new()
        );
        assert_eq!(rules(""), Vec::<String>::new());
    }

    #[test]
    fn a_docker_socket_mount_is_a_defect() {
        let contents = "services:\n  agent:\n    image: app\n    volumes:\n      - ./data:/data\n      - /var/run/docker.sock:/var/run/docker.sock\n";

        let findings = run_all(Path::new("docker-compose.yml"), contents).unwrap();

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-INFRA-003");
        assert_eq!(findings[0].kind, Kind::Defect);
        assert_eq!(findings[0].categories, vec![Category::Zt3]);
        assert_eq!(findings[0].location.line, 6);
    }

    #[test]
    fn a_read_only_or_long_form_socket_mount_is_still_a_defect() {
        // `:ro` on the docker socket buys nothing — the API is reached by
        // writing to it, and the daemon runs as root either way.
        let read_only = "services:\n  agent:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro\n";
        assert_eq!(rules(read_only), ["BAS-INFRA-003"]);

        let long_form = "services:\n  agent:\n    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /var/run/docker.sock\n";
        assert_eq!(rules(long_form), ["BAS-INFRA-003"]);
    }

    #[test]
    fn ordinary_volumes_are_not_flagged() {
        let contents = "services:\n  agent:\n    volumes:\n      - ./src:/app/src\n      - memory_data:/data/memory\n      - /var/run/postgres.sock:/tmp/postgres.sock\n";

        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }

    #[test]
    fn privileged_true_is_a_defect() {
        let contents = "services:\n  agent:\n    image: app\n    privileged: true\n";

        let findings = run_all(Path::new("docker-compose.yml"), contents).unwrap();

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-INFRA-004");
        assert_eq!(findings[0].kind, Kind::Defect);
        assert_eq!(findings[0].location.line, 4);
    }

    #[test]
    fn privileged_false_or_absent_is_not_a_finding() {
        assert_eq!(
            rules("services:\n  agent:\n    privileged: false\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            rules("services:\n  agent:\n    image: app\n"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn network_mode_host_is_an_observation_not_a_defect() {
        // Sharing the host network stack is how a sidecar or a metrics agent
        // is normally deployed. It removes a boundary, but the repository
        // cannot show that removing it was wrong.
        let contents = "services:\n  agent:\n    image: app\n    network_mode: host\n";

        let findings = run_all(Path::new("docker-compose.yml"), contents).unwrap();

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-INFRA-005");
        assert_eq!(findings[0].kind, Kind::Observation);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].location.line, 4);
    }

    #[test]
    fn other_network_modes_are_not_flagged() {
        for mode in ["bridge", "none", "service:db", "container:other"] {
            let contents = format!("services:\n  agent:\n    network_mode: {mode}\n");
            assert!(rules(&contents).is_empty(), "{mode} was wrongly flagged");
        }
    }

    #[test]
    fn pid_host_is_an_observation_not_a_defect() {
        // Same reasoning as network_mode: host — sharing the host PID
        // namespace is how a process-monitoring or debugging sidecar is
        // normally deployed. It removes a boundary, but the repository
        // cannot show that removing it was wrong for this service.
        let contents = "services:\n  agent:\n    image: app\n    pid: host\n";

        let findings = run_all(Path::new("docker-compose.yml"), contents).unwrap();

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-INFRA-010");
        assert_eq!(findings[0].kind, Kind::Observation);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].categories, vec![Category::Zt3]);
        assert_eq!(findings[0].location.line, 4);
    }

    #[test]
    fn other_pid_modes_are_not_flagged() {
        for mode in ["service:db", "container:other"] {
            let contents = format!("services:\n  agent:\n    pid: {mode}\n");
            assert!(rules(&contents).is_empty(), "{mode} was wrongly flagged");
        }
        // No `pid:` key at all is the overwhelmingly common case.
        assert_eq!(
            rules("services:\n  agent:\n    image: app\n"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn each_offending_service_gets_its_own_line() {
        // Two services with the same flag must not both point at the first
        // occurrence — deduplication would then silently drop one of them.
        let contents = "services:\n  one:\n    privileged: true\n  two:\n    privileged: true\n";

        let findings = run_all(Path::new("docker-compose.yml"), contents).unwrap();

        let mut lines: Vec<usize> = findings.iter().map(|f| f.location.line).collect();
        lines.sort_unstable();
        assert_eq!(lines, [3, 5], "{findings:#?}");
    }

    #[test]
    fn findings_are_ordered_by_service_name() {
        let contents =
            "services:\n  zebra:\n    privileged: true\n  alpha:\n    privileged: true\n";

        let findings = run_all(Path::new("docker-compose.yml"), contents).unwrap();

        assert_eq!(findings.len(), 2);
        assert!(findings[0].description.contains("alpha"), "{findings:#?}");
    }

    #[test]
    fn a_service_that_is_null_does_not_stop_the_others_being_checked() {
        // Real compose files carry commented-out or placeholder services.
        let contents = "services:\n  placeholder:\n  agent:\n    privileged: true\n";

        assert_eq!(rules(contents), ["BAS-INFRA-004"]);
    }

    #[test]
    fn a_hardcoded_weak_password_in_the_list_form_is_a_defect() {
        // Verbatim shape from the head-to-head benchmark against a Python
        // prototype: a real docker-compose file shipping default MySQL
        // credentials.
        let contents = "services:\n  db:\n    image: mysql:8\n    environment:\n      - MYSQL_ROOT_PASSWORD=aa123456\n";

        let findings = run_all(Path::new("docker-compose.yml"), contents).unwrap();

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-INFRA-006");
        assert_eq!(findings[0].kind, Kind::Defect);
        assert_eq!(findings[0].categories, vec![Category::Zt1]);
        assert_eq!(findings[0].location.line, 5);
    }

    #[test]
    fn a_hardcoded_token_in_the_mapping_form_is_a_defect() {
        let contents = "services:\n  agent:\n    environment:\n      SERVICE_TOKEN: 'svc_4f8a1c62d90b47e3a5216fbc8de07394'\n";

        assert_eq!(rules(contents), ["BAS-INFRA-006"]);
    }

    #[test]
    fn an_environment_interpolation_is_the_correct_pattern_and_not_flagged() {
        for value in ["${DB_PASSWORD}", "$DB_PASSWORD"] {
            let contents =
                format!("services:\n  db:\n    environment:\n      - MYSQL_PASSWORD={value}\n");
            assert!(rules(&contents).is_empty(), "{value} was wrongly flagged");
        }
    }

    #[test]
    fn an_empty_credential_value_is_not_flagged() {
        let contents = "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: \"\"\n";

        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }

    #[test]
    fn a_documented_placeholder_is_not_flagged() {
        let contents = "services:\n  db:\n    environment:\n      MYSQL_PASSWORD: changeme\n";

        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }

    #[test]
    fn a_boolean_flag_on_a_credential_named_key_is_not_flagged() {
        // MYSQL_ALLOW_EMPTY_PASSWORD contains "PASSWORD" but its value is a
        // boolean flag, not a credential.
        let contents =
            "services:\n  db:\n    environment:\n      MYSQL_ALLOW_EMPTY_PASSWORD: \"yes\"\n";

        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }

    #[test]
    fn a_storage_mode_setting_on_a_secret_named_key_is_not_flagged_but_a_real_value_nearby_is() {
        // Verbatim shape from the community benchmark: a key containing
        // SECRETKEY whose value is a mode word, two lines above the real
        // hardcoded secret on a differently-named key.
        let contents = "services:\n  agent:\n    environment:\n      SECRETKEY_STORAGE_TYPE: local\n      SECRETKEY_PATH: /root/.agent\n      AGENT_SECRETKEY_OVERWRITE: \"agent-demo-2026\"\n";

        let findings = run_all(Path::new("docker-compose.yml"), contents).unwrap();

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-INFRA-006");
        assert!(
            findings[0]
                .description
                .contains("AGENT_SECRETKEY_OVERWRITE"),
            "{findings:#?}"
        );
    }

    #[test]
    fn ordinary_non_credential_environment_variables_are_not_flagged() {
        let contents = "services:\n  agent:\n    environment:\n      - AGENT_ROLE=operator\n      - MYSQL_DATABASE=runbook\n      - PORT=8080\n";

        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }

    #[test]
    fn a_bare_pass_through_variable_with_no_value_is_not_flagged() {
        // `- MYSQL_PASSWORD` with no `=value` reads the value from the host
        // shell at `docker compose up` time; there is no literal to judge.
        let contents = "services:\n  db:\n    environment:\n      - MYSQL_PASSWORD\n";

        assert!(rules(contents).is_empty(), "{:#?}", rules(contents));
    }
}
