---
name: bastyn-scan
description: Scans AI agent repositories for security defects and reports them accurately. Use when reviewing, auditing or shipping an AI agent, MCP server, LLM tool-calling app or agent skill repo, for problems such as eval of model output, hardcoded API keys, unsafe MCP config, risky Docker settings, vulnerable dependencies or hidden Unicode in SKILL.md and AGENTS.md.
license: Apache-2.0
---

# Bastyn scan

`bastyn` is a static scanner for AI agent repositories. It reads Python, TypeScript, JavaScript, MCP configs, Dockerfiles, Compose files, dependency manifests and agent instruction files (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`), and reports findings. Single binary, no account, no API key.

## Run it

```sh
command -v bastyn || echo "not installed"
bastyn scan <path> --offline            # text report, no network
bastyn scan <path> --format json        # machine-readable
bastyn scan <path> --format sarif       # GitHub / GitLab code scanning
```

If `bastyn` is missing, ask the user once whether to install it, then use the first that applies, and run `bastyn --version` to confirm:

1. `brew install bastyn-labs/tap/bastyn` (macOS, Linux with Homebrew)
2. `cargo install bastyn` (Rust toolchain present)
3. `curl -fsSL https://raw.githubusercontent.com/BASTYN-labs/bastyn-scan/main/install.sh | sh`

With no path given by the user, scan the current directory. Start with `--offline`, report the result, and offer a full run with the CVE lookup.

Without `--offline`, the scan looks up dependency names and versions on OSV.dev for known CVEs, and sends a small anonymous scan summary. Use `--offline` when the user wants nothing to leave the machine, or `--no-reporting` to keep the CVE lookup but skip the summary. Never send code.

## Read the result

| Exit code | Meaning |
| --- | --- |
| `0` | Nothing at or above `--fail-on` (default `high`) |
| `1` | Defects at or above `--fail-on` |
| `2` | The scan could not run: bad path, unreadable tree, invalid usage |

- **Defect**: wrong in any deployment, with evidence in the code (for example, model output passed to `eval`). Report these first, with file and line.
- **Observation**: a control the repository does not show, which may live elsewhere (for example, no rate limit). Hidden by default; `--show-observations` lists them. Observations never fail the build. Present them as things to check, not as bugs.
- **Coverage gaps**: files the scan skipped or could not check. Always relay them. A clean result covers only what was scanned.
- In `--format json`, use `findings[]`, `summary`, and `coverage` (`mcp_manifests`, `skill_files`, `instruction_files`, `skipped`).

Each finding carries a rule id (`BAS-LLM10-001`), severity, confidence and a fix. Quote the fix text instead of inventing one.

## Reporting rules

- Say what was scanned and what was not. "No defects found" is not "secure".
- The compliance crosswalk (EU AI Act, NIST) lists areas a finding touches. It is not a compliance verdict; do not describe it as one.
- Do not edit code to silence a finding unless the user asks. To exclude paths, use `--exclude <GLOB>` or a `.bastynignore` file, and say what was excluded.
- Scan a clone, not a running system. Bastyn does not execute the code it reads.

## Common flags

| Flag | Use |
| --- | --- |
| `--fail-on <none\|low\|medium\|high\|critical>` | Set the exit-code threshold |
| `--show-observations` | Include context-dependent observations |
| `--exclude <GLOB>` | Skip matching paths (repeatable); listed under coverage gaps |
| `--hidden` | Include dot-files and dot-directories |
| `--quiet` | Summary line only |

Run `bastyn scan --help` for the full list.

## CI

```yaml
- uses: BASTYN-labs/bastyn-scan@v0
  with:
    fail-on: high
```

Source and docs: https://github.com/BASTYN-labs/bastyn-scan
