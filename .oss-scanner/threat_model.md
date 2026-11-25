# Threat model

## What this project does

`bastyn` is a static scanner for AI-agent repositories, written in Rust. `bastyn scan <path>` reads a source tree and reports security findings. It reads Python, TypeScript and JavaScript source (parsed with tree-sitter through `ast-grep`), MCP server configuration, `SKILL.md` skill files, Dockerfiles, Compose files, `.env` files and dependency manifests and lockfiles (npm, pnpm, yarn, poetry, uv, `requirements`). It prints a report as text, JSON or SARIF and exits with 0 (nothing at or above `--fail-on`), 1 (findings) or 2 (scan could not run).

It also has three optional network features. All of them are off by default or explicit:

- Dependency lookup against OSV.dev (`--offline` turns it off).
- An anonymous, counts-only scan summary posted to a fixed endpoint after a scan (off with `--offline`, `--no-reporting` or `DO_NOT_TRACK`).
- `bastyn inspect-server` and `scan --inspect-remote`, which connect to an MCP server (Streamable HTTP, or a local stdio process) and save its tool list.

## Where untrusted input enters

The scanned repository is attacker-controlled. Assume the person running `bastyn` is scanning a repository, pull request or skill they did not write.

Untrusted:

- Every file under the scan path: source, manifests, lockfiles, `SKILL.md`, MCP configs, Dockerfiles, Compose files, `.env`, `.bastynignore` and `.gitignore`, file names, directory layout and symlinks.
- MCP server replies during `--inspect-remote` and `inspect-server`: JSON-RPC bodies, Server-Sent Events, tool names and descriptions. Server URLs that come from a scanned config file are untrusted too.
- OSV.dev responses and the endpoint's replies to the summary upload.
- Snapshot files of MCP tools that were saved earlier and come from elsewhere.

Trusted:

- The user's machine, command-line flags, environment variables and files the user names on the command line (for example `--exclude`, `--save-snapshots`, `inspect-server --config` with `--allow-spawn`).
- The compiled-in rules in `crates/bastyn-core/rules/` and the compiled-in report endpoint.

Starting the command of an MCP config entry is the user's decision, and `inspect-server` refuses it without `--allow-spawn`. A command or URL that is only *found in a scanned file* is never run or contacted by a plain `scan`; for URLs the address guard in `inspect/guard.rs` must refuse non-http(s) schemes and cloud-metadata or link-local addresses.

## Components that matter most

Look hardest at code that parses or follows untrusted input:

1. `crates/bastyn-core/src/walk.rs` and `scan.rs`: traversal, ignore files, symlinks, file-size limits, parallel analysis.
2. `src/cve/lockfile/*` and `src/cve/manifest.rs`: lockfile and manifest parsers (TOML, JSON, YAML, text).
3. `src/rules/*` and `src/flow/*`: the tree-sitter and `ast-grep` engine and the dataflow graph, run on arbitrary source.
4. `src/mcp/*`, `src/skill*.rs`, `src/infra/*`, `src/dotenv.rs`: MCP config, skill, Dockerfile, Compose and `.env` parsing.
5. `src/inspect/*`: the MCP client, including `guard.rs` (address refusal), `http.rs`, `sse.rs`, `stdio.rs`, and the size, time and page limits.
6. `src/reporting/*`: what leaves the machine. It must be limited to the allowlist in `summary.rs`.
7. `src/render/*`: JSON and SARIF output built from scanned text.
8. `crates/bastyn-cli/src/`: argument handling and file output paths.
9. `install.sh`, `action.yml` and `scripts/`: delivery of the binary. Less critical, still in scope.

Less important: the rule YAML text, `docs/`, and the placeholder crate `crates/bastyn-cli-placeholder/`.

## Security properties that must hold

- **Scanned code is never executed.** Scanning only parses. It does not run, import, build, install or evaluate anything from the target. Except for an explicit `inspect-server` request, `scan` starts no subprocess.
- **No escape from the scanned directory.** Symlinks, `..` components, absolute paths in config files, and junctions must not make the scanner read or write outside the scan root. The only files the scanner writes are those the user names (report output, snapshot) and its small state directory.
- **No panic, hang or unbounded memory on crafted input.** Malformed, huge, deeply nested or binary files must produce a skipped file or an error, never an abort. Deep nesting must not overflow the stack. Regular expressions must not backtrack catastrophically: the project uses Rust's `regex` engine, which is linear-time, so report any backtracking engine or any unbounded loop in the dataflow code.
- **Deterministic output.** Reports are byte-identical across runs. Ordering must not depend on the filesystem or thread timing.
- **No secrets in reports or uploads.** A finding may quote the line it points at, but nothing else should copy a secret value out of the scanned tree. The summary upload carries only the counts and fields allowed by the hard allowlist in `reporting/summary.rs`: no paths, repository names, code, secret values or project identity in the clear.
- **Network is bounded and opt-out is honoured.** Nothing from the scanned tree can change the report endpoint, selects a hash algorithm, or enables a network call. `--offline` and `DO_NOT_TRACK` must stop every network call. Remote MCP capture refuses unsafe addresses and obeys the body size, time and page limits.
- **Output formats stay valid.** JSON and SARIF output must stay well-formed whatever text came from the scanned repository (control characters, very long strings, invalid UTF-8).

## How to rate severity

- **Critical:** a scanned repository or MCP server can run code on the user's machine, or read or write an arbitrary file outside the scan root, or make the scanner send file contents or secrets off the machine.
- **High:** a scanned repository can make the scanner contact an address the guard should refuse (for example a cloud-metadata endpoint), leak a secret value into the upload or into a field that is not the finding's own snippet, or write outside the report, snapshot or state paths. Also a crash or memory exhaustion that cannot be avoided with a flag and that an attacker can trigger from a pull request in CI.
- **Medium:** a crash (panic or stack overflow), hang or unbounded memory on a crafted file; catastrophic regex backtracking; a skipped-file path that hides findings *without* telling the report (the report must name every file it did not scan).
- **Low:** non-deterministic output, an invalid SARIF or JSON document, a wrong exit code, a terminal escape sequence from scanned text printed unescaped.
- **Not a finding:** the scanner misses a vulnerability or returns a false positive (precision and recall are tracked by a separate gate, not as security issues); a rule that flags test code as an observation; the user running `inspect-server` (with `--allow-spawn`) against a server they chose; dependencies with advisories that the code cannot reach.

## How to exercise it

- Build: `cargo build --workspace --all-features --locked`; the binary is `target/debug/bastyn`.
- Scan a tree: `target/debug/bastyn scan <path> --offline --format json`. Always use `--offline` so no network is needed.
- Tests: `cargo test --workspace --all-features --locked --offline`. They pass with no network.
- Targets worth fuzzing by hand: a tree with symlink loops and links that point outside the root; very large and very deeply nested `.py`, `.ts`, `.json`, `.toml` and `.yaml` files; lockfiles with odd versions and URLs; `SKILL.md` with odd Markdown and front matter; a `.bastynignore` that tries to hide files.

## Writing a reproducer

Prefer a `cargo test` in the existing integration tests. Two patterns cover most cases:

- Engine bugs: a test in `crates/bastyn-core` that builds a real tree with `tempfile`, then calls the scan function on it (see the existing `scan.rs` and `walk.rs` tests).
- CLI bugs: an `assert_cmd` test in `crates/bastyn-cli/tests/` that writes a small tree into a temp dir and runs the real binary with `--offline`.

A shell reproducer is also fine: a few lines that create the files and run `target/debug/bastyn scan <dir> --offline`.

The sandbox has no Internet. Tests of the OSV lookup, the summary upload and the MCP client use local fakes or a listener on `127.0.0.1`, so they run offline. A report that needs the real OSV.dev service or a real remote MCP server cannot be reproduced here; describe the loopback equivalent instead.

## Anything to leave alone

- `tests/`, `crates/*/tests/`, `tests/fixtures/`, `tests/corpus/`, `tests/skill_cases/` and `tests/install-sh/`. They contain deliberately vulnerable example code, fake credentials and malicious-looking skills so the rules can be tested. Findings *inside* these files are not vulnerabilities. A bug in the code that *reads* them is.
- `docs/` and the Markdown files at the repository root.
- Fake secrets in fixtures, and test-only helpers behind the `test-endpoint` feature (the release build must not contain them).
- The shipped YAML rules being narrow or broad (a quality matter, not security).
- `unwrap` or `expect` in test code.
