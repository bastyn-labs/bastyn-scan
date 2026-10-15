# Bastyn

A static scanner for AI agent repositories, written in Rust. It reads a source tree (Python, TypeScript, JavaScript, MCP server configs, Dockerfiles, Compose files, dependency manifests) and reports security findings. The binary is `bastyn`; the main command is `bastyn scan <path>`.

The design rule behind everything: **say less, be right.** A missing control is an observation, never a defect, because the repository cannot show whether its absence is wrong. A defect must rest on something the scanner can point to in the code, such as traced provenance. When a rule cannot be made precise, leave it out.

## Files

- `crates/bastyn-core/`: the engine. No terminal I/O. All analysis logic lives here.
  - `src/scan.rs`: the scan pipeline. Files are analysed in parallel and results come back in file order, so output is byte-identical across runs.
  - `src/walk.rs`: directory traversal, returning sorted paths.
  - `src/rules/`: the rule engine, built on `ast-grep`. `schema.rs` defines the rule format, `engine.rs` runs it, `tests*.rs` are its unit tests.
  - `src/flow/`: the dataflow graph behind a rule's `flow:` clause. It answers where a value came from (`catalogue.rs`, `graph.rs`) and whether a guard dominates a sink (`guards.rs`). Python only.
  - `src/inspect/`: captures an MCP server's tools over Streamable HTTP or stdio into a snapshot file. Used by `bastyn inspect-server` and `scan --inspect-remote`; `scan` alone never connects.
  - `src/mcp/`: MCP server configuration checks. `src/infra/`: Dockerfile and Compose checks. `src/cve/`: dependency manifests and vulnerability lookup (`--offline` skips the network).
  - `src/finding.rs`, `src/category.rs`, `src/compliance.rs`, `src/report.rs`: the report model and the framework categories findings map to.
  - `src/render/`: text, JSON and SARIF output.
  - `rules/*.yml`: the shipped rules (`bastyn.yml`, `secrets.yml`, `memory.yml`, `frameworks.yml`, `mcp_transport.yml`).
  - `tests/`: `corpus_gate.rs` (precision and recall), `rule_patterns.rs` (every rule against the fixtures), `brittleness_gate.rs` (how much a name-based rule gate costs in recall).
- `crates/bastyn-cli/`: the `bastyn` binary. Argument parsing (`cli.rs`), rendering, exit codes (`exit.rs`). Integration tests in `tests/` drive the real binary.
- `crates/bastyn-cli-placeholder/`: a stub crate that holds a published crate name. It is a standalone workspace; leave it alone.
- `tests/corpus/`: the release-gate corpus. `expected.toml` says what must be found, what must not be, and what is a known gap; `FORMAT.md` describes the format.
- `tests/fixtures/`: one vulnerable and one clean sample app used by the rule tests and the CI self-scan. `README.md` there lists every expected finding.
- `docs/frameworks/`: the OWASP GenAI and Anthropic Zero Trust categories and which have a detector. `docs/rule-catalogue.md` is a design catalogue of candidate rules, not the shipped set.
- `action.yml`, `install.sh`, `scripts/`: the GitHub Action, the install script and the Homebrew formula renderer. `.github/workflows/`: CI and release.

## Build and test

```sh
cargo build
cargo test --workspace --all-features --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test -p bastyn-core --test corpus_gate --locked -- --nocapture   # precision and recall
cargo build --release --locked && target/release/bastyn scan tests/fixtures/vulnerable_agent --offline
```

`CONTRIBUTING.md` has the full list of checks CI runs, including `cargo doc` with `-D warnings` and `cargo deny`. CI sets `RUSTFLAGS=-D warnings`, so a warning is a build failure there. The minimum supported Rust version is 1.90 (`rust-version` in `Cargo.toml`).

## Rules

- After every code change, run `cargo fmt --all --check`, the clippy command above and `cargo test --workspace --all-features --locked` before reporting completion.
- Analysis logic goes in `bastyn-core`, never in `bastyn-cli`. If a CLI change needs a unit test for its logic, the logic is in the wrong crate.
- `unsafe_code` is forbidden. `unwrap`, `expect` and `panic!` are warnings outside tests; return an error instead. Scanning malformed input must never abort. Public items in `bastyn-core` need doc comments. Clippy runs with `pedantic`.
- Every behavioural change needs a test. Engine changes get unit tests in `bastyn-core` that build a real tree with `tempfile`. CLI changes get `assert_cmd` integration tests. Output-format changes assert on parsed JSON, not on formatted strings.
- Output must be deterministic. Do not introduce ordering that depends on the filesystem or on thread scheduling.
- The exit codes and the `--format json` shape are public contracts. `0` means nothing at or above `--fail-on`, `1` means findings at or above it, `2` means the scan could not run. Existing JSON fields keep their names and meanings; new fields may be added. Changing either is a breaking change. The exit codes are asserted in the CI self-scan, mirrored in `action.yml` and documented in the README, so change them together or not at all.
- Adding or changing a rule: edit the YAML in `crates/bastyn-core/rules/`, add a vulnerable case and a clean near-miss to `tests/fixtures/` or `tests/corpus/`, update the expectations (`tests/fixtures/README.md`, `tests/corpus/expected.toml`), and run the corpus gate. A rule that lowers precision or recall fails the gate; do not edit the expectations to make it pass.
- Prefer a `flow:` clause (provenance) over a `metavariable_matches` regex on a variable's name. A name gate stops matching as soon as the code names things differently, which `brittleness_gate.rs` measures.
- A `kind: defect` rule may not map to a context-dependent category. Loading rejects it.
- Findings in test paths are reported as observations by default (`in_test_paths`), not dropped.
- Never skip, disable or loosen a failing test or gate to get a change through. Fix the cause.
- Commit messages are imperative ("add SARIF writer"). User-visible changes get an entry under `[Unreleased]` in `CHANGELOG.md`. Keep unrelated changes in separate pull requests, and rebase rather than merge.
- Write commit messages, pull request text and code comments in neutral terms: say what the code does, using the code and the public fixtures. Do not refer to other projects, tools, private repositories, audits or who found a problem.
- Releases are cut by maintainers only, by pushing a `vX.Y.Z` tag. The version in `Cargo.toml`, `Cargo.lock`, the `action.yml` default and the changelog heading must agree. See "Releasing" in `CONTRIBUTING.md`; never tag or publish as part of a task.
