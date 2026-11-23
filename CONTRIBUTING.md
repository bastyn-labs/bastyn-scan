# Contributing to Bastyn

Thanks for considering a contribution. This is what you need to know before opening a pull request.

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Bugs and small fixes.** Open a pull request directly. No issue needed.
- **New features, new commands, new rules.** Open an issue first so we can agree on the shape before you write code. This saves you building something we then ask you to restructure.
- **Security vulnerabilities in Bastyn itself.** Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Setup

You need Rust 1.90 or newer. [rustup](https://rustup.rs) will read `rust-toolchain.toml` and install the right toolchain and components automatically.

```console
git clone https://github.com/BASTYN-labs/bastyn-scan.git
cd bastyn-scan
cargo build
cargo test --workspace
```

## The checks CI runs

Run these locally before pushing; CI runs the same commands and will reject anything that fails them. The exact definitions are in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --release --locked
cargo doc --workspace --no-deps --all-features --locked   # with RUSTDOCFLAGS="-D warnings"
cargo deny --all-features check                           # requires: cargo install cargo-deny
cargo llvm-cov --workspace --all-features --locked --fail-under-lines 95   # requires: cargo install cargo-llvm-cov
```

`--locked` makes CI fail rather than silently update `Cargo.lock`. Run it locally too; a lockfile change should be a deliberate commit. CI also sets `RUSTFLAGS=-D warnings`, so a warning you can ignore locally is a build failure there. Cargo passes `--cap-lints allow` to dependencies, so that only ever bites on our own code.

Two further checks run after `cargo build --release`:

```console
cargo test -p bastyn-core --test corpus_gate --locked -- --nocapture
```

The corpus gate measures precision and recall against `tests/corpus/`. `--nocapture` puts those numbers in the log of the run that changed them, so a regression is visible where it was caused rather than only as a red test.

The second is a self-scan that asserts the exit-code contract end to end. It runs the release binary, on that platform, against known-answer fixtures: `tests/fixtures/clean_agent` (expects `0`), `tests/fixtures/vulnerable_agent` (expects `1`), the same fixture with `--fail-on none` (expects `0`), and a path that does not exist (expects `2`). See "Stability contracts" below for what those codes mean, and `ci.yml` for the script.

CI additionally builds against the minimum supported Rust version declared in `Cargo.toml`. If your change needs a newer language feature, say so in the pull request. Raising the MSRV is a deliberate decision, not a side effect.

## Project layout

| Path | Contents |
| --- | --- |
| `crates/bastyn-core` | The engine: traversal, parsing, and analysis. No terminal I/O. |
| `crates/bastyn-cli` | The `bastyn` binary: argument parsing, rendering, exit codes. |

The rule that keeps this useful: **analysis logic goes in `bastyn-core`, never in the CLI.** If a change to `bastyn-cli` needs a unit test for its logic, that logic is probably in the wrong crate.

## Code standards

The workspace enforces these via `[workspace.lints]`; they are not style preferences you can argue past in review.

- `unsafe_code` is **forbidden**. There is no acceptable reason for a file scanner to need it.
- `unwrap`, `expect`, and `panic!` are warnings in library and binary code. A security scanner that panics on malformed input has failed at its job. Return an error and let the caller decide. They are permitted in tests, where a broken assumption should fail the test.
- Public items in `bastyn-core` need doc comments (`missing_docs` is a warning).
- Clippy runs with `pedantic` enabled.

## Tests

Every behavioural change needs a test. Concretely:

- **Engine changes.** Unit tests in `crates/bastyn-core`, using `tempfile` to build a real tree on disk. Test the behaviour, not the implementation.
- **CLI changes.** Integration tests in `crates/bastyn-cli/tests/`, driving the real binary with `assert_cmd`. This is what catches broken flags, wrong exit codes, and malformed output.
- **Output format changes.** Assert on the parsed JSON, not on a formatted string, so the test survives whitespace changes but catches contract breaks.

Determinism matters: traversal returns sorted paths so that two runs over an unchanged tree produce byte-identical output. Do not introduce ordering that depends on filesystem or thread scheduling.

## Commits and pull requests

- Write commit messages in the imperative mood: "add SARIF writer", not "added" or "adds".
- Keep unrelated changes in separate pull requests. A formatting sweep mixed into a bug fix makes the fix impossible to review.
- Describe what changed and why in the pull request body. If it changes user-visible behaviour, add an entry to [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]`.
- Rebase rather than merge when updating a branch.

## Stability contracts

Two things in Bastyn are promises to users, not implementation details:

1. **The exit codes.** All three of them, listed below. People gate CI and pre-commit hooks on them.
2. **The `--format json` shape.** Fields may be added. Existing fields keep their names and meanings.

Changing either is a breaking change and needs a major version bump. Flag it explicitly in your pull request.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The scan ran and reported nothing at or above the `--fail-on` threshold. `--fail-on none` always lands here, however much was found. |
| `1` | The scan ran and reported at least one finding at or above the threshold. |
| `2` | The scan could not run: an unreadable or missing path, an invalid argument, a malformed rule file. Nothing was analysed, so nothing was ruled out. |

The distinction that matters is `1` versus `2`. `1` is an answer: the tool worked and found something. `2` is the absence of one. A CI job that treats `2` as "findings" will report a broken scanner as a passing one, or vice versa. Keep them apart.

This contract is asserted by the self-scan step in `ci.yml`, mirrored in `action.yml`, and documented in the README. Do not repurpose a code without changing all of them together.

## Releasing

Only maintainers cut releases. Pushing a tag is the only thing that publishes anything: [`release.yml`](.github/workflows/release.yml) triggers on tags matching `v[0-9]+.[0-9]+.[0-9]+*` and on nothing else, so merging to `main` never produces a release.

A repository ruleset named "release tags" enforces who may do that. Creating, updating or deleting any tag matching `v*.*.*` is restricted to repository admins and the release bot, so write access to the repository is not by itself enough to publish a release. The pattern deliberately stops short of the bare `vMAJOR` alias tag, because `major-alias` force-moves that one as `github-actions[bot]` and a rule covering it would block the workflow's own last step.

A release now updates four places, not just this repository: the GitHub Release itself, the `bastyn` and `bastyn-core` crates on crates.io, the `BASTYN-labs/homebrew-tap` formula, and (indirectly — no per-release action needed) the `install.sh` one-liner, which always resolves whatever the latest tag is. The crates.io and Homebrew updates only happen for a final `vMAJOR.MINOR.PATCH` tag, same as the `major-alias` job — a release candidate updates GitHub Releases only.

Four version numbers have to agree before a tag will build. Three of them are checked, and a mismatch fails the release rather than publishing something inconsistent.

| Number | Where | What checks it |
| --- | --- | --- |
| Crate version | `version` under `[workspace.package]` in `Cargo.toml` | `verify` compares it to the tag |
| Lockfile | the `bastyn` and `bastyn-core` entries in `Cargo.lock` | every build runs `--locked` |
| Action default | `default:` on the `version` input in `action.yml` | `verify` compares it to the tag |
| Changelog heading | the version heading in `CHANGELOG.md` | nothing. Get it right by hand |

The `action.yml` default is the one people forget. It decides which binary a caller downloads when they do not name a version, so if it lags the tag, `uses: BASTYN-labs/bastyn-scan@v0.1.2` installs some other release's binary and pinning stops meaning anything. That happened once already; the check exists so it cannot happen twice.

### Cutting a release

1. Open a pull request against `main` that does the release bump and nothing else:
   - Set `version` in `Cargo.toml` to the new number, in both `[workspace.package]` and the `bastyn-core` dependency entry.
   - Run `cargo build` and commit the updated `Cargo.lock`.
   - Set the `version` input's `default:` in `action.yml` to the tag, with the leading `v`.
   - In `CHANGELOG.md`, retitle `## [Unreleased]` as `## [X.Y.Z] - YYYY-MM-DD`, put a fresh empty `## [Unreleased]` above it, and update the link definitions at the bottom of the file.
2. Merge it. `main` requires a pull request and a passing `ci` run, so this is not a direct push.
3. Tag the merge commit and push the tag:

   ```console
   git switch main && git pull
   git tag -a v0.1.2 -m "bastyn v0.1.2"
   git push origin v0.1.2
   ```

4. When the workflow has finished, publish the release to the GitHub Marketplace. This is manual: the workflow cannot do it. Open the release on GitHub, choose Edit, tick "Publish this Action to the GitHub Marketplace" and save. The listing's name, description and "Use latest version" snippet come from the releases published this way, so a release that skips this step does not update the listing, however recently it was tagged. The `action.yml` `description` must be 125 characters or fewer, or the publish fails.

Tag a commit that is already on `main`. A tag is not a promise that the code works, so `verify` runs the full test suite against the tagged commit before anything is published.

### What the tag triggers

| Job | What it does |
| --- | --- |
| `verify` | `cargo test --workspace --all-features --locked`, then the two version checks above |
| `create-release` | Creates the GitHub release with generated notes, or reuses one that already exists |
| `upload-assets` | Builds `bastyn` for five targets, attaching each as an archive with a SHA-256 checksum |
| `major-alias` | Force-moves the `vMAJOR` tag onto the released commit |
| `release-gate` | Checks whether the tag is a final release (`vMAJOR.MINOR.PATCH`, no suffix) — crates.io and the Homebrew tap are only updated for final releases |
| `publish-crates` | Publishes `bastyn-core` and `bastyn` to crates.io via Trusted Publishing (no long-lived token); final releases only |
| `render-and-verify-tap` | Renders the Homebrew formula, then verifies it with `brew audit`/`brew install`/`brew test` before anything is pushed; final releases only |
| `push-tap` | Pushes the verified formula to `BASTYN-labs/homebrew-tap`, using a GitHub App token scoped to that repo only; final releases only |

The five targets are `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin` and `x86_64-pc-windows-msvc`. The Linux builds use musl so they are fully static: no host glibc version to match.

`major-alias` is what makes `uses: BASTYN-labs/bastyn-scan@v0` resolve to the newest 0.x release. It runs last and only after every target has uploaded, because a release missing the Windows archive is not one the alias should advertise. It also moves only for an exact `vMAJOR.MINOR.PATCH` on a release that is neither a draft nor a prerelease, so tagging `v0.2.0-rc.1` leaves `v0` pointing where it was.

### One-time infrastructure setup

None of this is automated, and none of it repeats on later releases.

1. **crates.io Trusted Publishing.** Done: `bastyn-core` and `bastyn` are published (`0.1.4`), and `bastyn-scan`'s `publish-crates` job is registered as a Trusted Publisher for both (crates.io → each crate's settings → Trusted Publishing → GitHub Actions, repository `BASTYN-labs/bastyn-scan`, workflow file `release.yml`). Both crates also have "Require trusted publishing for all new versions" enabled, so a plain API token can no longer publish a new version even if one leaked.
2. **Homebrew tap repository.** Done: `BASTYN-labs/homebrew-tap` exists with an initial commit.
3. **GitHub App for the tap push.** Done: the `bastyn-tap-publisher` GitHub App is registered under `BASTYN-labs`, installed only on `BASTYN-labs/homebrew-tap` (Contents: Read and write, no other repository), and its App ID and private key are stored as the `bastyn-scan` repo secrets `HOMEBREW_TAP_APP_ID` and `HOMEBREW_TAP_APP_PRIVATE_KEY`.
4. **`bastyn-cli` tombstone crate.** Done: published once (`0.1.0`) to claim the old name before this rename could be squatted. Nothing to re-publish on later releases — crates.io versions are immutable.

### When a release fails

`verify` failing has published nothing. Delete the tag, fix the mismatch on `main`, and tag again:

```console
git push --delete origin v0.1.2
git tag --delete v0.1.2
```

If a single target fails after the release object exists, use "Re-run failed jobs" on that workflow run — this is always safe and is the preferred recovery. Re-running the *whole* workflow through `workflow_dispatch` with the same tag is only safe if `publish-crates` has not yet succeeded for that tag: crates.io rejects re-publishing an already-published version, so a full re-run after a successful `publish-crates` will fail on that job specifically, even though `create-release`/`upload-assets` remain safe to repeat (create-release reuses the existing release rather than replacing it).

Because `publish-crates`, `render-and-verify-tap`, and `push-tap` all run in parallel with `major-alias` rather than after it, a release can end up "partially complete" — a public GitHub Release and a moved `vMAJOR` alias, but crates.io or the Homebrew tap not yet updated because one of those jobs failed. This is an expected possible state given the pipeline's additive design, not necessarily a sign something is broken elsewhere; use "Re-run failed jobs" to finish the incomplete piece.

Do not delete or move a tag that has already published assets. People pin to it.

## Licensing

Contributions are accepted under the [Apache License, Version 2.0](LICENSE), per section 5 of that license. By opening a pull request you confirm you have the right to submit the work under those terms.
