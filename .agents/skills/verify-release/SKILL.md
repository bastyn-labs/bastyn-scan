---
name: verify-release
description: Check that a Bastyn release vX.Y.Z is published in all four places (git tag, GitHub release, crates.io, Homebrew tap). Use when asked whether a release is tagged, published or live. Read-only; reports PASS or FAIL per check.
compatibility: Needs git, gh (authenticated) and curl, with network access.
---

# Verify a release

Run the script with the version, with or without the leading `v`:

```sh
.agents/skills/verify-release/scripts/verify-release.sh v0.8.0
```

It runs four checks and prints `PASS` or `FAIL` for each, then a `RESULT` line.

| Check | Passes when |
| --- | --- |
| git tag | `refs/tags/vX.Y.Z` exists on `BASTYN-labs/bastyn-scan` |
| github release | the release is not a draft and has five platform archives, each with a `.sha256` |
| crates.io | the `bastyn` crate has version X.Y.Z and it is not yanked |
| homebrew | `Formula/bastyn.rb` in `BASTYN-labs/homebrew-tap` names vX.Y.Z for the four macOS and Linux targets |

The release counts as published only when all four pass. Exit codes: `0` all passed, `1` at least one failed, `2` bad argument or missing tool.

Report the script's output as it is. Do not infer a pass for a check that failed or did not run.

## Notes

- The crate is `bastyn`. `bastyn-cli` is a placeholder that stays at 0.1.0.
- Only final `vMAJOR.MINOR.PATCH` tags are accepted. A release candidate updates GitHub Releases only, so the crates.io and Homebrew checks do not apply to it.
- Windows is in the release archives but not in the Homebrew formula.
- The script never tags, publishes or writes anything. How a release is cut is in `CONTRIBUTING.md` under "Releasing".
