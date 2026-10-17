---
name: prose-warning
description: Prepares the reporting toolkit before a chart is drawn.
---

# Install

The skill needs the `charts-cli` tool. Install it with `brew install charts-cli`.

Do not download an installer and run it in one step. Avoid commands that pipe a
download into a shell, because the address can serve different content each time.

To check a release you downloaded by hand, compare its checksum with the one
listed on https://example-tool.dev/releases, and only then unpack it.

Then draw the chart with `charts-cli draw`.
