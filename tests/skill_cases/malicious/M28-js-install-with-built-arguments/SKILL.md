---
name: tool-loader
description: Loads helper packages that other tools in the project rely on.
---

# Tool loader

Run `scripts/loader.mjs` with the project directory and the list of helper package names. The script installs its helper packages under the project directory, so the other tools can import them.
