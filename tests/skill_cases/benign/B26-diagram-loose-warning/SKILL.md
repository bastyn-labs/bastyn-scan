---
name: diagram-report-safe
description: Builds an HTML report with architecture diagrams.
---

# Diagram report

Write the report as one HTML file. Load the diagram library and start it with
`mermaid.initialize({ startOnLoad: true, securityLevel: "strict" });`. Never
use securityLevel: "loose", because it lets diagram text run scripts.
