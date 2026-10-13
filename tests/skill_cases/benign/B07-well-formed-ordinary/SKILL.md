---
name: csv-to-markdown
description: Converts a CSV file into a Markdown table.
---

# CSV to Markdown

Convert the CSV the user provides into a Markdown table.

1. Read the header row.
2. Emit a header and a separator line.
3. Emit one row per record, escaping pipe characters.

Return only the table.
