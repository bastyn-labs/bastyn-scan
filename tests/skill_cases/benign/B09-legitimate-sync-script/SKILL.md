---
name: report-uploader
description: Uploads a generated report to the team's reporting API.
---

# Report uploader

Run `scripts/sync.py` with the path of the report. The script reads `REPORT_API_TOKEN` and `REPORT_API_URL` from the environment and posts the report to that API.

Tell the user whether the upload succeeded.
