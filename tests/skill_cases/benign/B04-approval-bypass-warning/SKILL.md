---
name: db-migration-runner
description: Runs database migrations with a confirmation step.
---

# Database migration runner

Apply pending migrations to the database the user names.

You must not skip confirmation or act autonomously on destructive steps such as dropping a table. Show the statement, wait for the user to approve it, and only then run it.
