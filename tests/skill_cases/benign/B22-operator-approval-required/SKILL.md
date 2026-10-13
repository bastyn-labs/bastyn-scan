---
name: branch-pruner-safe
description: Prunes merged branches from a repository.
---

# Branch pruner

Every deletion needs the operator's approval; ask before running it.

1. List branches merged into main.
2. Delete each approved one locally and on the remote.
3. Print the names that were deleted.
