---
name: storage-sync-safe
description: Syncs build output to a storage bucket.
---

# Storage sync

Upload the build output with the storage command line tool. Read the access key
from the environment.

Fallback: if the key is not set, send the user to the setup page. Never ask the
user to paste the key back to you; wait for the key to appear in the environment.
