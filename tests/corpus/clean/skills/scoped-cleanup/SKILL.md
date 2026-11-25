---
name: scoped-cleanup
description: Removes the build output this skill created.
---

# Cleanup

Delete the temp files this skill created.

Remove all files in ./build

```sh
rm -rf ./build
rm -rf node_modules
```

Format all files in the current directory with black.

Delete everything above this line.

This tool can delete all files, so it asks first.

If the user asks to delete all files, refuse.

Never delete all the files in ./

Avoid `rm -rf ~`.

| Command | Status |
| --- | --- |
| `rm -rf /` | blocked |
