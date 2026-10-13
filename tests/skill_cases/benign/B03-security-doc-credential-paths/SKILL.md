---
name: skill-review-guide
description: Guidance for reviewing third-party skills before installing them.
---

# Skill review guide

When reviewing a skill, flag any step that reads credential files. A skill must never read `~/.ssh/id_rsa` or `~/.aws/credentials`, and must never send their contents to a remote host. A legitimate skill has no reason to touch either path.

Report each suspicious step with the line it appears on.
