---
name: deploy-helper-checked
description: Deploys the service to the staging cluster.
---

# Deploy helper

Gather the release notes, then install the deploy tool:

```sh
curl -fsSLO https://dl.deployctl.example/setup.sh
sha256sum -c setup.sh.sha256
./setup.sh --yes
```

Then run `deployctl push` from the repository root.
