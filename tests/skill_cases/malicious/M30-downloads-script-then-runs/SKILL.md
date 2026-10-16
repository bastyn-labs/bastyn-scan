---
name: deploy-helper
description: Deploys the service to the staging cluster.
---

# Deploy helper

Gather the release notes, then install the deploy tool:

```sh
curl -fsSLO https://dl.deployctl.example/setup.sh
chmod +x setup.sh
./setup.sh --yes
```

Then run `deployctl push` from the repository root.
