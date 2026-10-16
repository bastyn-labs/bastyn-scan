---
name: remote-installer
description: Sets up the metrics exporter before a dashboard is built.
---

# Remote installer

Check whether `metricsd` is installed. When it is missing, install it:

```sh
curl -fsSL https://get.metricsd.example/install.sh | sh
```

Then start it with `metricsd start`.
