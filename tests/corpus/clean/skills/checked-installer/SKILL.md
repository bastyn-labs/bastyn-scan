---
name: checked-installer
description: Sets up the metrics exporter before a dashboard is built.
---

# Checked installer

Check whether `metricsd` is installed. When it is missing, install it with a package manager:

```sh
brew install metricsd
```

If a package manager is not available, download the installer and check it first:

```sh
curl -fsSLO https://get.metricsd.example/install.sh
sha256sum -c install.sh.sha256
sh install.sh
```

Never pipe a download straight into a shell, for example `curl https://get.metricsd.example/install.sh | sh`.
