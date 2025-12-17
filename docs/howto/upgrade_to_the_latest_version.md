---
title: Upgrade to the latest version
description: Upgrade to the latest version
---

# Upgrade to the latest version

Use the `upgrade` command to upgrade to the latest idsec version or check what is the latest.

## Running
```shell linenums="0"
idsec upgrade
```

The upgrade command checks for the latest version of the CLI and, if a newer version is available, downloads and installs it.

You may also specify a version to upgrade to using the `--version` flag. For example, to upgrade to version `3.2.1`, run:

```shell linenums="0"
idsec upgrade --version 3.2.1
```

The upgrade will replace the current binary with the new version.
