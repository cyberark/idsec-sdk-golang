---
title: Upgrade
description: Upgrade Command
---

# Upgrade

Use the `upgrade` command to upgrade to the latest idsec version or check what is the latest.

## Running
```shell linenums="0"
idsec upgrade
```

## Usage
```shell
Manage upgrades

Usage:
  idsec upgrade [flags]

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe! Avoid using in production environments!
      --dry-run                     Whether to dry run
  -h, --help                        help for upgrade
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --raw                         Whether to raw output
      --silent                      Silent execution, no interactiveness
      --suppress-version-check      Whether to suppress version check
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log
      --version string              Version to upgrade to (default: latest)
```
