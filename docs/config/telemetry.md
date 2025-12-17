---
title: Telemetry
description: Information about telemetry data collection in the Idsec SDK.
---

# Telemetry

The Idsec SDK collects telemetry data to help improve the product and user experience. This data includes information about command usage, errors, and performance metrics.

## Telemetry Data Collected

The following telemetry data is collected by the Idsec SDK and is sent on every API call via additional header `X-Cybr-Telemetry`:
- Environment information (e.g., Cloud Console, Region)
- Metadata about the executed command (e.g., command name, parameters)
- OS information (e.g., OS type, version)
- SDK version
- Tool being used (CLI/SDK/Terraform)

## Disabling Telemetry

Telemetry collection can be disabled by setting the `IDSEC_DISABLE_TELEMETRY_COLLECTION` environment variable to `true`. This can be done in the terminal before running Idsec commands:

```shell
export IDSEC_DISABLE_TELEMETRY_COLLECTION=true
```

Alternatively, telemetry can be disabled by using the `--disable-telemetry` flag when executing Idsec commands:

```shell
idsec exec --disable-telemetry
```

When telemetry is disabled, only application metadata is collected.
