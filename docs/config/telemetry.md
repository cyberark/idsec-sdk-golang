---
title: Telemetry
description: Information about telemetry data collection in the Idsec SDK.
---

# Telemetry

The Idsec SDK collects telemetry data to help improve the product and user experience. This data is **non-content metadata** only: it does not include credentials, secrets, HTTP body payload, or customer business data.

## How telemetry is collected

Telemetry is assembled inside the shared HTTP client (`IdsecClient` in `pkg/common/idsec_client.go`) **immediately before each outbound API request**:

1. **Metadata** for that request is filled (API route, owning service label, and caller-derived Go type/operation from the stack).
2. **Metrics collectors** run (see `pkg/telemetry/`). The default stack uses environment, metadata, and OS collectors; a **limited** stack uses only the metadata collector when broad collection is turned off (see below).
3. Metrics are **encoded** into a single string and attached to the request.

Tools may add optional key/value context via `IdsecClient.AddExtraContextField` (for example Terraform or CLI hints); those values appear as extra metadata fields in the same bundle.

## How telemetry is sent

Every qualifying request can include an HTTP header:

| Header | Value |
|--------|--------|
| `X-Cybr-Telemetry` | **Standard Base64** encoding of a UTF-8 string in **query-string style**: `key=value&key=value&...` |

Encoding details live in `pkg/telemetry/encoders/idsec_telemetry_header_metrics_encoder.go`. The payload always begins with `sn=<tool>` (service/tool in use from config). Additional entries use the form `<collectorShort>.<metricShort>=<value>` (for example `mm.rt=/api/Example`).

Decode for inspection (example):

```shell
echo '<paste-base64-here>' | base64 -d
```

## Full vs limited payloads

| Mode | When | Collectors |
|------|------|------------|
| **Full** | Client created with telemetry enabled **and** `IDSEC_DISABLE_TELEMETRY_COLLECTION` is unset | Environment (`em`), metadata (`mm`), OS (`om`) |
| **Limited** | Telemetry collection disabled via env/CLI, or client constructed with telemetry disabled | Metadata (`mm`) only |

When telemetry is **limited**, environment and OS metrics are **not** included; the header may still be present with metadata only.

## Field reference — full telemetry

Decoded payload shape: `sn=...&em.*=...&mm.*=...&om.*=...` (then Base64-encoded for the header).

| Key | Metric name | Description | Example |
|-----|-------------|-------------|---------|
| `sn` | *(encoder prefix)* | Tool in use from global config; prepended before collector metrics. | `Idsec-SDK-Golang` |
| `em.pc` | `proxy_configured` | `true` if any of `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` is non-empty. | `true` |
| `em.prv` | `provider` | Detected cloud or on-prem provider; sensitive account/instance identifiers are not sent. | `aws`, `on-premise` |
| `em.env` | `environment` | Runtime flavor when a cloud environment is detected. | `ec2`, `lambda`, `on-premise` |
| `em.reg` | `region` | Region from cloud metadata or environment when detectable. | `us-east-1`, `unknown` |
| `mm.at` | `idsec_tool` | Current Idsec tool (global config). | `Idsec-CLI-Golang` |
| `mm.av` | `idsec_version` | SDK version string. | `1.4.0` |
| `mm.abn` | `idsec_build_number` | Build number. | `0`, `4521` |
| `mm.abd` | `idsec_build_date` | Build date string. | `N/A`, `2026-05-01` |
| `mm.agc` | `idsec_git_commit` | Embedded source control revision. | `N/A`, `a1b2c3d4` |
| `mm.agb` | `idsec_git_branch` | Embedded branch name. | `N/A`, `main` |
| `mm.cid` | `correlation_id` | UUID for correlating requests (generated if unset). | `550e8400-e29b-41d4-a716-446655440000` |
| `mm.lt` | `local_time` | Client local time when metrics are collected (`RFC3339`). | `2026-05-26T14:30:00+03:00` |
| `mm.rt` | `route` | API route path for this request (path-escaped by the client). | `/api/Users/Search` |
| `mm.svc` | `service` | Owning service label from client construction. | `IdentityAdmin` |
| `mm.cls` | `class` | Go caller type name from the runtime stack. | `idsec_user.Service` |
| `mm.op` | `operation` | Final segment of the caller’s qualified function name. | `Get`, `Create` |
| `mm.de` | `deploy_env` | Value from `DEPLOY_ENV` (defaults when unset; see `GetDeployEnv` in the SDK). | `Prod`, `gov-prod` |
| `mm.<short>` | *(dynamic)* | Optional tool context from `AddExtraContextField`; the **short** name is the key suffix. | `tfr=idsec_user` |
| `om.os` | `os_name` | Operating system from the Go runtime. | `darwin`, `linux` |
| `om.arch` | `architecture` | CPU architecture from the Go runtime. | `arm64`, `amd64` |
| `om.go_ver` | `go_version` | Go toolchain version. | `go1.22.0` |
| `om.tz` | `timezone` | Short timezone name from the local clock. | `UTC`, `EST` |

## Field reference — limited telemetry

Same header mechanism; only **`sn`** and **`mm.*`** appear (no `em.*` or `om.*`).

| Key | Metric name | Description | Example |
|-----|-------------|-------------|---------|
| `sn` | *(encoder prefix)* | Tool in use. | `Idsec-SDK-Golang` |
| `mm.at` | `idsec_tool` | Current Idsec tool. | `Idsec-Terraform-Provider` |
| `mm.av` | `idsec_version` | SDK version. | `0.9.1` |
| `mm.abn` | `idsec_build_number` | Build number. | `0` |
| `mm.abd` | `idsec_build_date` | Build date. | `N/A` |
| `mm.agc` | `idsec_git_commit` | Revision string. | `N/A` |
| `mm.agb` | `idsec_git_branch` | Branch string. | `N/A` |
| `mm.cid` | `correlation_id` | Correlation UUID. | `…` |
| `mm.lt` | `local_time` | RFC3339 local time. | `2026-05-26T12:00:00Z` |
| `mm.rt` | `route` | Request route. | `/SomeApi/Update` |
| `mm.svc` | `service` | Owning service label. | *(empty string possible)* |
| `mm.cls` | `class` | Caller type name. | `…` |
| `mm.op` | `operation` | Caller operation name. | `Put` |
| `mm.de` | `deploy_env` | Deploy environment. | `Prod` |
| `mm.<short>` | *(dynamic)* | Optional `AddExtraContextField` entries. | `clic=login` |

## Disabling Telemetry

Telemetry collection can be disabled by setting the `IDSEC_DISABLE_TELEMETRY_COLLECTION` environment variable to `true`. This can be done in the terminal before running Idsec commands:

```shell
export IDSEC_DISABLE_TELEMETRY_COLLECTION=true
```

Alternatively, telemetry can be disabled by using the `--disable-telemetry` flag when executing Idsec commands:

```shell
idsec exec --disable-telemetry
```

When telemetry is disabled, only application metadata is collected (limited payload above).
