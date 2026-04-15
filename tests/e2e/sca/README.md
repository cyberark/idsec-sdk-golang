# SCA E2E Testing

End-to-end tests for SCA flows using the shared E2E framework and environment-specific JSON test data.

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for a short getting started guide.

## Overview

SCA E2E tests use two kinds of input:

1. Authentication credentials (provided via env vars at runtime)
2. Scenario-specific test data from a JSON config file (IDs, targets, non-secret fields)

Secrets are never stored in the JSON config. They must be provided through environment variables at runtime.

## Config Files

SCA test data files live under:

```text
tests/e2e/sca/testdata/
```

Supported file names:

```text
sca_cli_test_data_dev.json
sca_cli_test_data_pre_prod.json
sca_cli_test_data_prod.json
```

Each file represents one environment and can contain data for multiple SCA scenarios.

## Config Selection

The config loader selects the file using `IDSEC_E2E_ENV`:

| `IDSEC_E2E_ENV` value | File used |
| --------------------- | --------- |
| `dev` | `sca_cli_test_data_dev.json` |
| `pre_prod` or `pre-prod` | `sca_cli_test_data_pre_prod.json` |
| unset or any other value | `sca_cli_test_data_prod.json` |

This behavior is implemented in `config_loader.go`.

## Environment Variables

Secrets and usernames are provided via env vars. Env vars always take precedence over JSON config values.

| Env var | Purpose |
| ------- | ------- |
| `IDSEC_E2E_ENV` | Selects the config file |
| `IDSEC_E2E_ISP_USERNAME` | Auth (service) user |
| `IDSEC_E2E_ISP_SECRET` | Auth (service) user secret |
| `IDSEC_E2E_SCA_PRINCIPAL_USERNAME` | Principal user for ListTargets |
| `IDSEC_E2E_SCA_PRINCIPAL_SECRET` | Principal user secret |

## Auth User vs Principal User

In SCA E2E tests, the authenticated user and the policy principal can be different.

- Auth user: dedicated service user (creates/deletes policies)
- Principal user: dedicated test user (used for ListTargets eligibility)

This means:

- the auth user can perform policy lookup / create calls
- the policy can be created for a different principal user
- `ListTargets` is called as the principal user so eligibility is validated in the principal context

## Current Cloud Console Flow

1. Load selected JSON config
2. Read credentials from env vars
3. Read `principal` block and `targets.targets[]` array from config
4. Create a cloud-console policy for the configured principal and target
5. Poll until the created policy becomes active (fail immediately on terminal status)
6. Call `GetPolicy` and validate policy state:
   - policy ID is present and consistent
   - policy status is `active`
7. Build a principal-authenticated cloud-console service
8. Call `ListTargets` and match `GetPolicy` target to response:
   - `roleId` -> `roleInfo.id`
   - `workspaceId` -> `workspaceId`
   - `orgId` -> `organizationId`
   - `workspaceType` -> `workspaceType`
   - Strict failure if the expected target is not found
9. Delete the created policy with best-effort cleanup at the end of the test

The current Cloud Console flow lives in:

- `cloud_console_azure_test.go`
- `utils.go`
- `config_loader.go`

## Config File Example

The JSON config contains only non-secret data (IDs, target fields, method, URL):

```json
{
  "auth": {
    "method": "identity",
    "identity_url": "https://identity.example.com"
  },
  "azure_cloud_console": {
    "principal": {
      "principal_id": "user-id",
      "principal_name": "eva_user@tenant.example",
      "source_directory_name": "CyberArk Cloud Directory",
      "source_directory_id": "directory-id"
    },
    "targets": {
      "targets": [
        {
          "roleId": "role-id",
          "workspaceId": "workspace-id",
          "orgId": "organization-id",
          "workspaceType": "directory"
        }
      ]
    }
  }
}
```

## Running Tests

Provide credentials inline with the test command:

```bash
IDSEC_E2E_ENV=pre_prod \
  IDSEC_E2E_ISP_USERNAME='service-user@domain' \
  IDSEC_E2E_ISP_SECRET='service-user-secret' \
  IDSEC_E2E_SCA_PRINCIPAL_USERNAME='principal-user@domain' \
  IDSEC_E2E_SCA_PRINCIPAL_SECRET='principal-secret' \
  go test -tags "e2e sca" -v ./tests/e2e/sca/...
```

Run only the Cloud Console ListTargets test:

```bash
IDSEC_E2E_ENV=pre_prod \
  IDSEC_E2E_ISP_USERNAME='service-user@domain' \
  IDSEC_E2E_ISP_SECRET='service-user-secret' \
  IDSEC_E2E_SCA_PRINCIPAL_USERNAME='principal-user@domain' \
  IDSEC_E2E_SCA_PRINCIPAL_SECRET='principal-secret' \
  go test -tags "e2e sca" -v ./tests/e2e/sca/ -run '^TestCloudConsoleAzureListTargets$'
```

## Notes

- One JSON file supports one environment and multiple SCA blocks
- Tests should only read the config block they need
- Secrets must be provided via env vars, never committed in JSON
- Env vars take precedence over JSON config values
- The Cloud Console test creates a policy, validates it with `GetPolicy`, calls `ListTargets` in principal context, then deletes the created policy
- Target field names in JSON (`roleId`, `workspaceId`, `orgId`, `workspaceType`) are matched against `GetPolicy` and `ListTargets`
