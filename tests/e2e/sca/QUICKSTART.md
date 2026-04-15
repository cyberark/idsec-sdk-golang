# SCA E2E Quick Start

Get started with SCA E2E tests quickly.

## Step 1: Prepare test data

Prepare the test data file for the environment you want to test and place it in:

```text
tests/e2e/sca/testdata/
```

Use the matching file name for that environment:

```text
sca_cli_test_data_dev.json
sca_cli_test_data_pre_prod.json
sca_cli_test_data_prod.json
```

## Step 2: Fill the JSON file with non-secret config data

The JSON file should include IDs, targets, and non-secret fields only. Do not add passwords or secrets.

Example:

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

## Step 3: Run tests

Provide credentials and environment inline with the command:

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

## Step 4: Understand the flow

For the Cloud Console E2E test:

1. Read `principal` block and `targets.targets[]` array from the selected JSON config
2. Read credentials from env vars
3. Create the Cloud Console policy for the configured principal and target
4. Poll `GetPolicy` until status becomes `active`
5. Verify `GetPolicy` is the source of truth for the expected target
6. Authenticate as the principal user for `ListTargets`
7. Match `ListTargets` response to `GetPolicy` target using:
   - `roleId` -> `roleInfo.id`
   - `workspaceId` -> `workspaceId`
   - `orgId` -> `organizationId`
   - `workspaceType` -> `workspaceType`
8. Delete the created policy at the end of the test

General SCA note:

- auth user: dedicated service user
- principal user: dedicated test user

This distinction matters because:

- `CreatePolicy` runs with the service user
- `ListTargets` runs with the principal user's credentials so eligibility is validated in the principal context

## Environment Variables

| Env var | Purpose |
| ------- | ------- |
| `IDSEC_E2E_ENV` | Selects the config file (`dev`, `pre_prod`, `prod`) |
| `IDSEC_E2E_ISP_USERNAME` | Auth (service) user |
| `IDSEC_E2E_ISP_SECRET` | Auth (service) user secret |
| `IDSEC_E2E_SCA_PRINCIPAL_USERNAME` | Principal user for ListTargets |
| `IDSEC_E2E_SCA_PRINCIPAL_SECRET` | Principal user secret |

## Troubleshooting

### No config file found

Make sure the file exists under:

```text
tests/e2e/sca/testdata/
```

and that `IDSEC_E2E_ENV` points to the correct environment.

### Auth succeeds but `ListTargets` does not contain the policy target

Make sure `IDSEC_E2E_SCA_PRINCIPAL_SECRET` is set correctly. The Cloud Console E2E flow authenticates as the principal user for the `ListTargets` step, so missing or incorrect principal credentials will break the final validation.

### Full package build fails because of unrelated SCA tests

Run only the Cloud Console test command shown above instead of the whole package.
