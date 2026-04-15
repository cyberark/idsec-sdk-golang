![Idsec SDK Golang](https://github.com/cyberark/idsec-sdk-golang/blob/main/assets/sdk.png)

<p align="center">
    <a alt="Go Version">
        <img src="https://img.shields.io/github/go-mod/go-version/cyberark/idsec-sdk-golang" />
    </a>
    <a href="https://github.com/cyberark/idsec-sdk-golang/blob/main/LICENSE.txt" alt="License">
        <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License" />
    </a>
</p>

Idsec SDK Golang
==============

📜[**Documentation**](https://cyberark.github.io/idsec-sdk-golang/)

CyberArk's Official SDK for different services operations

## Features and Services

### Supported Environments

Here's the list of `AwsEnv` values from `AwsEnvList` in Markdown format:
#### Standard Cloud Environments

- `prod`

#### Government Cloud Environments

- `gov-prod`

TL;DR
=====

## Enduser

For CLI installation and usage documentation, see the [idsec-cli-golang repository](https://github.com/cyberark/idsec-cli-golang).

SDK Usage
=========
One can develop using the idsec SDK using its API / class-driven design

### ISP authentication

Let's say we want to generate a short lived password from the code

To do so, we can use the following script:

```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso"
	"os"
)

func main() {
	// Perform authentication using IdsecISPAuth to the platform
	// First, create an ISP authentication class
	// Afterwards, perform the authentication
	ispAuth := auth.NewIdsecISPAuth(false)
	_, err := ispAuth.Authenticate(
		nil,
		&authmodels.IdsecAuthProfile{
			Username:           "user@cyberark.cloud.12345",
			AuthMethod:         authmodels.Identity,
			AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{},
		},
		&authmodels.IdsecSecret{
			Secret: os.Getenv("IDSEC_SECRET"),
		},
		false,
		false,
	)
	if err != nil {
		panic(err)
	}

	// Create an SSO service from the authenticator above
	ssoService, err := sso.NewIdsecSIASSOService(ispAuth)
	if err != nil {
		panic(err)
	}

	// Generate a short-lived password
	ssoPassword, err := ssoService.ShortLivedPassword(
		&ssomodels.IdsecSIASSOGetShortLivedPassword{},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", ssoPassword)
}
```

### Self-hosted / PVWA authentication

For **self-hosted CyberArk** deployments, use **PVWA** (Password Vault Web Access) authentication. This authenticates with username and password against your PVWA instance’s REST API (`/PasswordVault/API/auth/{method}/Logon`).

Provide the PVWA **base URL** (e.g. `https://pvwa.example.com`), the **login method** (`cyberark`, `ldap`, or `windows`), and the password via `IdsecSecret` (e.g. from `IDSEC_SECRET`). The resulting authenticator can be passed into `IdsecAPI` or into services such as PCloud and SIA when those are configured for PVWA.

```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"os"
)

func main() {
	pvwaAuth := auth.NewIdsecPVWAAuth(false)
	token, err := pvwaAuth.Authenticate(
		nil,
		&authmodels.IdsecAuthProfile{
			Username:   "AdminUser",
			AuthMethod: authmodels.PVWA,
			AuthMethodSettings: &authmodels.PVWAIdsecAuthMethodSettings{
				PVWAURL:         "https://pvwa.example.com",
				PVWALoginMethod: "cyberark", // or: ldap, windows
			},
		},
		&authmodels.IdsecSecret{Secret: os.Getenv("IDSEC_SECRET")},
		false,
		false,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Authenticated to PVWA: %s\n", token.Endpoint)
}
```

More examples can be found in the [examples](examples) folder

Linting
=======

The SDK uses [golangci-lint](https://golangci-lint.run/) for static analysis, including struct tag validation via the `tagliatelle` linter.

## Running Linters

```bash
make lint
```

## Struct Tag Conventions

Struct tags follow these naming conventions:

| Tag | Convention | Example |
|-----|------------|---------|
| `json` | snake_case | `json:"account_id"` |
| `mapstructure` | snake_case | `mapstructure:"account_id"` |
| `flag` | kebab-case | `flag:"account-id"` |

### Exceptions

Some struct tags intentionally deviate from these conventions because they must match external API contracts. These are marked with `//nolint:tagliatelle` comments. Common cases include:

- **API response models** — json tags must match the backend API's response format (often camelCase)
- **API request models** — json tags must match what the backend API expects
- **Terraform/CLI input models** — mapstructure tags must match the schema used by Terraform or CLI flag parsing

When adding new struct tags:
1. Use the standard conventions above for new code
2. If the tag must match an external API, add `//nolint:tagliatelle` with a comment explaining why
3. Empty mapstructure tags (`mapstructure:""`) and squash directives (`mapstructure:",squash"`) are automatically excluded from linting
4. If a model has many API-facing fields that deviate from snake_case (e.g., camelCase from the backend API), consider adding a path-based exclusion in `.golangci.yml` instead of annotating every field individually. See the existing exclusions for `cce/aws/models/` and `cce/azure/models/` as examples

Terraform Provider
==================

For Terraform resource and data source development, see the [terraform-provider-idsec](https://github.com/cyberark/terraform-provider-idsec) repository. Terraform action definitions, types, and configurations are maintained in the provider repository.

The SDK provides the service logic, models, and action schema maps (`ActionToSchemaMap`) that the Terraform provider imports.

Telemetry
=========

The Idsec SDK collects limited telemetry to support product reliability and improvement. Telemetry is used solely for operational insights such as feature usage trends, error diagnostics, and performance monitoring.

## Telemetry Data Collected

By default, the Idsec SDK attaches a telemetry header (`X-Cybr-Telemetry`) to API requests. The telemetry data is limited to non-content metadata and may include:

- Execution environment context (e.g., Cloud Console identifier, region)
- Command metadata (e.g., command name and execution outcome; no secrets or customer data)
- Operating system type and version
- SDK version
- Interface type (CLI, SDK, Terraform)

Telemetry does not include credentials, secrets, payload content, or customer business data.

## Disabling Telemetry

Telemetry collection can be disabled in either of the following ways:

```shell
export IDSEC_DISABLE_TELEMETRY_COLLECTION=true
```

Alternatively, telemetry can be disabled by using the `--disable-telemetry` flag when executing idsec commands:

```shell
idsec exec --disable-telemetry
```

When telemetry is disabled, only application metadata is collected.

## License

This project is licensed under Apache License 2.0 - see [`LICENSE`](LICENSE.txt) for more details

Copyright (c) 2026 CyberArk Software Ltd. All rights reserved.
