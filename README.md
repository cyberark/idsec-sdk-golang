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

CyberArk's Official SDK and CLI for different services operations

## Features and Services
- [x] Extensive and Interactive CLI
- [x] Different Authenticators
    - [x] Identity Authentication Methods
    - [x] MFA Support for Identity
    - [x] Identity Security Platform
- [x] Ready to use SDK in Golang
- [x] Fully Interactive CLI comprising of main actions
    - [x] Configure
    - [x] Login
    - [x] Exec
    - [x] Profiles
    - [x] Cache
    - [x] Upgrade
- [x] Services API
  - [x] SIA SSO Service
  - [x] SIA K8S Service
  - [x] SIA VM Secrets Service
  - [x] SIA DB Secrets Service
  - [x] SIA Target Sets Workspace Service
  - [x] SIA DB Workspace Service
  - [x] SIA Access Service
  - [x] SIA SSH CA Key Service
  - [x] SIA DB Service
  - [x] SIA Shortened Connection String Service
  - [x] SIA Settings Service
  - [x] SIA Certificates Service
  - [x] Connector Manager Service
  - [x] PCloud Accounts Service
  - [x] PCloud Safes Service
  - [x] PCloud Platforms Service
  - [x] Identity Directories Service
  - [x] Identity Roles Service
  - [x] Identity Users Service
  - [x] Secrets Hub Secret Stores Service
  - [x] Secrets Hub Secrets Service
  - [x] Secrets Hub Sync Policies Service
  - [x] Secrets Hub Scans Service
  - [x] Secrets Hub Service Info Service
  - [x] Secrets Hub Configuration Service
  - [x] Secrets Hub Filters Service
  - [x] Session Monitoring Service
  - [x] Unified Access Policies Service
    - [x] SCA - Secure Cloud Access
    - [x] DB - Databases
    - [x] VM - Virtual Machines
- [x] Filesystem Inputs and Outputs for the CLI
- [x] Silent and Verbose logging
- [x] Profile Management and Authentication Caching

### Supported Environments

Here's the list of `AwsEnv` values from `AwsEnvList` in Markdown format:
#### Standard Cloud Environments

- `prod`

#### Government Cloud Environments

- `gov-prod`

TL;DR
=====

## Enduser


SDK Usage
=========
As well as using the CLI, one can also develop under the idsec sdk using its API / class driven design

The same idea as the CLI applies here as well

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

More examples can be found in the [examples](examples) folder

Terraform Provider Integration
===============================

## Managing Immutable Attributes

The SDK supports defining immutable attributes for Terraform resources. Immutable attributes are fields that cannot be changed after resource creation - any attempt to modify them will cause the Terraform plan to fail with an error, preventing accidental changes to resource identity fields.

### What are Immutable Attributes?

Immutable attributes represent the identity of a resource. Changing these would fundamentally alter what resource is being managed, so they are protected from modification. Examples include:

- Resource IDs (e.g., `entra_id`, `subscription_id`)
- Resource names that serve as identifiers
- Parent references (e.g., tenant IDs)

### How to Define Immutable Attributes

To mark attributes as immutable, add the `ImmutableAttributes` field to your Terraform action definition:

```go
var TerraformActionEntraResource = &actions.IdsecServiceTerraformResourceActionDefinition{
    IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
        IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
            ActionName:        "cce-azure-entra",
            ActionDescription: "CCE Azure Entra resource",
            ActionVersion:     1,
            Schemas:           ActionToSchemaMap,
        },
        ExtraRequiredAttributes: []string{},
        ImmutableAttributes: []string{
            "entra_id",
            "entra_tenant_name",
        },
        StateSchema: &azuremodels.TfIdsecCCEAzureEntra{},
    },
    // ... rest of definition
}
```

### Adding Immutable Attributes to Existing Resources

1. **Identify identity fields** - Determine which fields uniquely identify the resource
2. **Add to action definition** - Update the `ImmutableAttributes` slice in the Terraform action
3. **Test thoroughly** - Verify that:
   - Resource creation works
   - Updates to non-immutable fields succeed
   - Attempts to change immutable fields fail with clear error messages

Example for a new AWS account resource:

```go
var TerraformActionAWSAccountResource = &actions.IdsecServiceTerraformResourceActionDefinition{
    IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
        // ... base definition ...
        ImmutableAttributes: []string{
            "account_id",      // AWS account ID cannot change
            "account_name",    // Account name is part of identity
        },
        StateSchema: &awsmodels.TfIdsecCCEAWSAccount{},
    },
    // ... rest of definition
}
```

### Removing Immutable Attributes

To remove immutability protection from an attribute:

1. Remove the attribute name from the `ImmutableAttributes` slice
2. Consider the impact on existing Terraform state files
3. Document the change as a breaking change in release notes

**Warning:** Removing immutability is a breaking change. Users who upgrade will be able to modify previously protected fields, which may lead to unexpected resource replacements.

### Best Practices

- **Only mark true identity fields as immutable** - Don't overuse this feature
- **Use centralized configuration** - The `ImmutableAttributes` field keeps all immutable attributes in one place for easy maintenance
- **Provide clear descriptions** - Document why a field is immutable in the `desc` tag
- **Test with Terraform** - Verify the behavior in actual Terraform workflows
- **Consider backwards compatibility** - Adding immutability to existing resources is a breaking change

### Terraform User Experience

When a user attempts to change an immutable attribute, they will see:

```text
Error: Immutable Attribute Cannot Be Changed

  with idsec_cce_azure_entra.example,
  on main.tf line 2, in resource "idsec_cce_azure_entra" "example":
   2:   entra_id = "new-uuid"

The attribute 'entra_id' is immutable and cannot be changed after resource creation.

Current value: old-uuid
Attempted new value: new-uuid

To use a different value, you must create a new resource.
```

This prevents accidental modifications and guides users toward the correct approach.

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

Copyright (c) 2025 CyberArk Software Ltd. All rights reserved.
