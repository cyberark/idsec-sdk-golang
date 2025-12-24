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

Installation
============

One can install the SDK via the community pypi with the following command:
```shell
export GOPRIVATE=1
git config --global url.\"https://<artifactoryUser>:<artifactoryToken>@github.com\".insteadOf \"https://github.com\"
go install github.com/cyberark/idsec-sdk-golang/cmd/idsec@latest
```

CLI Usage
============
Both the SDK and the CLI works with profiles

The profiles can be configured upon need and be used for the consecutive actions

The CLI has the following basic commands:
- <b>configure</b> - Configures profiles and their respective authentication methods
- <b>login</b> - Logs into the profile authentication methods
- <b>exec</b> - Executes different commands based on the supported services
- <b>profiles</b> - Manage multiple profiles on the machine
- <b>cache</b> - Manage the cache of the authentication methods
- <b>upgrade</b> - Upgrade the CLI to the latest version


configure
---------
The configure command is used to create a profile to work on<br>
The profile consists of infomration regarding which authentication methods to use and what are their method settings, along with other related information such as MFA

How to run:
```shell
idsec configure
```


The profiles are saved to ~/.idsec_profiles

No arguments are required, and interactive questions will be asked

If you wish to only supply arguments in a silent fashion, --silent can be added along with the arugments

Usage:
```shell
Configure the CLI

Usage:
  idsec configure [flags]

Flags:
      --allow-output                                    Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification                       Disables certificate verification on HTTPS calls, unsafe!
  -h, --help                                            help for configure
      --isp-auth-method string                          Authentication method for Identity Security Platform (default "default")
      --isp-identity-application string                 Identity Application
      --isp-identity-authorization-application string   Service User Authorization Application
      --isp-identity-mfa-interactive                    Allow Interactive MFA
      --isp-identity-mfa-method string                  MFA Method to use by default [pf, sms, email, otp]
      --isp-identity-tenant-subdomain string            Identity Tenant Subdomain
      --isp-identity-url string                         Identity Url
      --isp-username string                             Username
      --log-level string                                Log level to use while verbose (default "INFO")
      --logger-style string                             Which verbose logger style to use (default "default")
      --profile-description string                      Profile Description
      --profile-name string                             The name of the profile to use
      --raw                                             Whether to raw output
      --silent                                          Silent execution, no interactiveness
      --trusted-cert string                             Certificate to use for HTTPS calls
      --verbose                                         Whether to verbose log
      --work-with-isp                                   Whether to work with Identity Security Platform services
```


login
-----
The login command is used to login to the authentication methods configured for the profile

You will be asked to write a password for each respective authentication method that supports password, and alongside that, any needed MFA prompt

Once the login is done, the access tokens are stored on the computer keystore for their lifetime

Once they are expired, a consecutive login will be required

How to run:
```shell
idsec login
```

Usage:
```shell
Login to the system

Usage:
  idsec login [flags]

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
      --force                       Whether to force login even though token has not expired yet
  -h, --help                        help for login
      --isp-secret string           Secret to authenticate with to Identity Security Platform
      --isp-username string         Username to authenticate with to Identity Security Platform
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --no-shared-secrets           Do not share secrets between different authenticators with the same username
      --profile-name string         Profile name to load (default "idsec")
      --raw                         Whether to raw output
      --refresh-auth                If a cache exists, will also try to refresh it
      --show-tokens                 Print out tokens as well if not silent
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log
```

Notes:

- You may disable certificate validation for login to different authenticators using the --disable-certificate-verification or supply a certificate to be used, not recommended to disable


exec
----
The exec command is used to execute various commands based on supported services for the fitting logged in authenticators

The following services and commands are supported:
- <b>sia</b> - Secure Infrastructure Access Services
  - <b>sso</b> - SIA SSO Management
  - <b>k8s</b> - SIA K8S Management
  - <b>db</b> - SIA DB Management
  - <b>workspaces</b> - SIA Workspaces Management
    - <b>target-sets</b> - SIA VM Target Sets Management
  - <b>secrets</b> - SIA Secrets Management
    - <b>vm</b> - SIA VM Secrets Management
    - <b>db</b> - SIA DB Secrets Management
  - <b>access</b> - SIA Access Management
  - <b>ssh-ca</b> - SIA SSH Ca Key Management
  - <b>settings</b> - SIA Settings Management
  - <b>certificates</b> - SIA Certificates Management
- <b>cmgr</b> - Connector Manager
- <b>pcloud</b> - PCloud Service
  - <b>accounts</b> - PCloud Accounts Management
  - <b>safes</b> - PCloud Safes Management
- <b>identity</b> - Identity Service
  - <b>directories</b> - Identity Directories Management
  - <b>roles</b> - Identity Roles Management
  - <b>users</b> - Identity Users Management
- <b>uap</b> - Unified Access Policies Services
  - <b>sca</b> - secure cloud access policies management
  - <b>db</b> - databases access policies management
  - <b>vm</b> - virtual machines access policies management

Any command has its own subcommands, with respective arguments

For example, generating a short lived password for DB
```shell
idsec exec sia sso short-lived-password
```

Or a short lived password for RDP
```shell
idsec exec sia sso short-lived-password --service DPA-RDP
```

Add SIA VM Target Set
```shell
idsec exec sia workspaces target-sets add-target-set --name mydomain.com --type Domain
```

Add SIA VM Secret
```shell
idsec exec sia secrets vm add-secret --secret-type ProvisionerUser --provisioner-username=myuser --provisioner-password=mypassword
```

List connector pools
```shell
idsec exec exec cmgr list-pools
```

Get connector installation script
```shell
idsec exec sia access connector-setup-script --connector-type ON-PREMISE --connector-os windows --connector-pool-id 588741d5-e059-479d-b4c4-3d821a87f012
```

Create a PCloud Safe
```shell
idsec exec pcloud safes add-safe --safe-name=safe
```

Create a PCloud Account
```shell
idsec exec pcloud accounts add-account --name account --safe-name safe --platform-id='UnixSSH' --username root --address 1.2.3.4 --secret-type=password --secret mypass
```

Retrieve a PCloud Account Credentials
```shell
idsec exec pcloud accounts get-account-credentials --account-id 11_1
```

Create an Identity User
```shell
idsec exec identity users create-user --roles "DpaAdmin" --username "myuser"
```

Create an Identity Role
```shell
idsec exec identity roles create-role --role-name myrole
```

List all directories identities
```shell
idsec exec identity directories list-directories-entities
```

Add SIA Database Secret
```shell
idsec exec sia secrets db add-strong-account --store-type managed --name "my-postgres-account" --platform PostgreSQL --address "db.example.com" --username "dbuser" --port 5432 --database "mydb" --password "mypassword"
```

Delete SIA Database Secret
```shell
idsec exec sia secrets db delete-secret --secret-name mysecret
```

Add SIA database
```shell
idsec exec sia workspaces db add-database --name mydatabase --provider-engine aurora-mysql --read-write-endpoint myrds.com
```

Delete SIA database
```shell
idsec exec sia workspaces db delete-database --id databaseid
```

List all SIA Settings
```shell
idsec exec sia settings list-settings
```

Get specific SIA setting
```shell
idsec exec sia settings adb-mfa-caching
```

Set specific SIA setting
```shell
idsec exec sia settings set-rdp-mfa-caching --is-mfa-caching-enabled=true --client-ip-enforced=false
```

Get Secrets Hub Configuration
```shell
idsec exec sechub configuration get-configuration
```
Set Secrets Hub Configuration
```shell
idsec exec sechub configuration set-configuration --sync-settings 360
```

Get Secrets Hub Filters
```shell
idsec exec sechub filters get-filters --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```
Add Secrets Hub Filter
```shell
idsec exec sechub filters add-filter --type "PAM_SAFE" --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667 --data-safe-name "example-safe"
```
Delete Secrets Hub Filter
```shell
idsec exec sechub filters delete-filter --filter-id filter-7f3d187d-7439-407f-b968-ec27650be692 --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

Get Secrets Hub Scans
```shell
idsec exec sechub scans get-scans
```
Trigger Secrets Hub Scan
```shell
idsec exec sechub scans trigger-scan --id default --secret-stores-ids store-e488dd22-a59c-418c-bbe3-3f061dd9b667 type secret-store
```

Create Secrets Hub Secret Store
```shell
idsec exec sechub secret-stores create-secret-store --type AWS_ASM --description sdk-testing --name "SDK Testing" --state ENABLED --data-aws-account-alias ALIAS-NAME-EXAMPLE --data-aws-region-id us-east-1 --data-aws-account-id 123456789123 --data-aws-rolename Secrets-Hub-IAM-Role-Name-Created-For-Secrets-Hub
```
Retrieve Secrets Hub Secret Store
```shell
idsec exec sechub secret-stores get-secret-store --secret-store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```
Update Secrets Hub Secret Store
```shell
idsec exec sechub secret-stores update-secret-store --secret-store-id store-7f3d187d-7439-407f-b968-ec27650be692 --name "New Name" --description "Updated Description" --data-aws-account-alias "Test2"
```
Delete Secrets Hub Secret Store
```shell
idsec exec sechub secret-stores delete-secret-store --secret-store-id store-fd11bc7c-22d0-4d9b-ac1b-f8458161935f
```

Get Secrets Hub Secrets
```shell
idsec exec sechub secrets get-secrets
```
Get Secrets Hub Secrets using a filter
```shell
idsec exec sechub secrets get-secrets-by --limit 5 --projection EXTEND --filter "name CONTAINS EXAMPLE"
```

Get Secrets Hub Service Information
```shell
idsec exec sechub service-info get-service-info
```

Get Secrets Hub Sync Policies
```shell
idsec exec sechub sync-policies get-sync-policies
```
Get Secrets Hub Sync Policy
```shell
idsec exec sechub sync-policies get-sync-policy --policy-id policy-7f3d187d-7439-407f-b968-ec27650be692 --projection EXTEND
```
Create Secrets Hub Sync Policy
```shell
idsec exec sechub sync-policies create-sync-policy --name "New Sync Policy" --description "New Sync Policy Description" --filter-type PAM_SAFE --filter-data-safe-name EXAMPLE-SAFE-NAME --source-id store-e488dd22-a59c-418c-bbe3-3f061dd12367 --target-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```
Delete Secrets Hub Sync Policy
```shell
idsec exec sechub sync-policies delete-sync-policy --policy-id policy-7f3d187d-7439-407f-b968-ec27650be692
```

List Sessions
```shell
idsec exec sm list-sessions
```

Count Sessions
```shell
idsec exec sm count-sessions
```

List Sessions By Filter
```shell
idsec exec sm list-sessions-by --search "duration LE 01:00:00"
```

Count Sessions By Filter
```shell
idsec exec sm count-sessions-by --search "command STARTSWITH ls"
```

Get Session
```shell
idsec exec sm get-session --session-id my-id
```

List Session Activities
```shell
idsec exec sm list-session-activities --session-id my-id
```


Count Session Activities
```shell
idsec exec sm count-session-activities --session-id my-id
```

List Session Activities By Filter
```shell
idsec exec sm list-session-activities-by --session-id my-id --command-contains "ls"
```

Count Session Activities By Filter
```shell
idsec exec sm count-sessions-by --session-id my-id --command-contains "chmod"
```

Get Sessions Statistics
```shell
idsec exec sm get-sessions-stats
```

List all UAP policies
```shell
idsec exec uap list-policies
```

Delete UAP DB Policy
```shell
idsec exec uap db delete-policy --policy-id my-policy-id
```

List DB Policies from UAP
```shell
idsec exec uap db list-policies
```

Get DB Policy from UAP
```shell
idsec exec uap db policy --policy-id my-policy-id
```

Add UAP DB Policy
```shell
idsec exec uap db add-policy --request-file /path/to/policy-request.json
```

List UAP SCA Policies
```shell
idsec exec uap sca list-policies
```

Get UAP SCA Policy
```shell
idsec exec uap sca policy --policy-id my-policy-id
```

Add UAP SCA Policy
```shell
idsec exec uap sca add-policy --request-file /path/to/policy-request.json
```

Delete UAP SCA Policy
```shell
idsec exec uap sca delete-policy --policy-id my-policy-id
```

List VM Policies from UAP
```shell
idsec exec uap vm list-policies
```

Get VM Policy from UAP
```shell
idsec exec uap vm policy --policy-id my-policy-id
```

Delete VM Policy from UAP
```shell
idsec exec uap vm delete-policy --policy-id my-policy-id
```

Connect to MySQL ZSP with the mysql cli via Idsec CLI
```shell
idsec exec sia db mysql --target-address myaddress.com
```

Connect to PostgreSQL Vaulted with the psql cli via Idsec CLI
```shell
idsec exec sia db psql --target-address myaddress.com --target-user myuser
```

Generate a connection string alias for a given raw connection string
```shell
idsec exec sia shortened-connection-string generate --raw-connection-string=jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639
```

Install SIA SSH public key on a target machine
```shell
idsec exec sia ssh-ca install-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

Remove SIA SSH public key from a target machine
```shell
idsec exec sia ssh-ca uninstall-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

Check if SIA SSH public key is installed on a target machine
```shell
idsec exec sia ssh-ca is-public-key-installed --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

Add a SIA certificate
```shell
idsec exec sia certificates add-certificate --cert-name name --cert-type PEM --file /path/to/cert.crt
```

Update a SIA certificate
```shell
idsec exec sia certificates update-certificate --certificate-id cert-id --cert-name new-name --file /path/to/new-cert.crt
```

List all SIA certificates
```shell
idsec exec sia certificates list-certificates
```

Import a pCloud Platform
```shell
idsec exec pcloud platforms import-platform --platform-zip-path /path/to/zip
```

Import a pCloud Target Platform
```shell
idsec exec pcloud platforms import-target-platform --platform-zip-path /path/to/zip
```

Export a pCloud Platform
```shell
idsec exec pcloud platforms export-platform --platform-id myid --output-folder /path/to/folder
```

Export a pCloud Target Platform
```shell
idsec exec pcloud platforms export-target-platform --target-platform-id 123 --output-folder /path/to/folder
```

List pCloud Target Platforms
```shell
idsec exec pcloud platforms list-target-platforms
```

Activate a pCloud Target Platform
```shell
idsec exec pcloud platforms activate-target-platform --target-platform-id 123
```

Deactivate a pCloud Target Platform
```shell
idsec exec pcloud platforms deactivate-target-platform --target-platform-id 123
```

Delete a pCloud Target Platform
```shell
idsec exec pcloud platforms delete-target-platform --target-platform-id 123
```


You can view all of the commands via the --help for each respective exec action

Notes:

- You may disable certificate validation for login to different authenticators using the --disable-certificate-verification or supply a certificate to be used, not recommended to disable


Useful Env Vars:
- IDSEC_PROFILE - Sets the profile to be used across the CLI
- IDSEC_DISABLE_CERTIFICATE_VERIFICATION - Disables certificate verification on REST API's


profiles
-------
As one may have multiple environments to manage, this would also imply that multiple profiles are required, either for multiple users in the same environment or multiple tenants

Therefore, the profiles command manages those profiles as a convenice set of methods

Using the profiles as simply running commands under:
```shell
idsec profiles
```

Usage:
```shell
Manage profiles

Usage:
  idsec profiles [command]

Available Commands:
  add         Add a profile from a given path
  clear       Clear all profiles
  clone       Clone a profile
  delete      Delete a specific profile
  edit        Edit a profile interactively
  list        List all profiles
  show        Show a profile

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
      --disable-telemetry           Disables telemetry data collection
  -h, --help                        help for profiles
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --raw                         Whether to raw output
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log

Use "idsec profiles [command] --help" for more information about a command.
```


cache
-------
Use the cache command to manage the Idsec data cached on your machine. Currently, you can only clear the filesystem cache (not data cached in the OS's keystore).


Using the cache as simply running commands under:
```shell
idsec cache
```

Usage:
```shell
Manage cache

Usage:
  idsec cache [command]

Available Commands:
  clear       Clears all profiles cache

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
  -h, --help                        help for cache
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --raw                         Whether to raw output
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log

Use "idsec cache [command] --help" for more information about a command.
```


upgrade
-------

Use the `upgrade` command to upgrade to the latest idsec version or check what is the latest.

Using the upgrade as simply running:
```shell
idsec upgrade
```

Usage:
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

## License

This project is licensed under Apache License 2.0 - see [`LICENSE`](LICENSE.txt) for more details

Copyright (c) 2025 CyberArk Software Ltd. All rights reserved.
