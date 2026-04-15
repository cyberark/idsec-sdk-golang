---
title: Services
description: Services
---

# Services

SDK services are defined to execute requests on available ISP services (such as SIA). When a service is initialized, a valid authenticator is required to authorize access to the ISP service. To perform service actions, each service exposes a set of classes and methods.

Here's an example that initializes the `IdsecCmgrAPI` and uses its resource services:

```go
package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr"
	networksmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/networks/models"
	identifiersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolidentifiers/models"
	poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"
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

	// Configure a network, pool and identifiers using the CMGR API
	cmgrAPI, err := cmgr.NewIdsecCmgrAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	network, err := cmgrAPI.Networks().Create(&networksmodels.IdsecCmgrAddNetwork{Name: "tlv"})
	if err != nil {
		panic(err)
	}
	pool, err := cmgrAPI.Pools().Create(&poolsmodels.IdsecCmgrAddPool{Name: "tlvpool", AssignedNetworkIDs: []string{network.NetworkID}})
	if err != nil {
		panic(err)
	}
	identifier, err := cmgrAPI.PoolIdentifiers().Create(&identifiersmodels.IdsecCmgrAddPoolSingleIdentifier{PoolID: pool.PoolID, Type: identifiersmodels.GeneralFQDN, Value: "mymachine.tlv.com"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Added pool: %s\n", pool.PoolID)
	fmt.Printf("Added network: %s\n", network.NetworkID)
	fmt.Printf("Added identifier: %s\n", identifier.IdentifierID)
}
```

The above example authenticates to the specified ISP tenant, initializes a CMGR API using the authorized authenticator, and then uses the resource services to add a network, pool, and identifier.

## Secure Infrastructure Access service

The Secure Infrastructure Access (sia) service requires the IdsecISPAuth authenticator, and exposes these service classes:

- **IdsecSIAAccessService** (access) - SIA access service
- **IdsecSIASSHCAService** (ssh-ca) - SIA SSH CA Key service
- **IdsecSIAK8SService** (Kubernetes) - SIA end-user Kubernetes service
- **IdsecSIADBService** (Db) - SIA end-user Db service
- **IdsecSIASecretsDBService** (secrets-db) - SIA DB secrets services
- **IdsecSIASecretsVMService** (secrets-vm) - SIA VM secrets services
- **IdsecSIASSOService** (SSO) - SIA end-user SSO service
- **IdsecSIADatabasesService** (databases) - SIA end-user databases service
- **IdsecSIAWorkspacesDBService** (workspaces-db) - SIA DB workspace management
- **IdsecSIAWorkspacesTargetSetsService** (workspaces-target-sets) - SIA Target Sets workspace management
- **IdsecSIASSHCAService** (ssh-ca) - SIA SSH CA Key service
- **IdsecSIAShortenedConnectionStringService** (shortened-connection-string) - SIA Shortened connection string service
- **IdsecSIASettingsService** (settings) - SIA Settings service
- **IdsecSIACertificatesService** (certificates) - SIA Certificates service


## Identity service
The Identity (identity) service requires the IdsecISPAuth authenticator, and exposes those service classes:

- **IdsecIdentityRolesService** - Identity roles service
- **IdsecIdentityUsersService** - Identity users service
- **IdsecIdentityDirectoriesService** - Identity directories service
- **IdsecIdentityAuthProfilesService** - Identity auth profiles service
- **IdsecIdentityPoliciesService** - Identity policies service
- **IdsecIdentityWebappsService** - Identity webapps service


## Privilege Cloud service
The Privilege Cloud (pCloud) service requires the IdsecISPAuth authenticator, and exposes those service classes:

- **IdsecPCloudAccountsService** - Accounts management service
- **IdsecPCloudSafesService** - Safes management service
- **IdsecPCloudPlatformsService** - Platforms management service
- **IdsecPCloudApplicationsService** - Applications management service


## Connector Manager Service
The Connector Manager (cmgr) service requires the IdsecISPAuth authenticator, and exposes those service classes:

- **IdsecCmgrAPI** - Connector Manager API accessor that provides access to:
    - **IdsecCmgrNetworksService** (networks) - Networks management service
    - **IdsecCmgrPoolsService** (pools) - Pools management service
    - **IdsecCmgrPoolIdentifiersService** (pool-identifiers) - Pool identifiers management service
    - **IdsecCmgrPoolComponentsService** (pool-components) - Pool components management service

## Secrets Hub service
The Secrets Hub (sechub) service requires the IdsecISPAuth authenticator, and exposes those service classes:

- **IdsecSecHubConfigurationService** - Configuration service
- **IdsecSecHubSecretsService** - Secrets service
- **IdsecSecHubScansService** - Scans service
- **IdsecSecHubSecretStoresService** - Secret Stores service
- **IdsecSecHubServiceInfoService** - Service Info service
- **IdsecSecHubFiltersService** - Filter service

## Session Monitoring service
The Session Monitoring (sm) service requires the IdsecISPAuth authenticator, and exposes those service classes:

- **IdsecSMSessionsService** (sessions) - Session monitoring and management operations
- **IdsecSMSessionActivitiesService** (session-activities) - Session activity monitoring and filtering operations

## Policy
The Access Control Policies (policy) service requires the IdsecISPAuth authenticator, and exposes those service classes:
- **IdsecPolicyService** - Access Control Policies service
  - **IdsecPolicyCloudAccessService** - Access Control Policies Cloud Access service
  - **IdsecPolicyDBService** - Access Control Policies DB service
  - **IdsecPolicyVMService** - Access Control Policies VM service

## Enable Attribute

The Enable attribute controls the availability of services and actions. It is useful for hiding features that are still in development.

### Disabling a Service

To disable a service, set `Enabled` to `false` in the service configuration. The service will not be registered at startup.

```go
var ServiceConfig = services.IdsecServiceConfig{
    ServiceName: "my-service",
    Enabled:     boolPtr(false),  // Service is disabled
    RequiredAuthenticatorNames: []string{"isp"},
    ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
        // ...
    },
}

func boolPtr(b bool) *bool { return &b }
```

### Disabling an Action

To disable an action, set `Enabled` to `false` in the action definition. The action will be removed before registration.

```go
var TerraformAction = &actions.IdsecServiceTerraformResourceActionDefinition{
    IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
        IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
            ActionName: "my-resource",
            Enabled:    boolPtr(false),  // Action is disabled
        },
    },
}
```

### Default Behavior

If `Enabled` is not set (nil), the service or action is enabled. This keeps the SDK backwards compatible with existing code.

### Build Flag

The Enable attribute filtering is controlled by a build flag. By default, filtering is OFF and all services and actions are available.

To enable filtering for release builds, use:

```bash
go build -ldflags "-X github.com/cyberark/idsec-sdk-golang/pkg/services.releasedFeaturesOnly=true" ./...
```

When the flag is set to `true`, services and actions with `Enabled: false` are excluded from registration.
