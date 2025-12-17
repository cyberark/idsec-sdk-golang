---
title: Services
description: Services
---

# Services

SDK services are defined to execute requests on available ISP services (such as SIA). When a service is initialized, a valid authenticator is required to authorize access to the ISP service. To perform service actions, each service exposes a set of classes and methods.

Here's an example that initializes the `IdsecCmgrService` service:

```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	cmgrmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr"
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

	// Configure a network, pool and identifiers
	cmgrService, err := cmgr.NewIdsecCmgrService(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	network, err := cmgrService.AddNetwork(&cmgrmodels.IdsecCmgrAddNetwork{Name: "tlv"})
	if err != nil {
		panic(err)
	}
	pool, err := cmgrService.AddPool(&cmgrmodels.IdsecCmgrAddPool{Name: "tlvpool", AssignedNetworkIDs: []string{network.ID}})
	if err != nil {
		panic(err)
	}
	identifier, err := cmgrService.AddPoolIdentifier(&cmgrmodels.IdsecCmgrAddPoolSingleIdentifier{PoolID: pool.ID, Type: cmgrmodels.GeneralFQDN, Value: "mymachine.tlv.com"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Added pool: %s\n", pool.ID)
	fmt.Printf("Added network: %s\n", network.ID)
	fmt.Printf("Added identifier: %s\n", identifier.ID)
}
```

The above example authenticates to the specified ISP tenant, initializes a CMGR service using the authorized authenticator, and then uses the service to add a network and pool.

## Secure Infrastructure Access service

The Secure Infrastructure Access (sia) service requires the IdsecISPAuth authenticator, and exposes these service classes:

- **IdsecSIAAccessService** (access) - SIA access service
- **IdsecSIASSHCAService** (ssh-ca) - SIA SSH CA Key service
- **IdsecSIAK8SService** (Kubernetes) - SIA end-user Kubernetes service
- **IdsecSIADBService** (Db) - SIA end-user Db service
- **IdsecSIASecretsService** (secrets) - SIA secrets management
    - **IdsecSIAVMSecretsService** (VM) - SIA VM secrets services
    - **IdsecSIADBSecretsService** (DB) - SIA DB secrets services
- **IdsecSIASSOService** (SSO) - SIA end-user SSO service
- **IdsecSIADatabasesService** (databases) - SIA end-user databases service
- **IdsecSIAWorkspacesService** (workspaces) - SIA workspaces management
    - **IdsecSIATargetSetsWorkspaceService** (target-sets) - SIA Target Sets workspace management
    - **IdsecSIADBWorkspaceService** (db) - SIA DB workspace management
- **IdsecSIASSHCAService** (ssh-ca) - SIA SSH CA Key service
- **IdsecSIAShortenedConnectionStringService** (shortened-connection-string) - SIA Shortened connection string service
- **IdsecSIASettingsService** (settings) - SIA Settings service
- **IdsecSIACertificatesService** (certificates) - SIA Certificates service


## Identity service
The Identity (identity) service requires the IdsecISPAuth authenticator, and exposes those service classes:

- **IdsecIdentityRolesService** - Identity roles service
- **IdsecIdentityUsersService** - Identity users service
- **IdsecIdentityDirectoriesService** - Identity directories service


## Privilege Cloud service
The Privilege Cloud (pCloud) service requires the IdsecISPAuth authenticator, and exposes those service classes:

- **IdsecPCloudAccountsService** - Accounts management service
- **IdsecPCloudSafesService** - Safes management service
- **IdsecPCloudPlatformsService** - Platforms management service


## Connector Manager Service
The Connector Manager (cmgr) service requires the IdsecISPAuth authenticator, and exposes those service classes:

- **IdsecCmgrService** - Connector Manager service

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

- **IdsecSMService** - Session Monitoring service

## UAP
The Unified Access Policies (uap) service requires the IdsecISPAuth authenticator, and exposes those service classes:
- **IdsecUAPService** - Unified Access Policies service
  - **IdsecUAPSCAService** - Unified Access Policies SCA service
  - **IdsecUAPSIADBService** - Unified Access Policies SIA DB service
  - **IdsecUAPSIAVMService** - Unified Access Policies SIA VM service
