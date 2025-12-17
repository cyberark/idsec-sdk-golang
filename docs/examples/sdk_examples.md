---
title: SDK Examples
description: SDK Examples
---

# SDK Examples
Using the SDK is similar to using the CLI.

## Short lived password example

In this example we authenticate to our ISP tenant and create a short-lived password:

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

	// Generate a short-lived password for RDP
	ssoPassword, err = ssoService.ShortLivedPassword(
		&ssomodels.IdsecSIASSOGetShortLivedPassword{
			Service: "DPA-RDP",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", ssoPassword)
}
```

## Target set example

In this example we authenticate to our ISP tenant and create a target set with a VM secret:

```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	vmsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/models"
	targetsetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/targetsets/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
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

	// Add a VM secret
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	secret, err := siaAPI.VMSecrets().AddSecret(
		&vmsecretsmodels.IdsecSIAVMAddSecret{
			SecretType:          "ProvisionerUser",
			ProvisionerUsername: "CoolUser",
			ProvisionerPassword: "CoolPassword",
		},
	)
	if err != nil {
		panic(err)
	}
	// Add VM target set
	targetSet, err := siaAPI.WorkspacesTargetSets().AddTargetSet(
		&targetsetsmodels.IdsecSIAAddTargetSet{
			Name:       "mydomain.com",
			Type:       "Domain",
			SecretID:   secret.SecretID,
			SecretType: secret.SecretType,
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Target set %s created\n", targetSet.Name)
}
```

## SIA settings example

In this example we authenticate to our ISP tenant and get and update SIA settings:

```go
package main

import (
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	settingsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings/models"
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
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}

	// Load all settings
	settings, err := siaAPI.Settings().ListSettings()
	if err != nil {
		panic(err)
	}
	settings.AdbMfaCaching.IsMfaCachingEnabled = common.Ptr(false)

	// Update settings
	_, err = siaAPI.Settings().SetSettings(settings)
	if err != nil {
		panic(err)
	}

	// Set specific setting partially
	adbMfa := &settingsmodels.IdsecSIASettingsAdbMfaCaching{
		KeyExpirationTimeSec: common.Ptr(7200),
		ClientIPEnforced:     common.Ptr(false),
	}
	_, err = siaAPI.Settings().SetAdbMfaCaching(adbMfa)
	if err != nil {
		panic(err)
	}
}
````


## CMGR example

In this example we authenticate to our ISP tenant and create a network, pool, and identifier:

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
	pool, err := cmgrService.AddPool(&cmgrmodels.IdsecCmgrAddPool{Name: "tlvpool", AssignedNetworkIDs: []string{network.NetworkID}})
	if err != nil {
		panic(err)
	}
	identifier, err := cmgrService.AddPoolIdentifier(&cmgrmodels.IdsecCmgrAddPoolSingleIdentifier{PoolID: pool.PoolID, Type: cmgrmodels.GeneralFQDN, Value: "mymachine.tlv.com"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Added pool: %s\n", pool.PoolID)
	fmt.Printf("Added network: %s\n", network.NetworkID)
	fmt.Printf("Added identifier: %s\n", identifier.IdentifierID)
}
```

## List pCloud Accounts

In this example we authenticate to our ISP tenant and list pCloud accounts:

```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud"
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

	// List all of the accounts
	pcloudAPI, err := pcloud.NewIdsecPCloudAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	accountsChan, err := pcloudAPI.Accounts().ListAccounts()
	if err != nil {
		panic(err)
	}
	for accountsPage := range accountsChan {
		for account := range accountsPage.Items {
			fmt.Printf("Account: %v\n", account)
		}
	}
}
```

## List identities

In this example we authenticate to our ISP tenant and list all of the accounts:

```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
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

	// List all identities
	identityAPI, err := identity.NewIdsecIdentityAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	identitiesChan, err := identityAPI.Directories().ListDirectoriesEntities(&directoriesmodels.IdsecIdentityListDirectoriesEntities{})
	if err != nil {
		panic(err)
	}
	for loadedIdentity := range identitiesChan {
		fmt.Printf("Identity: %v\n", loadedIdentity)
	}
}
```

## Session Monitoring

In this example we authenticate to our ISP tenant and get all the active sessions:
```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sm"
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

	SMAPI, err := sm.NewIdsecSMService(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	filter := &IdsecSMSessionsFilter{
		Search: "status IN Active",
	}
	// Get all active sessions
	activeSessions, err := SMAPI.CountSessionsBy(filter)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Total Active Sessions: %d\n", activeSessions)
}
```

## UAP

In this example we authenticate to our ISP tenant and create a UAP DB policy:
```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"
	commonuapmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsia "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/common/models"
	uapdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/uap"
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

	uapAPI, err := uap.NewIdsecUAPAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	policy, err := uapAPI.Db().AddPolicy(
		&uapdbmodels.IdsecUAPSIADBAccessPolicy{
			IdsecUAPSIACommonAccessPolicy: uapsia.IdsecUAPSIACommonAccessPolicy{
				IdsecUAPCommonAccessPolicy: commonuapmodels.IdsecUAPCommonAccessPolicy{
					Metadata: commonuapmodels.IdsecUAPMetadata{
						Name:        "Example DB Access Policy",
						Description: "This is an example of a DB access policy for SIA.",
						Status: commonuapmodels.IdsecUAPPolicyStatus{
							Status: commonuapmodels.StatusTypeActive,
						},
						PolicyEntitlement: commonuapmodels.IdsecUAPPolicyEntitlement{
							TargetCategory: commonmodels.CategoryTypeDB,
							LocationType:   commonmodels.WorkspaceTypeFQDNIP,
							PolicyType:     commonuapmodels.PolicyTypeRecurring,
						},
						PolicyTags: []string{},
					},
					Principals: []commonuapmodels.IdsecUAPPrincipal{
						{
							Type:                commonuapmodels.PrincipalTypeUser,
							ID:                  "user-id",
							Name:                "user@cyberark.cloud.12345",
							SourceDirectoryName: "CyberArk",
							SourceDirectoryID:   "12345",
						},
					},
				},
				Conditions: uapsia.IdsecUAPSIACommonConditions{
					IdsecUAPConditions: commonuapmodels.IdsecUAPConditions{
						AccessWindow: commonuapmodels.IdsecUAPTimeCondition{
							DaysOfTheWeek: []int{1, 2, 3, 4, 5},
							FromHour:      "09:00",
							ToHour:        "17:00",
						},
						MaxSessionDuration: 4,
					},
					IdleTime: 10,
				},
			},
			Targets: map[string]uapdbmodels.IdsecUAPSIADBTargets{
				commonmodels.WorkspaceTypeFQDNIP: {
					Instances: []uapdbmodels.IdsecUAPSIADBInstanceTarget{
						{
							InstanceName:         "example-db-instance",
							InstanceType:         db.FamilyTypeMSSQL,
							InstanceID:           "1",
							AuthenticationMethod: uapdbmodels.AuthMethodLDAPAuth,
							LDAPAuthProfile: &uapdbmodels.IdsecUAPSIADBLDAPAuthProfile{
								AssignGroups: []string{"mygroup"},
							},
						},
					},
				},
			},
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Policy created successfully: %s\n", policy.Metadata.PolicyID)
}
```

In this example we authenticate to our ISP tenant and create a UAP SIA VM policy:
```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	commonuapmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsia "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/common/models"
	uapvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/vm/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/uap"
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

	uapAPI, err := uap.NewIdsecUAPAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	policy, err := uapAPI.Vm().AddPolicy(
		&uapvmmodels.IdsecUAPSIAVMAccessPolicy{
			IdsecUAPSIACommonAccessPolicy: uapsia.IdsecUAPSIACommonAccessPolicy{
				IdsecUAPCommonAccessPolicy: commonuapmodels.IdsecUAPCommonAccessPolicy{
					Metadata: commonuapmodels.IdsecUAPMetadata{
						Name:        "Example VM Access Policy",
						Description: "This is an example of a VM access policy for SIA.",
						Status: commonuapmodels.IdsecUAPPolicyStatus{
							Status: commonuapmodels.StatusTypeActive,
						},
						PolicyEntitlement: commonuapmodels.IdsecUAPPolicyEntitlement{
							TargetCategory: commonmodels.CategoryTypeVM,
							LocationType:   commonmodels.WorkspaceTypeFQDNIP,
							PolicyType:     commonuapmodels.PolicyTypeRecurring,
						},
						PolicyTags: []string{},
					},
					Principals: []commonuapmodels.IdsecUAPPrincipal{
						{
							Type:                commonuapmodels.PrincipalTypeUser,
							ID:                  "user-id",
							Name:                "user@cyberark.cloud.12345",
							SourceDirectoryName: "CyberArk",
							SourceDirectoryID:   "12345",
						},
					},
				},
				Conditions: uapsia.IdsecUAPSIACommonConditions{
					IdsecUAPConditions: commonuapmodels.IdsecUAPConditions{
						AccessWindow: commonuapmodels.IdsecUAPTimeCondition{
							DaysOfTheWeek: []int{1, 2, 3, 4, 5},
							FromHour:      "09:00",
							ToHour:        "17:00",
						},
						MaxSessionDuration: 4,
					},
					IdleTime: 10,
				},
			},
			Targets: uapvmmodels.IdsecUAPSIAVMPlatformTargets{
				FQDNIPResource: &uapvmmodels.IdsecUAPSIAVMFQDNIPResource{
					FQDNRules: []uapvmmodels.IdsecUAPSIAVMFQDNRule{
						{
							Operator:            uapvmmodels.VMFQDNOperatorExactly,
							ComputernamePattern: "example-vm",
							Domain:              "mydomain.com",
						},
					},
				},
			},
			Behavior: uapvmmodels.IdsecUAPSSIAVMBehavior{
				SSHProfile: &uapvmmodels.IdsecUAPSSIAVMSSHProfile{
					Username: "root",
				},
				RDPProfile: &uapvmmodels.IdsecUAPSSIAVMRDPProfile{
					LocalEphemeralUser: &uapvmmodels.IdsecUAPSSIAVMEphemeralUser{
						AssignGroups: []string{"Remote Desktop Users"},
					},
				},
			},
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Policy created successfully: %s\n", policy.Metadata.PolicyID)
}
```

In this example we authenticate to our ISP tenant and create a UAP SCA policy:
```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	commonuapmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapscamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sca/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/uap"
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

	uapAPI, err := uap.NewIdsecUAPAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	policy, err := uapAPI.Sca().AddPolicy(
		&uapscamodels.IdsecUAPSCACloudConsoleAccessPolicy{
			IdsecUAPCommonAccessPolicy: commonuapmodels.IdsecUAPCommonAccessPolicy{
				Metadata: commonuapmodels.IdsecUAPMetadata{
					Name:        "Example SCA Access Policy",
					Description: "This is an example of a SCA access policy.",
					Status: commonuapmodels.IdsecUAPPolicyStatus{
						Status: commonuapmodels.StatusTypeValidating,
					},
					PolicyEntitlement: commonuapmodels.IdsecUAPPolicyEntitlement{
						TargetCategory: commonmodels.CategoryTypeCloudConsole,
						LocationType:   commonmodels.WorkspaceTypeAWS,
						PolicyType:     commonuapmodels.PolicyTypeRecurring,
					},
					PolicyTags: []string{},
				},
				Principals: []commonuapmodels.IdsecUAPPrincipal{
					{
						Type:                commonuapmodels.PrincipalTypeUser,
						ID:                  "user-id",
						Name:                "user@cyberark.cloud.12345",
						SourceDirectoryName: "CyberArk",
						SourceDirectoryID:   "12345",
					},
				},
			},
			Conditions: uapscamodels.IdsecUAPSCAConditions{
				IdsecUAPConditions: commonuapmodels.IdsecUAPConditions{
					AccessWindow: commonuapmodels.IdsecUAPTimeCondition{
						DaysOfTheWeek: []int{1, 2, 3, 4, 5},
						FromHour:      "09:00:00",
						ToHour:        "17:00:00",
					},
					MaxSessionDuration: 4,
				},
			},
			Targets: uapscamodels.IdsecUAPSCACloudConsoleTarget{
				AwsAccountTargets: []uapscamodels.IdsecUAPSCAAWSAccountTarget{
					{
						uapscamodels.IdsecUAPSCATarget{
							RoleID:        "arn:aws:iam::123456789012:role/ExampleRole",
							RoleName:      "ExampleRole",
							WorkspaceID:   "123456789012",
							WorkspaceName: "ExampleWorkspace",
						},
					},
				},
			},
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Policy created successfully: %s\n", policy.Metadata.PolicyID)
}
```

## Shortened connection string

In this example we authenticate to our ISP tenant and generate a shortened connection string:
```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	shortenedconnectionstringmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/shortenedconnectionstring/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/shortenedconnectionstring"
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

	// Generate a shortened connection string
	shortenedConnectionStringService, err := shortenedconnectionstring.NewIdsecSIAShortenedConnectionStringService(ispAuth)
	if err != nil {
		panic(err)
	}
	shortenedConnectionString, err := shortenedConnectionStringService.Generate(
		&shortenedconnectionstringmodels.IdsecSIAGenerateShortenedConnectionString{
			RawConnectionString: "jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Shortened Connection String: %s\n", shortenedConnectionString.ShortenedConnectionString)
}
```

## SIA certificate

In this example we authenticate to our ISP tenant and add a certificate:
```go
package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	certificatesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/models"
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
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}

	// Add a new certificate
	cert, err := siaAPI.Certificates().AddCertificate(
		&certificatesmodels.IdsecSIACertificatesAddCertificate{
			CertName:        "My New SIA Certificate",
			CertDescription: "Certificate added via SDK example",
			File:            "/path/to/file",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Added certificate: %+v\n", cert)
}
```

## pCloud Import Target Platform

In this example we authenticate to our ISP tenant and add a certificate:
```go
package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud"
	platformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/models"
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

	// Import and get the target platform
	pcloudAPI, err := pcloud.NewIdsecPCloudAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	importedPlatform, err := pcloudAPI.Platforms().ImportTargetPlatform(
		&platformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: "/path/to/platform.zip"},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Imported platform: %v\n", importedPlatform)
}
```
