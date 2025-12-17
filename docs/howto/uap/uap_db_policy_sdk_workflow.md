---
title: UAP database policy SDK workflow
description: Creating a UAP DB Policy using Idsec SDK
---

# UAP database policy SDK workflow
Here is an example workflow for adding a UAP DB policy alongside all needed assets via the SDK:

```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	dbsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/db/models"
	dbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"
	commonuapmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsia "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/common/models"
	uapdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
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
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}

	account, err := siaAPI.SecretsDB().AddStrongAccount(
		&dbsecretsmodels.IdsecSIADBAddStrongAccount{
			StoreType: "managed",
			Platform:  "MySQL",
			Name: "MyCoolAccount",
			Username:   "CoolUser",
			Password:   "CoolPassword",
			Address:   "myrds.com",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Account ID:", account.ID)

	// Add the database with the created account
	database, err := siaAPI.WorkspacesDB().AddDatabase(
		&dbmodels.IdsecSIADBAddDatabase{
			Name:              "MyDatabase",
			ProviderEngine:    dbmodels.EngineTypeAuroraMysql,
			ReadWriteEndpoint: "myrds.com",
			SecretID:          account.ID,
		},
	)

	if err != nil {
		panic(err)
	}
	fmt.Printf("Database: %v\n", database)

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
							InstanceName:         database.Name,
							InstanceType:         database.ProviderDetails.Family,
							InstanceID:           string(rune(database.ID)),
							AuthenticationMethod: uapdbmodels.AuthMethodDBAuth,
							DBAuthProfile: &uapdbmodels.IdsecUAPSIADBDBAuthProfile{
								Roles: []string{"db_reader", "db_writer"},
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

In the script above, the following actions are defined:

- The admin user is logged in to perform actions on the tenant
- we then configure SIA's secret, database and UAP DB policy
