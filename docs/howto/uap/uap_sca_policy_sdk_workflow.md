---
title: UAP SCA policy SDK workflow
description: Creating a UAP SCA Policy using Idsec SDK
---

# UAP SCA policy SDK workflow
Here is an example workflow for adding a UAP SCA policy assets via the SDK:

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

In the script above, the following actions are defined:

- The admin user is logged in to perform actions on the tenant
- we then configure UAP SCA policy
