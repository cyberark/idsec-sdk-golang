---
title: Database policy SDK workflow
description: Creating a DB Policy using Idsec SDK
---

# Database policy SDK workflow
Here is an example workflow for adding a DB policy alongside all needed assets via the SDK:

```go
package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy"
	policycommomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policydbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db/models"
	dbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacesdb/models"
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

	policyAPI, err := policy.NewIdsecPolicyAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	policy, err := policyAPI.Db().CreatePolicy(
		&policydbmodels.IdsecPolicyDBAccessPolicy{
			IdsecPolicyInfraCommonAccessPolicy: policycommomodels.IdsecPolicyInfraCommonAccessPolicy{
				IdsecPolicyCommonAccessPolicy: policycommomodels.IdsecPolicyCommonAccessPolicy{
					Metadata: policycommomodels.IdsecPolicyMetadata{
						Name:        "Example DB Access Policy",
						Description: "This is an example of a DB access policy for Infrastructure.",
						Status: policycommomodels.IdsecPolicyStatus{
							Status: policycommomodels.StatusTypeActive,
						},
						PolicyEntitlement: policycommomodels.IdsecPolicyEntitlement{
							TargetCategory: commonmodels.CategoryTypeDB,
							LocationType:   commonmodels.WorkspaceTypeFQDNIP,
							PolicyType:     policycommomodels.PolicyTypeRecurring,
						},
						PolicyTags: []string{},
					},
					Principals: []policycommomodels.IdsecPolicyPrincipal{
						{
							Type:                policycommomodels.PrincipalTypeUser,
							ID:                  "user-id",
							Name:                "user@cyberark.cloud.12345",
							SourceDirectoryName: "CyberArk",
							SourceDirectoryID:   "12345",
						},
					},
				},
				Conditions: policycommomodels.IdsecPolicyInfraCommonConditions{
					IdsecPolicyConditions: policycommomodels.IdsecPolicyConditions{
						AccessWindow: policycommomodels.IdsecPolicyTimeCondition{
							DaysOfTheWeek: []int{1, 2, 3, 4, 5},
							FromHour:      "09:00",
							ToHour:        "17:00",
						},
						MaxSessionDuration: 4,
					},
					IdleTime: 10,
				},
			},
			Targets: map[string]policydbmodels.IdsecPolicyDBTargets{
				commonmodels.WorkspaceTypeFQDNIP: {
					Instances: []policydbmodels.IdsecPolicyDBInstanceTarget{
						{
							InstanceName:         "example-db-instance",
							InstanceType:         dbmodels.FamilyTypeMSSQL,
							InstanceID:           "1",
							AuthenticationMethod: policydbmodels.AuthMethodLDAPAuth,
							LDAPAuthProfile: &policydbmodels.IdsecPolicyDBLDAPAuthProfile{
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

In the script above, the following actions are defined:

- The admin user is logged in to perform actions on the tenant
- we then configure SIA's secret, database and DB policy
