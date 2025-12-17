package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	dbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/uap"
	commonuapmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsia "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/common/models"
	uapdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db/models"
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
							InstanceType:         dbmodels.FamilyTypeMSSQL,
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
