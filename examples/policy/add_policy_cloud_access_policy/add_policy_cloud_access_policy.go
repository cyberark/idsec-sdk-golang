package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy"
	policycloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
	commonpolicymodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
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
	policy, err := policyAPI.CloudAccess().AddPolicy(
		&policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{
			IdsecPolicyCommonAccessPolicy: commonpolicymodels.IdsecPolicyCommonAccessPolicy{
				Metadata: commonpolicymodels.IdsecPolicyMetadata{
					Name:        "Example SCA Access Policy",
					Description: "This is an example of a SCA access policy.",
					Status: commonpolicymodels.IdsecPolicyStatus{
						Status: commonpolicymodels.StatusTypeValidating,
					},
					PolicyEntitlement: commonpolicymodels.IdsecPolicyEntitlement{
						TargetCategory: commonmodels.CategoryTypeCloudConsole,
						LocationType:   commonmodels.WorkspaceTypeAWS,
						PolicyType:     commonpolicymodels.PolicyTypeRecurring,
					},
					PolicyTags: []string{},
				},
				Principals: []commonpolicymodels.IdsecPolicyPrincipal{
					{
						Type:                commonpolicymodels.PrincipalTypeUser,
						ID:                  "user-id",
						Name:                "user@cyberark.cloud.12345",
						SourceDirectoryName: "CyberArk",
						SourceDirectoryID:   "12345",
					},
				},
			},
			Conditions: policycloudaccessmodels.IdsecPolicyCloudAccessConditions{
				IdsecPolicyConditions: commonpolicymodels.IdsecPolicyConditions{
					AccessWindow: commonpolicymodels.IdsecPolicyTimeCondition{
						DaysOfTheWeek: []int{1, 2, 3, 4, 5},
						FromHour:      "09:00:00",
						ToHour:        "17:00:00",
					},
					MaxSessionDuration: 4,
				},
			},
			Targets: policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleTarget{
				AwsAccountTargets: []policycloudaccessmodels.IdsecPolicyCloudAccessAWSAccountTarget{
					{
						IdsecPolicyCloudAccessTarget: policycloudaccessmodels.IdsecPolicyCloudAccessTarget{
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
