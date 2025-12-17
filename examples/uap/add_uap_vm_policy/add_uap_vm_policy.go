package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/uap"
	commonuapmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsia "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/common/models"
	uapvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/vm/models"
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
	policy, err := uapAPI.VM().AddPolicy(
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
