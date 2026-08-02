// Package main contains an example for creating a VM access policy with dual control.
package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy"
	policycommomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policyvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm/models"
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
	policy, err := policyAPI.VM().CreatePolicy(
		&policyvmmodels.IdsecPolicyVMAccessPolicy{
			IdsecPolicyInfraCommonAccessPolicy: policycommomodels.IdsecPolicyInfraCommonAccessPolicy{
				IdsecPolicyCommonAccessPolicy: policycommomodels.IdsecPolicyCommonAccessPolicy{
					Metadata: policycommomodels.IdsecPolicyMetadata{
						Name:        "Example VM Access Policy with Dual Control",
						Description: "This is an example of a VM access policy for Infrastructure with dual control (additional approval) enabled.",
						Status: &policycommomodels.IdsecPolicyStatus{
							Status: policycommomodels.StatusTypeActive,
						},
						PolicyEntitlement: policycommomodels.IdsecPolicyEntitlement{
							TargetCategory: commonmodels.CategoryTypeVM,
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
					AccessWindow: policycommomodels.IdsecPolicyInfraTimeCondition{
						DaysOfTheWeek: []int{1, 2, 3, 4, 5},
						FromHour:      "09:00",
						ToHour:        "17:00",
					},
					MaxSessionDuration: 4,
					IdleTime:           10,
					// Dual control: an additional approver must approve the access
					// request before the applicant's access is elevated. If dual
					// control is not enabled for the tenant, the backend rejects
					// this policy with a "not supported" error.
					AccessApproval: &policycommomodels.IdsecPolicyAccessApprovalCondition{
						Required: true,
						Approvers: []policycommomodels.IdsecPolicyPrincipal{
							{
								Type:                policycommomodels.PrincipalTypeUser,
								ID:                  "approver-id",
								Name:                "approver@cyberark.cloud.12345",
								SourceDirectoryName: "CyberArk",
								SourceDirectoryID:   "12345",
							},
						},
					},
				},
			},
			Targets: policyvmmodels.IdsecPolicyVMPlatformTargets{
				FQDNIPResource: &policyvmmodels.IdsecPolicyVMFQDNIPResource{
					FQDNRules: []policyvmmodels.IdsecPolicyVMFQDNRule{
						{
							Operator:            policyvmmodels.VMFQDNOperatorExactly,
							ComputernamePattern: "example-vm",
							Domain:              "mydomain.com",
						},
					},
				},
			},
			Behavior: policyvmmodels.IdsecPolicyVMBehavior{
				SSHProfile: &policyvmmodels.IdsecPolicyVMSSHProfile{
					Username: "root",
				},
				RDPProfile: &policyvmmodels.IdsecPolicyVMRDPProfile{
					LocalEphemeralUser: &policyvmmodels.IdsecPolicyVMEphemeralUser{
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
