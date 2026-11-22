// Package main contains an example for creating a Google (GCP) group access dual control policy.
package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy"
	commonpolicymodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policygroupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/models"
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
	// Dual control (access approval) is supported for Google (GCP) groups only and must be enabled for the tenant.
	// When access approval is required, the access window is omitted.
	policy, err := policyAPI.GroupAccess().CreatePolicy(
		&policygroupaccessmodels.IdsecPolicyGroupAccessPolicy{
			IdsecPolicyCommonAccessPolicy: commonpolicymodels.IdsecPolicyCommonAccessPolicy{
				Metadata: commonpolicymodels.IdsecPolicyMetadata{
					Name:        "Example Google Groups Policy with Dual Control",
					Description: "This is an example of a Google groups access policy with dual control.",
					Status: &commonpolicymodels.IdsecPolicyStatus{
						Status: commonpolicymodels.StatusTypeValidating,
					},
					PolicyEntitlement: commonpolicymodels.IdsecPolicyEntitlement{
						TargetCategory: commonmodels.CategoryTypeGroupAccess,
						LocationType:   commonmodels.WorkspaceTypeGCP,
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
				DelegationClassification: commonpolicymodels.DelegationClassificationUnrestricted,
			},
			Conditions: policygroupaccessmodels.IdsecPolicyGroupAccessConditions{
				IdsecPolicyConditions: commonpolicymodels.IdsecPolicyConditions{
					MaxSessionDuration: 4,
				},
				AccessApproval: &commonpolicymodels.IdsecPolicyAccessApprovalCondition{
					Required: true,
					Approvers: []commonpolicymodels.IdsecPolicyPrincipal{
						{
							Type:                commonpolicymodels.PrincipalTypeUser,
							ID:                  "approver-id",
							Name:                "approver@cyberark.cloud.12345",
							SourceDirectoryName: "CyberArk",
							SourceDirectoryID:   "12345",
						},
					},
				},
			},
			Targets: policygroupaccessmodels.IdsecPolicyGroupAccessTarget{
				GCPTargets: []policygroupaccessmodels.IdsecPolicyGroupAccessGCPTarget{
					{
						GroupID:        "groups/01234abcde",
						OrganizationID: "123456789012",
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
