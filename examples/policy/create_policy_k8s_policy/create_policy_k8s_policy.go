package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policyk8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/k8s/models"
)

func main() {
	// Perform authentication using IdsecISPAuth to the platform.
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
	k8s := policyAPI.K8s()

	// --- Create ---
	created, err := k8s.CreatePolicy(exampleK8sPolicy())
	if err != nil {
		panic(err)
	}
	policyID := created.Metadata.PolicyID
	fmt.Printf("Policy created: %s (%s)\n", created.Metadata.Name, policyID)

	// --- Read ---
	fetched, err := k8s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: policyID,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Policy read: %s — %s\n", fetched.Metadata.PolicyID, fetched.Metadata.Description)

	status, err := k8s.PolicyStatus(&policycommonmodels.IdsecPolicyGetPolicyStatus{
		PolicyID: policyID,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Policy status: %s\n", status)

	// --- Update ---
	fetched.Metadata.Description = "Updated Kubernetes cluster access policy description"
	updated, err := k8s.UpdatePolicy(fetched)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Policy updated: %s\n", updated.Metadata.Description)

	// --- List (filtered) ---
	list, err := k8s.TfListPoliciesBy(&policyk8smodels.IdsecPolicyK8sFilters{
		IdsecPolicyFilters: *policycommonmodels.NewIdsecPolicyFilters(),
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Policies listed (Clusters): %d\n", len(list.Policies))

	// --- Delete ---
	if err := k8s.DeletePolicy(&policycommonmodels.IdsecPolicyDeletePolicyRequest{
		PolicyID: policyID,
	}); err != nil {
		panic(err)
	}
	fmt.Printf("Policy deleted: %s\n", policyID)
}

// exampleK8sPolicy builds a sample Kubernetes cluster access policy with an AWS IAM (account) target.
// Swap Targets for Azure (azure_targets) or AWS Identity Center (aws_idc_targets) as needed.
func exampleK8sPolicy() *policyk8smodels.IdsecPolicyK8sPolicy {
	return &policyk8smodels.IdsecPolicyK8sPolicy{
		IdsecPolicyCommonAccessPolicy: policycommonmodels.IdsecPolicyCommonAccessPolicy{
			Metadata: policycommonmodels.IdsecPolicyMetadata{
				Name:        "Example K8s Cluster Access Policy",
				Description: "Example Kubernetes cluster access policy created via the SDK.",
				Status: &policycommonmodels.IdsecPolicyStatus{
					Status: policycommonmodels.StatusTypeValidating,
				},
				PolicyEntitlement: policycommonmodels.IdsecPolicyEntitlement{
					TargetCategory: commonmodels.CategoryTypeClusters,
					LocationType:   commonmodels.WorkspaceTypeAWS,
					PolicyType:     policycommonmodels.PolicyTypeRecurring,
				},
				PolicyTags: []string{"sdk-example"},
				TimeZone:   "GMT",
			},
			Principals: []policycommonmodels.IdsecPolicyPrincipal{
				{
					Type:                policycommonmodels.PrincipalTypeUser,
					ID:                  "user-id",
					Name:                "user@cyberark.cloud.12345",
					SourceDirectoryName: "CyberArk",
					SourceDirectoryID:   "12345",
				},
			},
			DelegationClassification: policycommonmodels.DelegationClassificationUnrestricted,
		},
		// ConnectionMethod controls how the user connects to the cluster: "direct" or "proxy".
		ConnectionMethod: "direct",
		Conditions: policycommonmodels.IdsecPolicyConditions{
			AccessWindow: policycommonmodels.IdsecPolicyTimeCondition{
				DaysOfTheWeek: []int{0, 1, 2, 3, 4, 5, 6},
				FromHour:      "",
				ToHour:        "",
			},
			MaxSessionDuration: 2,
		},
		Targets: policyk8smodels.IdsecPolicyK8sTargets{
			AwsAccountTargets: []policyk8smodels.IdsecPolicyK8sAWSAccountTarget{
				{
					IdsecPolicyK8sAWSTarget: policyk8smodels.IdsecPolicyK8sAWSTarget{
						IdsecPolicyK8sSharedTarget: policyk8smodels.IdsecPolicyK8sSharedTarget{
							Scope: "cluster",
							FQDN:  "https://example-cluster.eks.us-east-1.amazonaws.com",
						},
						RoleID:        "arn:aws:iam::123456789012:role/ExampleEKSRole",
						WorkspaceID:   "123456789012",
						RoleName:      "ExampleEKSRole",
						WorkspaceName: "Example AWS Account",
						ClusterID:     "arn:aws:eks:us-east-1:123456789012:cluster/example-cluster",
					},
				},
			},
			// Azure example (uncomment and set LocationType to WorkspaceTypeAzure):
			// AzureTargets: []policyk8smodels.IdsecPolicyK8sAzureTarget{{
			// 	IdsecPolicyK8sSharedTarget: policyk8smodels.IdsecPolicyK8sSharedTarget{Scope: "cluster"},
			// 	RoleID: "role-id", WorkspaceID: "workspace-id", OrgID: "tenant-uuid",
			// 	WorkspaceType: policyk8smodels.AzureWSTypeResource,
			// 	ClusterID: "/subscriptions/.../managedClusters/example",
			// }},
			// AWS IAM Identity Center (IDC) example: RoleID is the SSO permission-set ARN and OrgID
			// is the AWS organization / SSO instance owner account.
			// AwsIdcTargets: []policyk8smodels.IdsecPolicyK8sAWSIDCTarget{{
			// 	IdsecPolicyK8sAWSTarget: policyk8smodels.IdsecPolicyK8sAWSTarget{
			// 		IdsecPolicyK8sSharedTarget: policyk8smodels.IdsecPolicyK8sSharedTarget{Scope: "cluster"},
			// 		RoleID:      "arn:aws:sso:::permissionSet/ssoins-xxxx/ps-xxxx",
			// 		RoleName:    "AdminPS",
			// 		WorkspaceID: "081626391589",
			// 		ClusterID:   "arn:aws:eks:us-east-1:081626391589:cluster/example-cluster",
			// 	},
			// 	OrgID: "081626391589",
			// }},
		},
	}
}
