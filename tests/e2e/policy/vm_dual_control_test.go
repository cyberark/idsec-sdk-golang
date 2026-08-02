//go:build (e2e && policy) || e2e

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	identityusers "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policyvm "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm"
	policyvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

func buildVMDualControlPolicy(policyName string, principal, approver policycommonmodels.IdsecPolicyPrincipal) *policyvmmodels.IdsecPolicyVMAccessPolicy {
	return &policyvmmodels.IdsecPolicyVMAccessPolicy{
		IdsecPolicyInfraCommonAccessPolicy: policycommonmodels.IdsecPolicyInfraCommonAccessPolicy{
			IdsecPolicyCommonAccessPolicy: policycommonmodels.IdsecPolicyCommonAccessPolicy{
				Metadata: policycommonmodels.IdsecPolicyMetadata{
					Name:        policyName,
					Description: "E2E test: VM access policy with dual control",
					Status: &policycommonmodels.IdsecPolicyStatus{
						Status: policycommonmodels.StatusTypeActive,
					},
					PolicyEntitlement: policycommonmodels.IdsecPolicyEntitlement{
						TargetCategory: commonmodels.CategoryTypeVM,
						LocationType:   commonmodels.WorkspaceTypeFQDNIP,
						PolicyType:     policycommonmodels.PolicyTypeRecurring,
					},
					PolicyTags: []string{},
					TimeZone:   "Asia/Jerusalem",
				},
				Principals:               []policycommonmodels.IdsecPolicyPrincipal{principal},
				DelegationClassification: policycommonmodels.DelegationClassificationUnrestricted,
			},
			Conditions: policycommonmodels.IdsecPolicyInfraCommonConditions{
				AccessWindow: policycommonmodels.IdsecPolicyInfraTimeCondition{
					DaysOfTheWeek: []int{0, 1, 2, 3, 4, 5, 6},
					FromHour:      "00:00",
					ToHour:        "23:59",
				},
				MaxSessionDuration: 4,
				IdleTime:           10,
				AccessApproval: &policycommonmodels.IdsecPolicyAccessApprovalCondition{
					Required:  true,
					Approvers: []policycommonmodels.IdsecPolicyPrincipal{approver},
				},
			},
		},
		Targets: policyvmmodels.IdsecPolicyVMPlatformTargets{
			FQDNIPResource: &policyvmmodels.IdsecPolicyVMFQDNIPResource{
				FQDNRules: []policyvmmodels.IdsecPolicyVMFQDNRule{
					{
						Operator:            policyvmmodels.VMFQDNOperatorExactly,
						ComputernamePattern: framework.RandomResourceName("e2e-dual-control-vm") + ".example.com",
						Domain:              "example.com",
					},
				},
			},
		},
		Behavior: policyvmmodels.IdsecPolicyVMBehavior{
			SSHProfile: &policyvmmodels.IdsecPolicyVMSSHProfile{
				Username: "e2e-dual-control-user",
			},
		},
	}
}

func buildVMPolicyWithoutAccessApproval(policyName string, principal policycommonmodels.IdsecPolicyPrincipal) *policyvmmodels.IdsecPolicyVMAccessPolicy {
	return &policyvmmodels.IdsecPolicyVMAccessPolicy{
		IdsecPolicyInfraCommonAccessPolicy: policycommonmodels.IdsecPolicyInfraCommonAccessPolicy{
			IdsecPolicyCommonAccessPolicy: policycommonmodels.IdsecPolicyCommonAccessPolicy{
				Metadata: policycommonmodels.IdsecPolicyMetadata{
					Name:        policyName,
					Description: "E2E test: VM access policy WITHOUT dual control (baseline)",
					Status: &policycommonmodels.IdsecPolicyStatus{
						Status: policycommonmodels.StatusTypeActive,
					},
					PolicyEntitlement: policycommonmodels.IdsecPolicyEntitlement{
						TargetCategory: commonmodels.CategoryTypeVM,
						LocationType:   commonmodels.WorkspaceTypeFQDNIP,
						PolicyType:     policycommonmodels.PolicyTypeRecurring,
					},
					PolicyTags: []string{},
					TimeZone:   "Asia/Jerusalem",
				},
				Principals:               []policycommonmodels.IdsecPolicyPrincipal{principal},
				DelegationClassification: policycommonmodels.DelegationClassificationUnrestricted,
			},
			Conditions: policycommonmodels.IdsecPolicyInfraCommonConditions{
				AccessWindow: policycommonmodels.IdsecPolicyInfraTimeCondition{
					DaysOfTheWeek: []int{0, 1, 2, 3, 4, 5, 6},
					FromHour:      "00:00",
					ToHour:        "23:59",
				},
				MaxSessionDuration: 4,
				IdleTime:           10,
				// AccessApproval intentionally left nil -- this is the field under test.
			},
		},
		Targets: policyvmmodels.IdsecPolicyVMPlatformTargets{
			FQDNIPResource: &policyvmmodels.IdsecPolicyVMFQDNIPResource{
				FQDNRules: []policyvmmodels.IdsecPolicyVMFQDNRule{
					{
						Operator:            policyvmmodels.VMFQDNOperatorExactly,
						ComputernamePattern: framework.RandomResourceName("e2e-no-access-approval-vm") + ".example.com",
						Domain:              "example.com",
					},
				},
			},
		},
		Behavior: policyvmmodels.IdsecPolicyVMBehavior{
			SSHProfile: &policyvmmodels.IdsecPolicyVMSSHProfile{
				Username: "e2e-no-access-approval-user",
			},
		},
	}
}

// TestVMPolicyNoAccessApproval exercises Create/Read/Update for a VM access
// policy that never sets AccessApproval. this one must ALWAYS pass, proving that omitting
// access_approval never triggers the dual-control gate.
func TestVMPolicyNoAccessApproval(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: VM Policy Without Access Approval")

		svc, err := ctx.API.PolicyVm()
		require.NoError(t, err, "Failed to get Policy VM service")

		principalUser := createDualControlUser(t, ctx, "e2e-vm-no-approval-principal")
		principal := userToPolicyPrincipal(principalUser)

		policyName := framework.RandomResourceName("e2e-vm-no-access-approval")
		createPolicy := buildVMPolicyWithoutAccessApproval(policyName, principal)

		created, err := svc.CreatePolicy(createPolicy)
		require.NoError(t, err, "CreatePolicy without access_approval should succeed on any tenant, "+
			"regardless of the enable_vm_access_approval allowlist")
		require.NotNil(t, created)
		require.NotEmpty(t, created.Metadata.PolicyID, "CreatePolicy should return a policy ID")
		t.Logf("Created VM policy without access approval: %s", created.Metadata.PolicyID)

		ctx.TrackResourceByType("VMPolicy", created.Metadata.PolicyID, func() error {
			return svc.DeletePolicy(&policycommonmodels.IdsecPolicyDeletePolicyRequest{PolicyID: created.Metadata.PolicyID})
		})

		require.Nil(t, created.Conditions.AccessApproval, "created policy should have a nil AccessApproval "+
			"when it was never requested -- the backend omits access_approval from the response entirely")

		fetched, err := svc.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{PolicyID: created.Metadata.PolicyID})
		require.NoError(t, err)
		require.NotNil(t, fetched)
		require.Nil(t, fetched.Conditions.AccessApproval, "fetched policy should also have a nil AccessApproval")

		t.Log("VM Policy Without Access Approval completed successfully")
	}, policyvm.ServiceConfig, identityusers.ServiceConfig)
}

// TestVMPolicyDualControl exercises Create/Read/Update for a VM access
// policy with dual control (access_approval.required=true).
func TestVMPolicyDualControl(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: VM Policy Dual Control")

		svc, err := ctx.API.PolicyVm()
		require.NoError(t, err, "Failed to get Policy VM service")

		principalUser := createDualControlUser(t, ctx, "e2e-vm-principal")
		approverUser := createDualControlUser(t, ctx, "e2e-vm-approver")
		principal := userToPolicyPrincipal(principalUser)
		approver := userToPolicyPrincipal(approverUser)

		policyName := framework.RandomResourceName("e2e-vm-dual-control")
		createPolicy := buildVMDualControlPolicy(policyName, principal, approver)

		created, err := svc.CreatePolicy(createPolicy)
		require.NoError(t, err, "CreatePolicy with dual control should succeed: this e2e tenant must be on the "+
			"enable_vm_access_approval allowlist in dpa-config-store")
		require.NotNil(t, created)
		require.NotEmpty(t, created.Metadata.PolicyID, "CreatePolicy should return a policy ID")
		t.Logf("Created VM policy with dual control: %s", created.Metadata.PolicyID)

		ctx.TrackResourceByType("VMPolicy", created.Metadata.PolicyID, func() error {
			return svc.DeletePolicy(&policycommonmodels.IdsecPolicyDeletePolicyRequest{PolicyID: created.Metadata.PolicyID})
		})

		require.NotNil(t, created.Conditions.AccessApproval, "created policy should have a non-nil AccessApproval")
		require.True(t, created.Conditions.AccessApproval.Required, "created policy should have AccessApproval.Required=true")
		require.Len(t, created.Conditions.AccessApproval.Approvers, 1, "created policy should have exactly 1 approver")
		require.Equal(t, approver.ID, created.Conditions.AccessApproval.Approvers[0].ID)

		fetched, err := svc.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{PolicyID: created.Metadata.PolicyID})
		require.NoError(t, err)
		require.NotNil(t, fetched)
		require.NotNil(t, fetched.Conditions.AccessApproval, "fetched policy should have a non-nil AccessApproval")
		require.True(t, fetched.Conditions.AccessApproval.Required, "fetched policy should preserve AccessApproval.Required=true")
		require.Len(t, fetched.Conditions.AccessApproval.Approvers, 1, "fetched policy should preserve the approver")
		require.Equal(t, approver.ID, fetched.Conditions.AccessApproval.Approvers[0].ID)

		// Update: add a second approver, then verify dual control preserves both.
		secondApproverUser := createDualControlUser(t, ctx, "e2e-vm-approver-2")
		secondApprover := userToPolicyPrincipal(secondApproverUser)

		fetched.Conditions.AccessApproval.Approvers = append(fetched.Conditions.AccessApproval.Approvers, secondApprover)

		updated, err := svc.UpdatePolicy(fetched)
		require.NoError(t, err, "UpdatePolicy adding a second approver should succeed")
		require.NotNil(t, updated)
		require.NotNil(t, updated.Conditions.AccessApproval, "updated policy should still have dual control enabled")
		require.True(t, updated.Conditions.AccessApproval.Required, "updated policy should preserve AccessApproval.Required=true")
		require.Len(t, updated.Conditions.AccessApproval.Approvers, 2, "updated policy should have exactly 2 approvers")
		require.Equal(t, approver.ID, updated.Conditions.AccessApproval.Approvers[0].ID, "updated policy should preserve the first approver")
		require.Equal(t, secondApprover.ID, updated.Conditions.AccessApproval.Approvers[1].ID, "updated policy should have the second approver appended")

		t.Log("VM Policy Dual Control completed successfully")
	}, policyvm.ServiceConfig, identityusers.ServiceConfig)
}
