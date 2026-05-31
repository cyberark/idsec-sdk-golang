//go:build (e2e && sca) || e2e

package groupaccess

import (
	"testing"

	policygroupaccess "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess"
	scagroupaccesssvc "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/groupaccess"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
	scahelpers "github.com/cyberark/idsec-sdk-golang/tests/e2e/sca"
)

// ---------------------------------------------------------------------------
// ListTargets pagination test
// ---------------------------------------------------------------------------

// TestGroupAccessListTargetsWithNextToken creates multiple eligible groups,
// then pages through results using limit=1 to verify nextToken handling.
func TestGroupAccessListTargetsWithNextToken(t *testing.T) {
	t.Skip("Azure GroupAccess tests are temporarily disabled")

	framework.LogSection(t, "Test: GroupAccess Azure ListTargets pagination")

	testCtx := scahelpers.SetupGroupAccessListTargetsTest(t, false)

	framework.Run(t, func(ctx *framework.TestContext) {
		policySvc := scahelpers.MustPolicyGroupAccessService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		createdPolicyIDs := scahelpers.CreateGroupAccessPaginationPolicies(t, policySvc, testCtx, principal)
		defer func() {
			for _, policyID := range createdPolicyIDs {
				scahelpers.DeletePolicyBestEffort(t, policyID, policySvc.DeletePolicy)
			}
		}()

		groupAccessSvc := scahelpers.MustPrincipalGroupAccessService(t, testCtx)
		page1, page2 := scahelpers.ListGroupAccessTargetsWithNextToken(t, groupAccessSvc)
		scahelpers.VerifyGroupAccessPagination(t, page1, page2)
	}, scagroupaccesssvc.ServiceConfig, policygroupaccess.ServiceConfig)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestGroupAccessAzureListTargets(t *testing.T) {
	t.Skip("Azure GroupAccess tests are temporarily disabled")

	framework.LogSection(t, "Test: GroupAccess Azure ListTargets")

	testCtx := scahelpers.SetupGroupAccessListTargetsTest(t, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		policySvc := scahelpers.MustPolicyGroupAccessService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.GroupAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := scahelpers.CreateGroupAccessPolicy(t, policySvc, principal, target, "sca_cli_groupaccess_azure_e2e")
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := scahelpers.GetGroupAccessPolicy(t, policySvc, createdPolicyID)
		groupAccessSvc := scahelpers.MustPrincipalGroupAccessService(t, testCtx)
		listResp := scahelpers.ListGroupAccessTargets(t, groupAccessSvc, 20)
		scahelpers.VerifyGroupAccessTargetInListTargets(t, fetchedPolicy, listResp.Response)
	}, scagroupaccesssvc.ServiceConfig, policygroupaccess.ServiceConfig)
}

func TestGroupAccessAzureElevate(t *testing.T) {
	t.Skip("Azure GroupAccess tests are temporarily disabled")

	const (
		displayName      = "GroupAccess Azure Elevate"
		policyNamePrefix = "sca_cli_groupaccess_azure_elevate_e2e"
	)

	framework.LogSection(t, "Test: "+displayName)

	framework.Run(t, func(ctx *framework.TestContext) {
		testCtx := scahelpers.SetupGroupAccessListTargetsTest(t, true)
		scahelpers.RunGroupAccessElevateTest(t, ctx, testCtx, displayName, policyNamePrefix)
	}, scagroupaccesssvc.ServiceConfig, policygroupaccess.ServiceConfig)
}
