//go:build (e2e && sca) || e2e

package sca

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess"
	scagroupaccesssvc "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/groupaccess"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// ---------------------------------------------------------------------------
// ListTargets pagination test
// ---------------------------------------------------------------------------

// TestGroupAccessListTargetsWithNextToken creates multiple eligible groups,
// then pages through results using limit=1 to verify nextToken handling.
func TestGroupAccessListTargetsWithNextToken(t *testing.T) {
	testCtx := setupGroupAccessListTargetsTest(t, false)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: GroupAccess Azure ListTargets pagination")

		policySvc := mustPolicyGroupAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		createdPolicyIDs := createGroupAccessPaginationPolicies(t, policySvc, testCtx, principal)
		defer func() {
			for _, policyID := range createdPolicyIDs {
				deletePolicyBestEffort(t, policyID, policySvc.DeletePolicy)
			}
		}()

		groupAccessSvc := mustPrincipalGroupAccessService(t, testCtx)
		page1, page2 := listGroupAccessTargetsWithNextToken(t, groupAccessSvc)
		verifyGroupAccessPagination(t, page1, page2)
	}, scagroupaccesssvc.ServiceConfig, groupaccess.ServiceConfig)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestGroupAccessAzureListTargets(t *testing.T) {
	testCtx := setupGroupAccessListTargetsTest(t, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: GroupAccess Azure ListTargets")

		policySvc := mustPolicyGroupAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		target := groupAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := createGroupAccessPolicy(t, policySvc, principal, target, "sca_cli_groupaccess_azure_e2e")
		defer deletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := getGroupAccessPolicy(t, policySvc, createdPolicyID)
		groupAccessSvc := mustPrincipalGroupAccessService(t, testCtx)
		listResp := listGroupAccessTargets(t, groupAccessSvc, 20)
		verifyGroupAccessTargetInListTargets(t, fetchedPolicy, listResp.Response)
	}, scagroupaccesssvc.ServiceConfig, groupaccess.ServiceConfig)
}
