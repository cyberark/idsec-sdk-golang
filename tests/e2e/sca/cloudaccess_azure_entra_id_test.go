//go:build (e2e && sca) || e2e

package sca

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	scacloudaccesssvc "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// ---------------------------------------------------------------------------
// ListTargets pagination test
// ---------------------------------------------------------------------------

// TestCloudAccessAzureEntraIDListTargetsWithNextToken creates multiple eligible targets,
// then pages through results using limit=1 to verify nextToken handling.
func TestCloudAccessAzureEntraIDListTargetsWithNextToken(t *testing.T) {
	testCtx := setupCloudAccessListTargetsTest(t, azureEntraIDCloudAccessListTargetsConfig, false)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: CloudAccess Azure Entra ID ListTargets pagination")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		createdPolicyIDs := createCloudAccessPaginationPolicies(t, policySvc, azureEntraIDCloudAccessListTargetsConfig, testCtx, principal)
		defer func() {
			for _, policyID := range createdPolicyIDs {
				deletePolicyBestEffort(t, policyID, policySvc.DeletePolicy)
			}
		}()

		cloudAccessSvc := mustPrincipalCloudAccessService(t, testCtx)
		page1, page2 := listCloudAccessTargetsWithNextToken(t, cloudAccessSvc, azureEntraIDCloudAccessListTargetsConfig)
		verifyCloudAccessPagination(t, page1, page2)
	}, scacloudaccesssvc.ServiceConfig, cloudaccess.ServiceConfig)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestCloudAccessAzureEntraIDListTargets(t *testing.T) {
	testCtx := setupCloudAccessListTargetsTest(t, azureEntraIDCloudAccessListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: CloudAccess Azure Entra ID ListTargets")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		target := cloudAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := createCloudAccessPolicy(t, policySvc, azureEntraIDCloudAccessListTargetsConfig, principal, target, azureEntraIDCloudAccessListTargetsConfig.policyNamePrefix)
		defer deletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := getCloudAccessPolicy(t, policySvc, createdPolicyID)
		cloudAccessSvc := mustPrincipalCloudAccessService(t, testCtx)
		filteredResp := listCloudAccessTargets(t, cloudAccessSvc, azureEntraIDCloudAccessListTargetsConfig.csp, target.WorkspaceID, 20)
		verifyCloudAccessFilteredTargets(t, azureEntraIDCloudAccessListTargetsConfig, fetchedPolicy, target, filteredResp)
	}, scacloudaccesssvc.ServiceConfig, cloudaccess.ServiceConfig)
}
