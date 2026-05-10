//go:build (e2e && sca) || e2e

package sca

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	scacloudaccesssvc "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestCloudAccessAzureResourceListTargets(t *testing.T) {
	testCtx := setupCloudAccessListTargetsTest(t, azureResourceCloudAccessListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: CloudAccess Azure Resource ListTargets")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		target := cloudAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := createCloudAccessPolicy(t, policySvc, azureResourceCloudAccessListTargetsConfig, principal, target, azureResourceCloudAccessListTargetsConfig.policyNamePrefix)
		defer deletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := getCloudAccessPolicy(t, policySvc, createdPolicyID)
		cloudAccessSvc := mustPrincipalCloudAccessService(t, testCtx)
		filteredResp := listCloudAccessTargets(t, cloudAccessSvc, azureResourceCloudAccessListTargetsConfig.csp, target.WorkspaceID, 20)
		verifyCloudAccessFilteredTargets(t, azureResourceCloudAccessListTargetsConfig, fetchedPolicy, target, filteredResp)
	}, scacloudaccesssvc.ServiceConfig, cloudaccess.ServiceConfig)
}
