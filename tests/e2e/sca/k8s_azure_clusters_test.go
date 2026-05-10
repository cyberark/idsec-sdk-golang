//go:build (e2e && sca) || e2e

package sca

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestK8sAzureListTargets(t *testing.T) {
	t.Skip("K8s cluster policy support is temporarily disabled in policy_cloud_access")

	testCtx := setupK8sListTargetsTest(t, azureK8sListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: K8s Azure Clusters ListTargets")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		target := k8sTargetFromConfig(t, azureK8sListTargetsConfig, testCtx, 0)
		createdPolicyID := createK8sPolicy(t, policySvc, azureK8sListTargetsConfig, principal, target, azureK8sListTargetsConfig.policyNamePrefix)
		defer deletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := getCloudAccessPolicy(t, policySvc, createdPolicyID)
		validateAzureK8sFetchedPolicy(t, fetchedPolicy, target)

		k8sSvc := mustPrincipalK8sService(t, testCtx)
		filteredResp := listK8sTargets(t, k8sSvc, azureK8sListTargetsConfig.csp, target.PolicyTarget.WorkspaceID, 20)
		verifyK8sFilteredTargets(t, target, filteredResp)
	}, k8sservice.ServiceConfig, cloudaccess.ServiceConfig)

}
