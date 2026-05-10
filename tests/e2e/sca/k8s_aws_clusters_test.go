//go:build (e2e && sca) || e2e

package sca

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// ---------------------------------------------------------------------------
// ListTargets pagination test
// ---------------------------------------------------------------------------

// TestK8sAWSListTargetsWithNextToken creates multiple eligible clusters,
// then pages through results using limit=1 to verify nextToken handling.
func TestK8sAWSListTargetsWithNextToken(t *testing.T) {
	t.Skip("K8s cluster policy support is temporarily disabled in policy_cloud_access")

	testCtx := setupK8sListTargetsTest(t, awsK8sListTargetsConfig, false)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: K8s AWS Clusters ListTargets pagination")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		createdPolicyIDs := createK8sPaginationPolicies(t, policySvc, awsK8sListTargetsConfig, testCtx, principal)
		defer func() {
			for _, policyID := range createdPolicyIDs {
				deletePolicyBestEffort(t, policyID, policySvc.DeletePolicy)
			}
		}()

		k8sSvc := mustPrincipalK8sService(t, testCtx)
		page1, page2 := listK8sTargetsWithNextToken(t, k8sSvc, awsK8sListTargetsConfig)
		verifyK8sPagination(t, page1, page2)
	}, k8sservice.ServiceConfig, cloudaccess.ServiceConfig)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestK8sAWSListTargets(t *testing.T) {
	t.Skip("K8s cluster policy support is temporarily disabled in policy_cloud_access")

	testCtx := setupK8sListTargetsTest(t, awsK8sListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: K8s AWS Clusters ListTargets")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		target := k8sTargetFromConfig(t, awsK8sListTargetsConfig, testCtx, 0)
		createdPolicyID := createK8sPolicy(t, policySvc, awsK8sListTargetsConfig, principal, target, awsK8sListTargetsConfig.policyNamePrefix)
		defer deletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		k8sSvc := mustPrincipalK8sService(t, testCtx)
		filteredResp := listK8sTargets(t, k8sSvc, awsK8sListTargetsConfig.csp, target.PolicyTarget.WorkspaceID, 20)
		verifyK8sFilteredTargets(t, target, filteredResp)
	}, k8sservice.ServiceConfig, cloudaccess.ServiceConfig)
}
