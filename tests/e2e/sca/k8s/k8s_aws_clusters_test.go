//go:build (e2e && sca) || e2e

package k8s

import (
	"testing"

	policyk8s "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/k8s"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
	scahelpers "github.com/cyberark/idsec-sdk-golang/tests/e2e/sca"
)

// ---------------------------------------------------------------------------
// ListTargets pagination test
// ---------------------------------------------------------------------------

// TestK8sAWSListTargetsWithNextToken creates multiple eligible clusters,
// then pages through results using limit=1 to verify nextToken handling.
func TestK8sAWSListTargetsWithNextToken(t *testing.T) {
	framework.LogSection(t, "Test: K8s AWS Clusters ListTargets pagination")
	testCtx := scahelpers.SetupK8sListTargetsTest(t, scahelpers.AWSK8sListTargetsConfig, false)

	framework.Run(t, func(ctx *framework.TestContext) {
		// K8s cluster policies are created via policy-k8s (not Cloud Console policy-cloudaccess).
		policySvc := scahelpers.MustPolicyK8sService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		createdPolicyIDs := scahelpers.CreateK8sPaginationPolicies(t, policySvc, scahelpers.AWSK8sListTargetsConfig, testCtx, principal)
		defer func() {
			for _, policyID := range createdPolicyIDs {
				scahelpers.DeletePolicyBestEffort(t, policyID, policySvc.DeletePolicy)
			}
		}()

		k8sSvc := scahelpers.MustPrincipalK8sService(t, testCtx)
		page1, page2 := scahelpers.ListK8sTargetsWithNextToken(t, k8sSvc, scahelpers.AWSK8sListTargetsConfig)
		scahelpers.VerifyK8sPagination(t, page1, page2)
	}, k8sservice.ServiceConfig, policyk8s.ServiceConfig)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestK8sAWSListTargets(t *testing.T) {
	framework.LogSection(t, "Test: K8s AWS Clusters ListTargets full flow")
	testCtx := scahelpers.SetupK8sListTargetsTest(t, scahelpers.AWSK8sListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		// K8s cluster policies are created via policy-k8s (not Cloud Console policy-cloudaccess).
		policySvc := scahelpers.MustPolicyK8sService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.K8sTargetFromConfig(t, scahelpers.AWSK8sListTargetsConfig, testCtx, 0)
		createdPolicyID := scahelpers.CreateK8sPolicy(t, policySvc, scahelpers.AWSK8sListTargetsConfig, principal, target, scahelpers.AWSK8sListTargetsConfig.PolicyNamePrefix)
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		k8sSvc := scahelpers.MustPrincipalK8sService(t, testCtx)
		filteredResp := scahelpers.ListK8sTargets(t, k8sSvc, scahelpers.AWSK8sListTargetsConfig.CSP, target.PolicyTarget.WorkspaceID, 20)
		scahelpers.VerifyK8sFilteredTargets(t, target, filteredResp)
	}, k8sservice.ServiceConfig, policyk8s.ServiceConfig)
}
