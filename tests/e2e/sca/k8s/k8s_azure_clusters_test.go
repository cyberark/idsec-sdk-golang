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
// Full E2E flow
// ---------------------------------------------------------------------------

func TestK8sAzureListTargets(t *testing.T) {
	framework.LogSection(t, "Test: K8s Azure Clusters ListTargets")
	testCtx := scahelpers.SetupK8sListTargetsTest(t, scahelpers.AzureK8sListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		// K8s cluster policies are created via policy-k8s (not Cloud Console policy-cloudaccess).
		policySvc := scahelpers.MustPolicyK8sService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.K8sTargetFromConfig(t, scahelpers.AzureK8sListTargetsConfig, testCtx, 0)
		createdPolicyID := scahelpers.CreateK8sPolicy(t, policySvc, scahelpers.AzureK8sListTargetsConfig, principal, target, scahelpers.AzureK8sListTargetsConfig.PolicyNamePrefix)
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := scahelpers.GetK8sPolicy(t, policySvc, createdPolicyID)
		scahelpers.ValidateAzureK8sFetchedPolicy(t, fetchedPolicy, target)

		k8sSvc := scahelpers.MustPrincipalK8sService(t, testCtx)
		filteredResp := scahelpers.ListK8sTargets(t, k8sSvc, scahelpers.AzureK8sListTargetsConfig.CSP, target.PolicyTarget.WorkspaceID, 20)
		scahelpers.VerifyK8sFilteredTargets(t, target, filteredResp)
	}, k8sservice.ServiceConfig, policyk8s.ServiceConfig)

}
